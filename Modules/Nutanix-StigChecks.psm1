#Requires -Version 7.0
Set-StrictMode -Version Latest

function Connect-NutanixPrism {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Fqdn,
        [int]$Port = 9440,
        [Parameter(Mandatory)][pscredential]$Credential,
        [switch]$SkipCertificateCheck
    )

    if ($SkipCertificateCheck) {
        Write-Verbose 'Nutanix API calls will skip TLS certificate validation.'
    }

    $pair = "$($Credential.UserName):$($Credential.GetNetworkCredential().Password)"
    $bytes = [Text.Encoding]::ASCII.GetBytes($pair)
    $b64 = [Convert]::ToBase64String($bytes)

    @{
        BaseUri              = "https://${Fqdn}:${Port}"
        Headers              = @{
            Authorization  = "Basic $b64"
            Accept         = 'application/json'
            'Content-Type' = 'application/json'
        }
        Credential           = $Credential
        Fqdn                 = $Fqdn
        SkipCertificateCheck = [bool]$SkipCertificateCheck
    }
}

function Invoke-NutanixApi {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Session,
        [Parameter(Mandatory)][string]$Path,
        [ValidateSet('Get', 'Post')]
        [string]$Method = 'Get',
        [hashtable]$Query = @{},
        [object]$Body
    )

    $uriBuilder = [System.UriBuilder]::new("$($Session.BaseUri)$Path")
    if ($Query.Count -gt 0) {
        $qs = ($Query.GetEnumerator() | ForEach-Object {
            "$([uri]::EscapeDataString($_.Key))=$([uri]::EscapeDataString([string]$_.Value))"
        }) -join '&'
        $uriBuilder.Query = $qs
    }

    $params = @{
        Uri     = $uriBuilder.Uri.AbsoluteUri
        Method  = $Method
        Headers = $Session.Headers
    }
    if ($Body) {
        $params.Body = ($Body | ConvertTo-Json -Depth 20)
    }
    if ($Session.SkipCertificateCheck) {
        $params.SkipCertificateCheck = $true
    }

    Invoke-RestMethod @params
}

function Get-NutanixStigControlResults {
    <#
    .SYNOPSIS
        Retrieves per-control STIG results from Prism Central Security API (PC 2024.3+).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Session,
        [string]$ClusterExtId,
        [int]$PageSize = 100
    )

    $all = [System.Collections.Generic.List[object]]::new()
    $page = 0
    do {
        $query = @{ '$page' = $page; '$limit' = $PageSize }
        if ($ClusterExtId) { $query['$filter'] = "clusterExtId eq '$ClusterExtId'" }

        $response = Invoke-NutanixApi -Session $Session -Path '/api/security/v4.1/report/stigs' -Query $query
        $items = @($response.data)
        if ($items.Count -eq 0) { break }
        $all.AddRange($items)
        $page++
    } while ($items.Count -eq $PageSize)

    return $all
}

function Resolve-NutanixClusterHypervisor {
    <#
    .SYNOPSIS
        Derives cluster hypervisor type (AHV, ESXi, etc.) from Prism cluster entity payload.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Entity)

    $signals = [System.Collections.Generic.List[string]]::new()

    $statusConfig = $Entity.status.resources.config
    if ($statusConfig) {
        if ($statusConfig.hypervisor_types) { $signals.AddRange(@($statusConfig.hypervisor_types | ForEach-Object { [string]$_ })) }
        if ($statusConfig.hypervisor_type) { $signals.Add([string]$statusConfig.hypervisor_type) }
    }

    $specConfig = $Entity.spec.resources.config
    if ($specConfig) {
        if ($specConfig.hypervisor_types) { $signals.AddRange(@($specConfig.hypervisor_types | ForEach-Object { [string]$_ })) }
        if ($specConfig.hypervisor_type) { $signals.Add([string]$specConfig.hypervisor_type) }
    }

    $nodeList = $Entity.status.resources.nodes
    if ($nodeList -and $nodeList.hypervisor_server_list) {
        foreach ($srv in @($nodeList.hypervisor_server_list)) {
            if ($srv.hypervisor_type) { $signals.Add([string]$srv.hypervisor_type) }
            if ($srv.type) { $signals.Add([string]$srv.type) }
        }
    }

    $combined = ($signals | Where-Object { $_ }) -join ' '
    if ($combined -match '(?i)VMware|ESXi|kVMware') { return 'ESXi' }
    if ($combined -match '(?i)KVM|kKvm|AHV|Acropolis') { return 'AHV' }
    if ($combined -match '(?i)Hyper-?V|kHyperv') { return 'Hyper-V' }
    return 'Unknown'
}

function Get-NutanixClusterInventory {
    <#
    .SYNOPSIS
        Lists clusters registered on Prism Central or the local cluster on Prism Element.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Session,
        [ValidateSet('AHV', 'ESXi', 'All')]
        [string]$HypervisorFilter = 'All'
    )

    $response = Invoke-NutanixApi -Session $Session -Path '/api/nutanix/v3/clusters/list' -Method Post -Body @{
        kind   = 'cluster'
        length = 500
        offset = 0
    }

    $inventory = [System.Collections.Generic.List[object]]::new()
    foreach ($entity in @($response.entities)) {
        $name = $entity.status.name
        $uuid = $entity.metadata.uuid
        $nodeList = $entity.status.resources.nodes
        $nodes = if ($nodeList -and $nodeList.hypervisor_server_list) {
            @($nodeList.hypervisor_server_list).Count
        } elseif ($entity.status.resources.node_uuids) {
            @($entity.status.resources.node_uuids).Count
        } else {
            '?'
        }

        $config = $entity.status.resources.config
        $version = ''
        if ($config -and $config.software_map -and $config.software_map.NOS) {
            $version = $config.software_map.NOS.version
        } elseif ($config -and $config.build_info) {
            $version = $config.build_info.version
        }

        $hypervisor = Resolve-NutanixClusterHypervisor -Entity $entity
        if ($HypervisorFilter -ne 'All' -and $hypervisor -ne $HypervisorFilter) { continue }

        $inventory.Add([PSCustomObject]@{
            ClusterName = $name
            ClusterUuid = $uuid
            NodeCount   = $nodes
            AosVersion  = $version
            Hypervisor  = $hypervisor
        })
    }

    return $inventory
}

function Get-NutanixClusterMap {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Session)

    $clusters = Invoke-NutanixApi -Session $Session -Path '/api/nutanix/v3/clusters/list' -Method Post -Body @{
        kind = 'cluster'
        length = 500
        offset = 0
    }

    $map = @{}
    foreach ($c in @($clusters.entities)) {
        $extId = $c.metadata.uuid
        $name = $c.status.name
        $map[$name] = $extId
        $map[$extId] = $name
    }
    return $map
}

function Convert-NutanixStigStatus {
    param([string]$ApiStatus, [string]$ComplianceStatus)

    switch -Regex ($ComplianceStatus) {
        'PASS|COMPLIANT|PASSED' { return 'Pass' }
        'FAIL|NON_COMPLIANT|FAILED' { return 'Fail' }
        'NOT_APPLICABLE|NA' { return 'NotApplicable' }
        default {
            switch -Regex ($ApiStatus) {
                'PASS|COMPLIANT' { 'Pass' }
                'FAIL|NON_COMPLIANT' { 'Fail' }
                'NOT_APPLICABLE' { 'NotApplicable' }
                default { 'Manual' }
            }
        }
    }
}

function Invoke-NutanixNativeStigAudit {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Session,
        [Parameter(Mandatory)][string[]]$ClusterNames,
        [string]$StigName = 'Nutanix Acropolis GPOS'
    )

    $results = [System.Collections.Generic.List[object]]::new()
    $clusterMap = Get-NutanixClusterMap -Session $Session

    foreach ($clusterName in $ClusterNames) {
        $clusterExtId = $clusterMap[$clusterName]
        $target = "$($Session.Fqdn) / $clusterName"

        if (-not $clusterExtId) {
            $results.Add((New-StigResult -Cluster $clusterName -Target $target -StigName $StigName `
                -RuleId 'N/A' -Title 'Cluster discovery' -Status 'Error' `
                -Details "Cluster '$clusterName' not found in Prism Central"))
            continue
        }

        try {
            $controls = Get-NutanixStigControlResults -Session $Session -ClusterExtId $clusterExtId
        } catch {
            $results.Add((New-StigResult -Cluster $clusterName -Target $target -StigName $StigName `
                -RuleId 'N/A' -Title 'STIG API retrieval' -Status 'Error' `
                -Details $_.Exception.Message))
            continue
        }

        if (@($controls).Count -eq 0) {
            $results.Add((New-StigResult -Cluster $clusterName -Target $target -StigName $StigName `
                -RuleId 'N/A' -Title 'STIG scan data' -Status 'Manual' `
                -Details 'No STIG controls returned. Run STIG scan in Prism Central Security Dashboard first.'))
            continue
        }

        foreach ($ctrl in $controls) {
            $ruleId = if ($ctrl.ruleId) { $ctrl.ruleId } elseif ($ctrl.stigRuleId) { $ctrl.stigRuleId } else { "NTNX-$($ctrl.extId)" }
            $title = if ($ctrl.title) { $ctrl.title } elseif ($ctrl.name) { $ctrl.name } else { 'Nutanix STIG control' }
            $severity = ($ctrl.severity ?? 'medium').ToString().ToLower()
            $status = Convert-NutanixStigStatus -ApiStatus $ctrl.status -ComplianceStatus $ctrl.complianceStatus
            $details = if ($ctrl.remediation) { $ctrl.remediation } elseif ($ctrl.description) { $ctrl.description } else { '' }

            $results.Add((New-StigResult -Cluster $clusterName -Target $target -StigName $StigName `
                -RuleId $ruleId -Severity $severity -Title $title -Status $status -Details $details))
        }
    }

    return $results
}

function Invoke-NutanixApplicationServerStigAudit {
    <#
    .SYNOPSIS
        Automated checks for Nutanix Acropolis Application Server STIG via Prism APIs.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ClusterName,
        [Parameter(Mandatory)][hashtable]$Session
    )

    $stigName = 'Nutanix Acropolis Application Server'
    $target = "$($Session.Fqdn) / $ClusterName"
    $results = [System.Collections.Generic.List[object]]::new()

    # V-279418 - TLS enabled
    $results.Add((Invoke-SafeStigCheck -ResultTemplate @{
        Cluster = $ClusterName; Target = $target; StigName = $stigName
        RuleId = 'V-279418'; Severity = 'medium'
        Title = 'Nutanix AOS must have TLS enabled.'
        Status = 'Pass'; Details = ''; Expected = 'HTTPS/TLS on management interfaces'; Actual = ''
    } -Check {
        $uri = [uri]$Session.BaseUri
        if ($uri.Scheme -ne 'https') {
            return @{ Status = 'Fail'; Actual = $uri.Scheme; Details = 'Prism Central not accessed over HTTPS' }
        }
        @{ Status = 'Pass'; Actual = 'https'; Details = 'Management API accessed over TLS' }
    }))

    # V-279450 - NTP configured
    $results.Add((Invoke-SafeStigCheck -ResultTemplate @{
        Cluster = $ClusterName; Target = $target; StigName = $stigName
        RuleId = 'V-279450'; Severity = 'medium'
        Title = 'Nutanix AOS must configure Network Time Protocol (NTP).'
        Status = 'Manual'; Details = ''
    } -Check {
        try {
            $ntp = Invoke-NutanixApi -Session $Session -Path '/api/nutanix/v3/ntp_servers' -Method Post -Body @{
                kind = 'ntp_server'; length = 10; offset = 0
            }
            $servers = @($ntp.entities | ForEach-Object { $_.status.resources.ntp_server_ip_list }) | Where-Object { $_ }
            if ($servers.Count -gt 0) {
                return @{ Status = 'Pass'; Actual = ($servers -join ', '); Details = 'NTP servers configured in PC' }
            }
            return @{ Status = 'Fail'; Details = 'No NTP servers configured in Prism Central' }
        } catch {
            return @{ Status = 'Manual'; Details = "Could not verify NTP via API: $($_.Exception.Message)" }
        }
    }))

    # V-279433 - Enterprise user management (directory services)
    $results.Add((Invoke-SafeStigCheck -ResultTemplate @{
        Cluster = $ClusterName; Target = $target; StigName = $stigName
        RuleId = 'V-279433'; Severity = 'high'
        Title = 'Nutanix AOS must use an enterprise user management system.'
        Status = 'Manual'; Details = ''
    } -Check {
        try {
            $dirs = Invoke-NutanixApi -Session $Session -Path '/api/nutanix/v3/directory_services/list' -Method Post -Body @{
                kind = 'directory_service'; length = 50; offset = 0
            }
            if (@($dirs.entities).Count -gt 0) {
                $names = $dirs.entities | ForEach-Object { $_.spec.name }
                return @{ Status = 'Pass'; Actual = ($names -join ', '); Details = 'Directory service integration configured' }
            }
            return @{ Status = 'Fail'; Details = 'No directory services configured' }
        } catch {
            return @{ Status = 'Manual'; Details = $_.Exception.Message }
        }
    }))

    # V-279440 - LDAP encryption
    $results.Add((Invoke-SafeStigCheck -ResultTemplate @{
        Cluster = $ClusterName; Target = $target; StigName = $stigName
        RuleId = 'V-279440'; Severity = 'medium'
        Title = 'Nutanix AOS must use encryption when using LDAP for authentication.'
        Status = 'Manual'; Details = ''
    } -Check {
        try {
            $dirs = Invoke-NutanixApi -Session $Session -Path '/api/nutanix/v3/directory_services/list' -Method Post -Body @{
                kind = 'directory_service'; length = 50; offset = 0
            }
            $ldap = @($dirs.entities | Where-Object { $_.spec.resources -and $_.spec.resources.domain_name })
            if ($ldap.Count -eq 0) {
                return @{ Status = 'NotApplicable'; Details = 'LDAP not in use' }
            }
            $insecure = $ldap | Where-Object {
                $url = $_.spec.resources.url ?? $_.spec.resources.directory_url
                $url -match '^ldap://'
            }
            if ($insecure) {
                return @{ Status = 'Fail'; Details = 'One or more directory services use unencrypted ldap://' }
            }
            return @{ Status = 'Pass'; Details = 'LDAP/LDAPS directory URLs appear encrypted' }
        } catch {
            return @{ Status = 'Manual'; Details = $_.Exception.Message }
        }
    }))

    # Manual-only controls (MFA, CAC, DOD banner, FICAM, etc.)
    $manualRules = @(
        @{ Id = 'V-279415'; Title = 'Limit concurrent sessions to 10.'; Sev = 'medium' },
        @{ Id = 'V-279416'; Title = 'Terminate nonprivileged sessions after 15 minutes.'; Sev = 'medium' },
        @{ Id = 'V-279421'; Title = 'Configure role mapping.'; Sev = 'medium' },
        @{ Id = 'V-279422'; Title = 'Display DOD Notice and Consent Banner.'; Sev = 'medium' },
        @{ Id = 'V-279423'; Title = 'Protect against repudiation (centralized logging).'; Sev = 'medium' },
        @{ Id = 'V-279424'; Title = 'Off-load log records to separate system.'; Sev = 'medium' },
        @{ Id = 'V-279425'; Title = 'NCC alert at 75% audit storage capacity.'; Sev = 'medium' },
        @{ Id = 'V-279426'; Title = 'Use synchronized system clocks for log timestamps.'; Sev = 'medium' },
        @{ Id = 'V-279427'; Title = 'Protect log files from unauthorized access.'; Sev = 'medium' },
        @{ Id = 'V-279430'; Title = 'Configure NCC to alert ISSO/ISSM.'; Sev = 'medium' },
        @{ Id = 'V-279431'; Title = 'Enforce access restrictions on configuration changes.'; Sev = 'medium' },
        @{ Id = 'V-279434'; Title = 'MFA via CAC authentication.'; Sev = 'high' },
        @{ Id = 'V-279435'; Title = 'MFA for local privileged access.'; Sev = 'high' },
        @{ Id = 'V-279438'; Title = 'Authenticate users individually before group auth.'; Sev = 'medium' },
        @{ Id = 'V-279439'; Title = 'MFA via client certificate authentication.'; Sev = 'medium' },
        @{ Id = 'V-279441'; Title = 'Terminate privileged UI sessions after 10 min inactivity.'; Sev = 'medium' },
        @{ Id = 'V-279442'; Title = 'RFC 5280-compliant certificate path validation.'; Sev = 'medium' },
        @{ Id = 'V-279443'; Title = 'Accept FICAM-approved third-party credentials.'; Sev = 'medium' },
        @{ Id = 'V-279444'; Title = 'Conform to FICAM-issued profiles.'; Sev = 'medium' },
        @{ Id = 'V-279445'; Title = 'Use DOD PKI-issued certificates.'; Sev = 'medium' },
        @{ Id = 'V-279446'; Title = 'Protect confidentiality/integrity of information at rest.'; Sev = 'medium' },
        @{ Id = 'V-279447'; Title = 'Cryptographic mechanisms for offline data at rest.'; Sev = 'medium' },
        @{ Id = 'V-279448'; Title = 'Cryptographic mechanisms for data at rest.'; Sev = 'medium' },
        @{ Id = 'V-279451'; Title = 'Restrict error messages to authorized users.'; Sev = 'medium' },
        @{ Id = 'V-279464'; Title = 'UI must initiate session logging upon startup.'; Sev = 'medium' },
        @{ Id = 'V-279486'; Title = 'Separate user functionality from VMM management.'; Sev = 'medium' },
        @{ Id = 'V-279526'; Title = 'Guest VM network via VMM virtual devices only.'; Sev = 'medium' }
    )

    $automated = @('V-279418', 'V-279450', 'V-279433', 'V-279440')
    foreach ($rule in $manualRules) {
        if ($rule.Id -in $automated) { continue }
        $results.Add((New-StigResult -Cluster $ClusterName -Target $target -StigName $stigName `
            -RuleId $rule.Id -Severity $rule.Sev -Title $rule.Title -Status 'Manual' `
            -Details 'Requires manual validation in Prism / policy documentation.'))
    }

    return $results
}

Export-ModuleMember -Function @(
    'Connect-NutanixPrism',
    'Invoke-NutanixApi',
    'Resolve-NutanixClusterHypervisor',
    'Get-NutanixClusterInventory',
    'Get-NutanixStigControlResults',
    'Invoke-NutanixNativeStigAudit',
    'Invoke-NutanixApplicationServerStigAudit'
)
