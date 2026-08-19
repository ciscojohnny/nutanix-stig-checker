#Requires -Version 7.0
Set-StrictMode -Version Latest

Import-Module (Join-Path $PSScriptRoot 'StigFramework.psm1') -Force

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
        $items = @(Get-ObjectProperty -InputObject $response -Name 'data')
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

    $status = Get-ObjectProperty -InputObject $Entity -Name 'status'
    $statusResources = Get-ObjectProperty -InputObject $status -Name 'resources'
    $statusConfig = Get-ObjectProperty -InputObject $statusResources -Name 'config'

    if ($null -ne $statusConfig) {
        $hypervisorTypes = Get-ObjectProperty -InputObject $statusConfig -Name 'hypervisor_types'
        if ($hypervisorTypes) {
            $signals.AddRange(@($hypervisorTypes | ForEach-Object { [string]$_ }))
        }
        $hypervisorType = Get-ObjectProperty -InputObject $statusConfig -Name 'hypervisor_type'
        if ($hypervisorType) { $signals.Add([string]$hypervisorType) }
    }

    $spec = Get-ObjectProperty -InputObject $Entity -Name 'spec'
    $specResources = Get-ObjectProperty -InputObject $spec -Name 'resources'
    $specConfig = Get-ObjectProperty -InputObject $specResources -Name 'config'

    if ($null -ne $specConfig) {
        $hypervisorTypes = Get-ObjectProperty -InputObject $specConfig -Name 'hypervisor_types'
        if ($hypervisorTypes) {
            $signals.AddRange(@($hypervisorTypes | ForEach-Object { [string]$_ }))
        }
        $hypervisorType = Get-ObjectProperty -InputObject $specConfig -Name 'hypervisor_type'
        if ($hypervisorType) { $signals.Add([string]$hypervisorType) }
    }

    $nodeList = Get-ObjectProperty -InputObject $statusResources -Name 'nodes'
    $hypervisorServerList = Get-ObjectProperty -InputObject $nodeList -Name 'hypervisor_server_list'
    if ($hypervisorServerList) {
        foreach ($srv in @($hypervisorServerList)) {
            $srvHypervisor = Get-ObjectProperty -InputObject $srv -Name 'hypervisor_type'
            if ($srvHypervisor) { $signals.Add([string]$srvHypervisor) }
            $srvType = Get-ObjectProperty -InputObject $srv -Name 'type'
            if ($srvType) { $signals.Add([string]$srvType) }
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
    foreach ($entity in @(Get-ObjectProperty -InputObject $response -Name 'entities')) {
        $status = Get-ObjectProperty -InputObject $entity -Name 'status'
        $name = Get-ObjectProperty -InputObject $status -Name 'name'
        $metadata = Get-ObjectProperty -InputObject $entity -Name 'metadata'
        $uuid = Get-ObjectProperty -InputObject $metadata -Name 'uuid'
        $statusResources = Get-ObjectProperty -InputObject $status -Name 'resources'
        $nodeList = Get-ObjectProperty -InputObject $statusResources -Name 'nodes'
        $hypervisorServerList = Get-ObjectProperty -InputObject $nodeList -Name 'hypervisor_server_list'
        $nodeUuids = Get-ObjectProperty -InputObject $statusResources -Name 'node_uuids'

        $nodes = if ($hypervisorServerList) {
            @($hypervisorServerList).Count
        } elseif ($nodeUuids) {
            @($nodeUuids).Count
        } else {
            '?'
        }

        $config = Get-ObjectProperty -InputObject $statusResources -Name 'config'
        $version = ''
        if ($null -ne $config) {
            $softwareMap = Get-ObjectProperty -InputObject $config -Name 'software_map'
            $nos = Get-ObjectProperty -InputObject $softwareMap -Name 'NOS'
            if ($nos) {
                $version = Get-ObjectProperty -InputObject $nos -Name 'version'
            } else {
                $buildInfo = Get-ObjectProperty -InputObject $config -Name 'build_info'
                if ($buildInfo) {
                    $version = Get-ObjectProperty -InputObject $buildInfo -Name 'version'
                }
            }
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
    foreach ($c in @(Get-ObjectProperty -InputObject $clusters -Name 'entities')) {
        $metadata = Get-ObjectProperty -InputObject $c -Name 'metadata'
        $extId = Get-ObjectProperty -InputObject $metadata -Name 'uuid'
        $status = Get-ObjectProperty -InputObject $c -Name 'status'
        $name = Get-ObjectProperty -InputObject $status -Name 'name'
        if ($name -and $extId) {
            $map[$name] = $extId
            $map[$extId] = $name
        }
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
            $ruleIdVal = Get-ObjectProperty -InputObject $ctrl -Name 'ruleId'
            $stigRuleIdVal = Get-ObjectProperty -InputObject $ctrl -Name 'stigRuleId'
            $extIdVal = Get-ObjectProperty -InputObject $ctrl -Name 'extId'
            $ruleId = if ($ruleIdVal) { $ruleIdVal } elseif ($stigRuleIdVal) { $stigRuleIdVal } else { "NTNX-$extIdVal" }

            $titleVal = Get-ObjectProperty -InputObject $ctrl -Name 'title'
            $nameVal = Get-ObjectProperty -InputObject $ctrl -Name 'name'
            $title = if ($titleVal) { $titleVal } elseif ($nameVal) { $nameVal } else { 'Nutanix STIG control' }

            $severityRaw = Get-ObjectProperty -InputObject $ctrl -Name 'severity'
            $severity = (($severityRaw ?? 'medium').ToString().ToLower())

            $status = Convert-NutanixStigStatus -ApiStatus (Get-ObjectProperty -InputObject $ctrl -Name 'status') `
                -ComplianceStatus (Get-ObjectProperty -InputObject $ctrl -Name 'complianceStatus')

            $remediation = Get-ObjectProperty -InputObject $ctrl -Name 'remediation'
            $description = Get-ObjectProperty -InputObject $ctrl -Name 'description'
            $details = if ($remediation) { $remediation } elseif ($description) { $description } else { '' }

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
            $ntpEntities = @(Get-ObjectProperty -InputObject $ntp -Name 'entities')
            $servers = @($ntpEntities | ForEach-Object {
                $entityStatus = Get-ObjectProperty -InputObject $_ -Name 'status'
                $entityResources = Get-ObjectProperty -InputObject $entityStatus -Name 'resources'
                Get-ObjectProperty -InputObject $entityResources -Name 'ntp_server_ip_list'
            }) | Where-Object { $_ }
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
            $dirEntities = @(Get-ObjectProperty -InputObject $dirs -Name 'entities')
            if ($dirEntities.Count -gt 0) {
                $names = $dirEntities | ForEach-Object {
                    $entitySpec = Get-ObjectProperty -InputObject $_ -Name 'spec'
                    Get-ObjectProperty -InputObject $entitySpec -Name 'name'
                }
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
            $dirEntities = @(Get-ObjectProperty -InputObject $dirs -Name 'entities')
            $ldap = @($dirEntities | Where-Object {
                $entitySpec = Get-ObjectProperty -InputObject $_ -Name 'spec'
                $entityResources = Get-ObjectProperty -InputObject $entitySpec -Name 'resources'
                Get-ObjectProperty -InputObject $entityResources -Name 'domain_name'
            })
            if ($ldap.Count -eq 0) {
                return @{ Status = 'NotApplicable'; Details = 'LDAP not in use' }
            }
            $insecure = $ldap | Where-Object {
                $entitySpec = Get-ObjectProperty -InputObject $_ -Name 'spec'
                $entityResources = Get-ObjectProperty -InputObject $entitySpec -Name 'resources'
                $url = Get-ObjectProperty -InputObject $entityResources -Name 'url'
                if (-not $url) {
                    $url = Get-ObjectProperty -InputObject $entityResources -Name 'directory_url'
                }
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
