#Requires -Version 7.0
Set-StrictMode -Version Latest

function Get-StigWorkflowDefinition {
    [CmdletBinding()]
    param(
        [ValidateSet('AHV', 'ESXi')]
        [Parameter(Mandatory)]
        [string]$WorkflowType
    )

    switch ($WorkflowType) {
        'AHV' {
            [PSCustomObject]@{
                WorkflowType     = 'AHV'
                Label            = 'Nutanix AHV Cluster'
                StigChecklists   = @(
                    'Nutanix Acropolis Application Server'
                    'Nutanix Acropolis GPOS'
                )
                StigNamePatterns = @(
                    'Nutanix Acropolis Application Server'
                    'Nutanix Acropolis GPOS'
                )
                Description      = 'Prism Central GPOS native scan + Application Server API/manual checks'
            }
        }
        'ESXi' {
            [PSCustomObject]@{
                WorkflowType     = 'ESXi'
                Label            = 'VMware ESXi Cluster'
                StigChecklists   = @(
                    'VMware vSphere 8.0 ESXi'
                    'VMware vSphere 8.0 vCenter'
                    'VMware vSphere 8.0 vCenter Appliance Photon OS 4.0'
                    'VMware vSphere 8.0 vCenter Appliance PostgreSQL'
                    'VMware vSphere 8.0 vCenter Appliance VAMI'
                    'VMware vSphere 8.0 vCenter Appliance Envoy'
                    'VMware vSphere 8.0 vCenter Appliance ESX Agent Manager (EAM)'
                    'VMware vSphere 8.0 vCenter Appliance Lookup Service'
                    'VMware vSphere 8.0 vCenter Appliance Secure Token Service (STS)'
                    'VMware vSphere 8.0 vCenter Appliance User Interface (UI)'
                    'VMware vSphere 8.0 vCenter Appliance Perfcharts'
                )
                StigNamePatterns = @(
                    'VMware vSphere 8.0 ESXi'
                    'VMware vSphere 8.0 vCenter'
                    'Photon OS'
                    'PostgreSQL'
                    'VAMI'
                    'Envoy'
                    'EAM'
                    'Lookup Service'
                    'STS'
                    'User Interface'
                    'Perfcharts'
                )
                Description      = 'ESXi host PowerCLI checks + vCenter/VCSA appliance checks'
            }
        }
    }
}

function New-StigClusterSelection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ClusterName,
        [Parameter(Mandatory)][ValidateSet('AHV', 'ESXi')][string]$WorkflowType,
        [Parameter(Mandatory)][string]$ManagementFqdn,
        [int]$ManagementPort = 0,
        $NodeCount = '?',
        [string]$PrismEndpointType = '',
        [string]$PrismFqdn = '',
        [int]$PrismPort = 0,
        [string]$ClusterUuid = ''
    )

    $wf = Get-StigWorkflowDefinition -WorkflowType $WorkflowType
    $port = if ($ManagementPort -gt 0) {
        $ManagementPort
    } elseif ($WorkflowType -eq 'AHV') {
        9440
    } else {
        443
    }

    $prismLabel = if ($PrismEndpointType -eq 'PE') { 'Prism Element' } else { 'Prism Central' }

    $endpointLabel = switch ($WorkflowType) {
        'AHV' { $prismLabel }
        'ESXi' {
            if ($PrismFqdn) { "$prismLabel → vCenter" } else { 'vCenter' }
        }
    }

    $displayName = "$ClusterName [$WorkflowType, $NodeCount nodes — $endpointLabel]"

    [PSCustomObject]@{
        ClusterName         = $ClusterName
        ClusterUuid         = $ClusterUuid
        WorkflowType        = $WorkflowType
        NodeCount           = $NodeCount
        ManagementFqdn      = $ManagementFqdn
        ManagementPort      = $port
        PrismEndpointType   = $PrismEndpointType
        PrismFqdn           = $PrismFqdn
        PrismPort           = if ($PrismPort -gt 0) { $PrismPort } else { 9440 }
        ManagementLabel     = if ($WorkflowType -eq 'ESXi') { 'vCenter' } else { $prismLabel }
        StigChecklists      = $wf.StigChecklists
        DisplayName         = $displayName
    }
}

function Get-ClusterInventoryFromConfig {
    <#
    .SYNOPSIS
        Deprecated: clusters are discovered live from Prism or vCenter in the wizard.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Config)
    Write-Warning 'Config-based cluster lists are no longer used. Connect to Prism Central/Element or vCenter in the wizard.'
    return @()
}

function Add-XccdfManualPlaceholders {
    param(
        [System.Collections.Generic.List[object]]$Results,
        [hashtable]$Catalog,
        [string]$ClusterName,
        [string]$Target,
        [string[]]$StigNamePatterns
    )

    foreach ($stigKey in $Catalog.Keys) {
        $matched = $StigNamePatterns | Where-Object { $stigKey -like "*$_*" }
        if (-not $matched) { continue }

        $existingIds = $Results | Where-Object { $_.StigName -eq $stigKey } | ForEach-Object { $_.RuleId }
        foreach ($rule in $Catalog[$stigKey]) {
            if ($rule.RuleId -in $existingIds) { continue }
            $Results.Add((New-StigResult -Cluster $ClusterName -Target $Target -StigName $stigKey `
                -RuleId $rule.RuleId -Severity $rule.Severity -Title $rule.Title `
                -Status 'Manual' -Details 'No automated check implemented; review check content in STIG.'))
        }
    }
}

function Invoke-AhvClusterStigWorkflow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ClusterName,
        [Parameter(Mandatory)][hashtable]$NutanixSession,
        [hashtable]$XccdfCatalog = @{},
        [string]$TargetLabel
    )

    $results = [System.Collections.Generic.List[object]]::new()
    $target = if ($TargetLabel) { $TargetLabel } else { "$($NutanixSession.Fqdn) / $ClusterName" }
    $wf = Get-StigWorkflowDefinition -WorkflowType 'AHV'

    Write-Host "`n  Workflow: $($wf.Label)" -ForegroundColor Cyan
    Write-Host "  STIGs:" -ForegroundColor Gray
    $wf.StigChecklists | ForEach-Object { Write-Host "    - $_" -ForegroundColor Gray }

    Write-Host "`n  [1/2] Nutanix Acropolis GPOS (native PC STIG scan)..." -ForegroundColor Yellow
    $gpos = Invoke-NutanixNativeStigAudit -Session $NutanixSession `
        -ClusterNames @($ClusterName) -StigName 'Nutanix Acropolis GPOS'
    $results.AddRange($gpos)

    Write-Host "  [2/2] Nutanix Acropolis Application Server..." -ForegroundColor Yellow
    $app = Invoke-NutanixApplicationServerStigAudit -ClusterName $ClusterName -Session $NutanixSession
    $results.AddRange($app)

    if ($XccdfCatalog.Count -gt 0) {
        Add-XccdfManualPlaceholders -Results $results -Catalog $XccdfCatalog `
            -ClusterName $ClusterName -Target $target -StigNamePatterns $wf.StigNamePatterns
    }

    return $results
}

function Invoke-EsxiClusterStigWorkflow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ClusterName,
        [Parameter(Mandatory)]$VIConnection,
        [Parameter(Mandatory)][string]$VCenterFqdn,
        [switch]$IncludeVcsaSsh,
        [pscredential]$VcsaSshCredential,
        [pscredential]$VmwareCredential,
        [hashtable]$XccdfCatalog = @{}
    )

    $results = [System.Collections.Generic.List[object]]::new()
    $wf = Get-StigWorkflowDefinition -WorkflowType 'ESXi'

    Write-Host "`n  Workflow: $($wf.Label)" -ForegroundColor Cyan
    Write-Host "  STIGs:" -ForegroundColor Gray
    $wf.StigChecklists | ForEach-Object { Write-Host "    - $_" -ForegroundColor Gray }

    Write-Host "`n  [1/3] VMware vSphere 8.0 ESXi (hosts in $ClusterName)..." -ForegroundColor Yellow
    $esxi = Invoke-VmwareEsxiStigAudit -ClusterName $ClusterName -VIConnection $VIConnection
    $results.AddRange($esxi)

    Write-Host "  [2/3] VMware vSphere 8.0 vCenter..." -ForegroundColor Yellow
    $vc = Invoke-VmwareVCenterStigAudit -ClusterName $ClusterName -VIConnection $VIConnection
    $results.AddRange($vc)

    if ($IncludeVcsaSsh) {
        Write-Host "  [3/3] VCSA appliance component STIGs (SSH)..." -ForegroundColor Yellow
        $sshCred = if ($VcsaSshCredential) { $VcsaSshCredential } else { $VmwareCredential }
        $vcsa = Invoke-VmwareVcsaApplianceStigAudit -ClusterName $ClusterName `
            -VcsaFqdn $VCenterFqdn -Credential $sshCred
        $results.AddRange($vcsa)
    } else {
        Write-Host "  [3/3] VCSA appliance checks skipped (enable in wizard or use -IncludeVcsaSsh)" -ForegroundColor DarkYellow
    }

    if ($XccdfCatalog.Count -gt 0) {
        Add-XccdfManualPlaceholders -Results $results -Catalog $XccdfCatalog `
            -ClusterName $ClusterName -Target $VCenterFqdn -StigNamePatterns $wf.StigNamePatterns
    }

    return $results
}

function Invoke-ClusterStigWorkflow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$ClusterSelection,
        [pscredential]$NutanixCredential,
        [pscredential]$VmwareCredential,
        [pscredential]$VcsaSshCredential,
        [hashtable]$XccdfCatalog = @{},
        [switch]$SkipCertificateCheck,
        [switch]$IncludeVcsaSsh
    )

    switch ($ClusterSelection.WorkflowType) {
        'AHV' {
            if (-not $NutanixCredential) {
                throw 'NutanixCredential is required for AHV cluster workflows.'
            }
            $session = Connect-NutanixPrism -Fqdn $ClusterSelection.ManagementFqdn `
                -Port $ClusterSelection.ManagementPort -Credential $NutanixCredential `
                -SkipCertificateCheck:$SkipCertificateCheck

            return Invoke-AhvClusterStigWorkflow -ClusterName $ClusterSelection.ClusterName `
                -NutanixSession $session -XccdfCatalog $XccdfCatalog
        }
        'ESXi' {
            if (-not $VmwareCredential) {
                throw 'VmwareCredential is required for ESXi cluster workflows.'
            }
            $viConn = Connect-VmwareStigSession -VCenterFqdn $ClusterSelection.ManagementFqdn `
                -Credential $VmwareCredential -SkipCertificateCheck:$SkipCertificateCheck
            try {
                return Invoke-EsxiClusterStigWorkflow -ClusterName $ClusterSelection.ClusterName `
                    -VIConnection $viConn -VCenterFqdn $ClusterSelection.ManagementFqdn `
                    -IncludeVcsaSsh:$IncludeVcsaSsh `
                    -VcsaSshCredential $VcsaSshCredential `
                    -VmwareCredential $VmwareCredential `
                    -XccdfCatalog $XccdfCatalog
            } finally {
                Disconnect-VIServer -Server $viConn -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
            }
        }
        default {
            throw "Unknown workflow type: $($ClusterSelection.WorkflowType)"
        }
    }
}

Export-ModuleMember -Function @(
    'Get-StigWorkflowDefinition',
    'New-StigClusterSelection',
    'Get-ClusterInventoryFromConfig',
    'Invoke-AhvClusterStigWorkflow',
    'Invoke-EsxiClusterStigWorkflow',
    'Invoke-ClusterStigWorkflow'
)
