#Requires -Version 7.0
Set-StrictMode -Version Latest

function Write-WizardHeader {
    param([string]$Title)
    Write-Host ''
    Write-Host ('=' * 64) -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host ('=' * 64) -ForegroundColor Cyan
    Write-Host ''
}

function Read-WizardChoice {
    param(
        [Parameter(Mandatory)][string]$Prompt,
        [Parameter(Mandatory)][int]$Min,
        [Parameter(Mandatory)][int]$Max,
        [int]$Default = 0
    )

    while ($true) {
        $hint = if ($Default -gt 0) { " [$Default]" } else { '' }
        $raw = Read-Host "$Prompt ($Min-$Max)$hint"
        if ([string]::IsNullOrWhiteSpace($raw) -and $Default -gt 0) { return $Default }
        if ($raw -match '^\d+$') {
            $choice = [int]$raw
            if ($choice -ge $Min -and $choice -le $Max) { return $choice }
        }
        Write-Host '  Invalid selection. Enter a number in range.' -ForegroundColor Yellow
    }
}

function Read-WizardFqdn {
    param(
        [Parameter(Mandatory)][string]$Prompt,
        [string]$Default = ''
    )

    while ($true) {
        $hint = if ($Default) { " [$Default]" } else { '' }
        $raw = Read-Host "$Prompt$hint"
        if ([string]::IsNullOrWhiteSpace($raw) -and $Default) { return $Default }
        $raw = $raw.Trim()
        if ($raw) { return $raw }
        Write-Host '  A hostname or IP address is required.' -ForegroundColor Yellow
    }
}

function Confirm-WizardContinue {
    param([string]$Prompt = 'Continue?')
    $answer = Read-Host "$Prompt [Y/n]"
    return ($answer -eq '' -or $answer -match '^[Yy]')
}

function Show-WorkflowStigInfo {
    param([Parameter(Mandatory)][string]$WorkflowType)
    $wf = Get-StigWorkflowDefinition -WorkflowType $WorkflowType
    Write-Host ''
    Write-Host "  $($wf.Label)" -ForegroundColor Green
    Write-Host "  $($wf.Description)" -ForegroundColor DarkGray
    Write-Host ''
    Write-Host '  STIG checklists included:' -ForegroundColor Green
    $i = 1
    foreach ($stig in $wf.StigChecklists) {
        Write-Host ("    {0}. {1}" -f $i, $stig)
        $i++
    }
    Write-Host ''
}

function Show-ClusterStigSummary {
    param([Parameter(Mandatory)]$Cluster)
    Write-Host ''
    Write-Host '  Selected cluster:' -ForegroundColor Green
    Write-Host "    Name:       $($Cluster.ClusterName)"
    Write-Host "    Type:       $($Cluster.WorkflowType)"
    Write-Host "    Nodes:      $($Cluster.NodeCount)"
    Write-Host "    Endpoint:   $($Cluster.ManagementLabel) ($($Cluster.ManagementFqdn):$($Cluster.ManagementPort))"
    if ($Cluster.ClusterUuid) {
        Write-Host "    UUID:       $($Cluster.ClusterUuid)" -ForegroundColor DarkGray
    }
    Write-Host ''
    Show-WorkflowStigInfo -WorkflowType $Cluster.WorkflowType
}

function Select-ClusterFromInventory {
    param(
        [Parameter(Mandatory)][object[]]$Inventory,
        [Parameter(Mandatory)][string]$SourceLabel
    )

    if (@($Inventory).Count -eq 0) {
        throw "No clusters returned from $SourceLabel."
    }

    Write-Host ''
    Write-Host "Clusters discovered on ${SourceLabel}:" -ForegroundColor White
    for ($i = 0; $i -lt $Inventory.Count; $i++) {
        $c = $Inventory[$i]
        $version = if ($c.AosVersion) { " | AOS $($c.AosVersion)" } else { '' }
        Write-Host ("  {0}. {1} ({2} nodes{3})" -f ($i + 1), $c.ClusterName, $c.NodeCount, $version)
    }

    $choice = Read-WizardChoice -Prompt 'Cluster' -Min 1 -Max $Inventory.Count
    return $Inventory[$choice - 1]
}

function Get-AhvClusterFromPrismWizard {
    param(
        [switch]$SkipCertificateCheck,
        [pscredential]$NutanixCredential
    )

    Write-Host ''
    Write-Host 'Step 2: Nutanix management endpoint' -ForegroundColor White
    Write-Host '  1. Prism Central  (lists all registered clusters)'
    Write-Host '  2. Prism Element   (local cluster on a single PE instance)'
    Write-Host ''

    $endpointChoice = Read-WizardChoice -Prompt 'Endpoint type' -Min 1 -Max 2
    $prismType = if ($endpointChoice -eq 1) { 'PC' } else { 'PE' }
    $endpointLabel = if ($prismType -eq 'PC') { 'Prism Central' } else { 'Prism Element' }

    Write-Host ''
    $fqdn = Read-WizardFqdn -Prompt "$endpointLabel FQDN or IP"
    $portRaw = Read-Host "Port [9440]"
    $port = if ([string]::IsNullOrWhiteSpace($portRaw)) { 9440 } else { [int]$portRaw }

    if (-not $NutanixCredential) {
        Write-Host ''
        $NutanixCredential = Get-Credential -Message "$endpointLabel credentials"
    }

    Write-Host ''
    Write-Host "Connecting to $endpointLabel at ${fqdn}:${port}..." -ForegroundColor Cyan
    $session = Connect-NutanixPrism -Fqdn $fqdn -Port $port -Credential $NutanixCredential `
        -SkipCertificateCheck:$SkipCertificateCheck

    Write-Host 'Retrieving cluster inventory...' -ForegroundColor Cyan
    $discovered = @(Get-NutanixClusterInventory -Session $session)
    $picked = Select-ClusterFromInventory -Inventory $discovered -SourceLabel $endpointLabel

    $selection = New-StigClusterSelection -ClusterName $picked.ClusterName `
        -WorkflowType 'AHV' -ManagementFqdn $fqdn -ManagementPort $port `
        -NodeCount $picked.NodeCount -PrismEndpointType $prismType -ClusterUuid $picked.ClusterUuid

    return @{
        Cluster            = $selection
        NutanixCredential  = $NutanixCredential
        IncludeVcsaSsh     = $false
    }
}

function Get-EsxiClusterFromVcenterWizard {
    param(
        [switch]$SkipCertificateCheck,
        [pscredential]$VmwareCredential
    )

    Write-Host ''
    Write-Host 'Step 2: vCenter connection' -ForegroundColor White
    $fqdn = Read-WizardFqdn -Prompt 'vCenter FQDN or IP'

    if (-not $VmwareCredential) {
        Write-Host ''
        $VmwareCredential = Get-Credential -Message 'vCenter SSO (e.g. administrator@vsphere.local)'
    }

    Write-Host ''
    Write-Host "Connecting to vCenter at $fqdn..." -ForegroundColor Cyan
    Write-Host 'Retrieving cluster inventory...' -ForegroundColor Cyan
    $discovered = @(Get-VmwareClusterInventory -VCenterFqdn $fqdn -Credential $VmwareCredential `
        -SkipCertificateCheck:$SkipCertificateCheck)

    $picked = Select-ClusterFromInventory -Inventory $discovered -SourceLabel "vCenter ($fqdn)"

    $selection = New-StigClusterSelection -ClusterName $picked.ClusterName `
        -WorkflowType 'ESXi' -ManagementFqdn $fqdn -ManagementPort 443 `
        -NodeCount $picked.NodeCount -ClusterUuid $picked.ClusterUuid

    Write-Host ''
    Write-Host 'Step 3: VCSA appliance STIG checks (SSH)' -ForegroundColor White
    Write-Host '  Photon OS, PostgreSQL, VAMI, Envoy, EAM, Lookup, STS, UI, Perfcharts'
    $includeVcsaSsh = Confirm-WizardContinue -Prompt 'Include VCSA SSH appliance checks?'

    return @{
        Cluster           = $selection
        VMwareCredential  = $VmwareCredential
        IncludeVcsaSsh    = $includeVcsaSsh
    }
}

function Invoke-StigClusterWizard {
    [CmdletBinding()]
    param(
        $Config,
        [switch]$SkipCertificateCheck,
        [pscredential]$NutanixCredential,
        [pscredential]$VmwareCredential
    )

    Write-WizardHeader -Title 'Nutanix STIG Checker — Cluster Wizard'

    Write-Host 'Step 1: Select cluster type' -ForegroundColor White
    Write-Host ''
    Write-Host '  1. Nutanix AHV'
    Write-Host '     STIGs: Acropolis Application Server, Acropolis GPOS'
    Write-Host ''
    Write-Host '  2. VMware ESXi'
    Write-Host '     STIGs: ESXi, vCenter, VCSA appliance components (optional SSH)'
    Write-Host ''

    $typeChoice = Read-WizardChoice -Prompt 'Cluster type' -Min 1 -Max 2
    $workflowType = if ($typeChoice -eq 1) { 'AHV' } else { 'ESXi' }

    Show-WorkflowStigInfo -WorkflowType $workflowType

    $wizardData = if ($workflowType -eq 'AHV') {
        Get-AhvClusterFromPrismWizard -SkipCertificateCheck:$SkipCertificateCheck `
            -NutanixCredential $NutanixCredential
    } else {
        Get-EsxiClusterFromVcenterWizard -SkipCertificateCheck:$SkipCertificateCheck `
            -VmwareCredential $VmwareCredential
    }

    Show-ClusterStigSummary -Cluster $wizardData.Cluster

    if (-not (Confirm-WizardContinue -Prompt 'Run STIG audit on this cluster?')) {
        Write-Host 'Audit cancelled.' -ForegroundColor Yellow
        return $null
    }

    return [PSCustomObject]$wizardData
}

function Invoke-StigWizardLoop {
    [CmdletBinding()]
    param(
        $Config,
        [switch]$SkipCertificateCheck,
        [pscredential]$NutanixCredential,
        [pscredential]$VmwareCredential,
        [scriptblock]$OnClusterSelected
    )

    $keepRunning = $true
    $allResults = [System.Collections.Generic.List[object]]::new()

    while ($keepRunning) {
        $wizardResult = Invoke-StigClusterWizard -Config $Config `
            -SkipCertificateCheck:$SkipCertificateCheck `
            -NutanixCredential $NutanixCredential -VmwareCredential $VmwareCredential

        if (-not $wizardResult) {
            $keepRunning = Confirm-WizardContinue -Prompt 'Connect to another endpoint?'
            continue
        }

        $batchResults = & $OnClusterSelected $wizardResult
        if ($batchResults) {
            $allResults.AddRange(@($batchResults))

            Write-WizardHeader -Title "Results: $($wizardResult.Cluster.DisplayName)"
            Write-StigSummaryTable -Results $batchResults -Title 'Cluster Summary'
            Write-StigDetailTable -Results $batchResults -Title 'Check Details' -Filter All
        }

        Write-Host ''
        $keepRunning = Confirm-WizardContinue -Prompt 'Audit another cluster?'
    }

    return $allResults
}

Export-ModuleMember -Function @(
    'Invoke-StigClusterWizard',
    'Invoke-StigWizardLoop',
    'Show-ClusterStigSummary',
    'Show-WorkflowStigInfo'
)
