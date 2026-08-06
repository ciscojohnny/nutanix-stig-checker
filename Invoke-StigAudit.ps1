#Requires -Version 7.0
<#
.SYNOPSIS
    Nutanix STIG Checker — interactive cluster STIG audit (AHV or ESXi).

.DESCRIPTION
    Connects to Prism Central, Prism Element, and vCenter, discovers cluster
    inventory live, and audits ONE cluster at a time.

    Workflows:
      AHV  → Nutanix Acropolis Application Server + Acropolis GPOS
      ESXi → VMware vSphere 8.0 ESXi + vCenter + optional VCSA appliance STIGs

.PARAMETER ConfigPath
    Optional settings file (output path, STIG XML path). Default: .\config\clusters.json

.PARAMETER ClusterName
    Skip wizard and audit a cluster by name (requires -PrismFqdn or -VCenterFqdn).

.PARAMETER Workflow
    AHV or ESXi (required with direct targeting parameters).

.PARAMETER PrismFqdn
    Prism Central or Prism Element FQDN for direct AHV targeting.

.PARAMETER PrismEndpoint
    PC (Prism Central) or PE (Prism Element). Default: PC.

.PARAMETER VCenterFqdn
    vCenter FQDN for direct ESXi targeting.

.PARAMETER NutanixCredential
    Prism credential (prompted in wizard if omitted).

.PARAMETER VMwareCredential
    vCenter SSO credential (prompted in wizard if omitted).

.EXAMPLE
    .\Invoke-StigAudit.ps1

.EXAMPLE
    .\Invoke-StigAudit.ps1 -Workflow AHV -PrismFqdn prism.example.mil -PrismEndpoint PC `
        -ClusterName prod-cluster -NutanixCredential (Get-Credential)
#>
[CmdletBinding(DefaultParameterSetName = 'Wizard')]
param(
    [string]$ConfigPath = (Join-Path $PSScriptRoot 'config/clusters.json'),

    [Parameter(ParameterSetName = 'DirectAhv', Mandatory)]
    [Parameter(ParameterSetName = 'DirectEsxi', Mandatory)]
    [ValidateSet('AHV', 'ESXi')]
    [string]$Workflow,

    [Parameter(ParameterSetName = 'DirectAhv', Mandatory)]
    [string]$PrismFqdn,

    [Parameter(ParameterSetName = 'DirectAhv')]
    [ValidateSet('PC', 'PE')]
    [string]$PrismEndpoint = 'PC',

    [Parameter(ParameterSetName = 'DirectAhv', Mandatory)]
    [Parameter(ParameterSetName = 'DirectEsxi', Mandatory)]
    [string]$ClusterName,

    [Parameter(ParameterSetName = 'DirectEsxi', Mandatory)]
    [string]$VCenterFqdn,

    [pscredential]$NutanixCredential,
    [pscredential]$VmwareCredential,
    [pscredential]$VcsaSshCredential,

    [string]$StigXmlPath,
    [int]$PrismPort = 9440,
    [switch]$SkipCertificateCheck,
    [switch]$IncludeVcsaSsh,

    [ValidateSet('Console', 'Csv', 'Json', 'All')]
    [string]$ExportFormat = 'Console'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptRoot = $PSScriptRoot
Import-Module (Join-Path $scriptRoot 'Modules/StigFramework.psm1') -Force
Import-Module (Join-Path $scriptRoot 'Modules/Nutanix-StigChecks.psm1') -Force
Import-Module (Join-Path $scriptRoot 'Modules/VMware-StigChecks.psm1') -Force
Import-Module (Join-Path $scriptRoot 'Modules/VMware-Vcsa-StigChecks.psm1') -Force
Import-Module (Join-Path $scriptRoot 'Modules/StigWorkflows.psm1') -Force
Import-Module (Join-Path $scriptRoot 'Modules/StigWizard.psm1') -Force

function Read-AuditSettings {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        return [PSCustomObject]@{
            stigXmlPath           = $null
            outputPath            = (Join-Path $scriptRoot 'reports')
            skipCertificateCheck  = $false
        }
    }
    Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
}

function Resolve-XccdfCatalog {
    param($Settings)
    $catalog = @{}
    $path = $StigXmlPath
    if (-not $path -and $Settings.stigXmlPath -and (Test-Path $Settings.stigXmlPath)) {
        $path = $Settings.stigXmlPath
    }
    if ($path -and (Test-Path $path)) {
        Write-Host "Loading STIG XCCDF catalog from $path ..." -ForegroundColor Cyan
        $catalog = Import-StigXccdfCatalog -Path $path
        Write-Host "  Loaded $($catalog.Keys.Count) STIG benchmark(s)" -ForegroundColor Gray
    }
    return $catalog
}

function Get-CredentialsForWorkflow {
    param(
        [Parameter(Mandatory)][string]$WorkflowType,
        [pscredential]$NutanixCredential,
        [pscredential]$VmwareCredential,
        [pscredential]$VcsaSshCredential,
        [switch]$IncludeVcsaSsh
    )

    $creds = @{
        Nutanix = $NutanixCredential
        VMware  = $VmwareCredential
        VcsaSsh = $VcsaSshCredential
    }

    if ($WorkflowType -eq 'AHV' -and -not $creds.Nutanix) {
        Write-Host ''
        $creds.Nutanix = Get-Credential -Message 'Prism Central or Prism Element'
    }

    if ($WorkflowType -eq 'ESXi' -and -not $creds.Vmware) {
        Write-Host ''
        $creds.Vmware = Get-Credential -Message 'vCenter SSO (e.g. administrator@vsphere.local)'
    }

    if ($WorkflowType -eq 'ESXi' -and $IncludeVcsaSsh -and -not $creds.VcsaSsh) {
        Write-Host ''
        $creds.VcsaSsh = Get-Credential -Message 'VCSA SSH (root) — Cancel to reuse vCenter credential'
        if (-not $creds.VcsaSsh) { $creds.VcsaSsh = $creds.Vmware }
    }

    return $creds
}

function Write-AuditFooter {
    param([object[]]$Results, [string]$OutputDir, [string]$Timestamp, [string]$Label)

    if (@($Results).Count -eq 0) { return }

    Write-Host "`n$('=' * 60)" -ForegroundColor Cyan
    Write-Host $Label -ForegroundColor Cyan
    Write-StigSummaryTable -Results $Results -Title $Label

    $Results | Group-Object StigName | Sort-Object Name | ForEach-Object {
        Write-StigSummaryTable -Results $_.Group -Title $_.Name
    }

    Write-StigDetailTable -Results $Results -Title 'All Checks' -Filter All

    if (-not (Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    }

    $safeLabel = ($Label -replace '[^\w\-]', '_').ToLower()
    $csvPath = Join-Path $OutputDir "stig-audit-${safeLabel}-$Timestamp.csv"
    $jsonPath = Join-Path $OutputDir "stig-audit-${safeLabel}-$Timestamp.json"

    if ($ExportFormat -in @('Csv', 'All', 'Console')) {
        Export-StigResults -Results $Results -OutputPath $csvPath
    }
    if ($ExportFormat -in @('Json', 'All')) {
        $Results | ConvertTo-Json -Depth 5 | Set-Content -Path $jsonPath -Encoding UTF8
        Write-Host "Exported JSON to $jsonPath" -ForegroundColor Green
    }

    Write-Host "`nTotal checks: $($Results.Count)" -ForegroundColor Green
    Write-Host "  Pass:   $(@($Results | Where-Object Status -eq 'Pass').Count)" -ForegroundColor Green
    Write-Host "  Fail:   $(@($Results | Where-Object Status -eq 'Fail').Count)" -ForegroundColor Red
    Write-Host "  Manual: $(@($Results | Where-Object Status -eq 'Manual').Count)" -ForegroundColor Yellow
}

function Invoke-SingleClusterAudit {
    param(
        $ClusterSelection,
        $Settings,
        [hashtable]$XccdfCatalog,
        [switch]$IncludeVcsaSsh,
        [pscredential]$NutanixCredential,
        [pscredential]$VmwareCredential,
        [pscredential]$VcsaSshCredential
    )

    $creds = Get-CredentialsForWorkflow -WorkflowType $ClusterSelection.WorkflowType `
        -NutanixCredential $NutanixCredential -VmwareCredential $VmwareCredential `
        -VcsaSshCredential $VcsaSshCredential -IncludeVcsaSsh:$IncludeVcsaSsh

    $skipCert = $SkipCertificateCheck -or ($Settings.skipCertificateCheck -eq $true)

    Write-Host ''
    Write-Host "Starting audit: $($ClusterSelection.DisplayName)" -ForegroundColor Green

    return Invoke-ClusterStigWorkflow -ClusterSelection $ClusterSelection `
        -NutanixCredential $creds.Nutanix -VmwareCredential $creds.Vmware `
        -VcsaSshCredential $creds.VcsaSsh -XccdfCatalog $XccdfCatalog `
        -SkipCertificateCheck:$skipCert -IncludeVcsaSsh:$IncludeVcsaSsh
}

function Resolve-DirectAhvCluster {
    param(
        [string]$PrismFqdn,
        [string]$PrismEndpoint,
        [string]$ClusterName,
        [int]$Port,
        [switch]$SkipCertificateCheck,
        [pscredential]$Credential
    )

    if (-not $Credential) {
        $Credential = Get-Credential -Message 'Prism Central or Prism Element'
    }

    $session = Connect-NutanixPrism -Fqdn $PrismFqdn -Port $Port -Credential $Credential `
        -SkipCertificateCheck:$SkipCertificateCheck
    $discovered = @(Get-NutanixClusterInventory -Session $session -HypervisorFilter 'AHV')
    $match = $discovered | Where-Object ClusterName -eq $ClusterName | Select-Object -First 1
    if (-not $match) {
        $names = ($discovered | ForEach-Object ClusterName) -join ', '
        throw "Cluster '$ClusterName' not found on $PrismFqdn. Available: $names"
    }

    return New-StigClusterSelection -ClusterName $match.ClusterName -WorkflowType 'AHV' `
        -ManagementFqdn $PrismFqdn -ManagementPort $Port -NodeCount $match.NodeCount `
        -PrismEndpointType $PrismEndpoint -ClusterUuid $match.ClusterUuid
}

function Resolve-DirectEsxiCluster {
    param(
        [string]$VCenterFqdn,
        [string]$ClusterName,
        [switch]$SkipCertificateCheck,
        [pscredential]$Credential
    )

    if (-not $Credential) {
        $Credential = Get-Credential -Message 'vCenter SSO'
    }

    $discovered = @(Get-VmwareClusterInventory -VCenterFqdn $VCenterFqdn -Credential $Credential `
        -SkipCertificateCheck:$SkipCertificateCheck)
    $match = $discovered | Where-Object ClusterName -eq $ClusterName | Select-Object -First 1
    if (-not $match) {
        $names = ($discovered | ForEach-Object ClusterName) -join ', '
        throw "Cluster '$ClusterName' not found on $VCenterFqdn. Available: $names"
    }

    return New-StigClusterSelection -ClusterName $match.ClusterName -WorkflowType 'ESXi' `
        -ManagementFqdn $VCenterFqdn -ManagementPort 443 -NodeCount $match.NodeCount `
        -ClusterUuid $match.ClusterUuid
}

$settings = Read-AuditSettings -Path $ConfigPath
$xccdfCatalog = Resolve-XccdfCatalog -Settings $settings
$outputDir = if ($settings.outputPath) { $settings.outputPath } else { Join-Path $scriptRoot 'reports' }
$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$allResults = [System.Collections.Generic.List[object]]::new()
$skipCert = $SkipCertificateCheck -or ($settings.skipCertificateCheck -eq $true)

if ($PSCmdlet.ParameterSetName -eq 'DirectAhv') {
    if ($Workflow -ne 'AHV') { throw 'Direct AHV mode requires -Workflow AHV.' }
    $cluster = Resolve-DirectAhvCluster -PrismFqdn $PrismFqdn -PrismEndpoint $PrismEndpoint `
        -ClusterName $ClusterName -Port $PrismPort -SkipCertificateCheck:$skipCert `
        -Credential $NutanixCredential
    Show-ClusterStigSummary -Cluster $cluster
    $batchResults = Invoke-SingleClusterAudit -ClusterSelection $cluster -Settings $settings `
        -XccdfCatalog $xccdfCatalog -NutanixCredential $NutanixCredential
    $allResults.AddRange(@($batchResults))
    Write-AuditFooter -Results $allResults -OutputDir $outputDir -Timestamp $timestamp -Label $ClusterName
}
elseif ($PSCmdlet.ParameterSetName -eq 'DirectEsxi') {
    if ($Workflow -ne 'ESXi') { throw 'Direct ESXi mode requires -Workflow ESXi.' }
    $cluster = Resolve-DirectEsxiCluster -VCenterFqdn $VCenterFqdn -ClusterName $ClusterName `
        -SkipCertificateCheck:$skipCert -Credential $VmwareCredential
    Show-ClusterStigSummary -Cluster $cluster
    $batchResults = Invoke-SingleClusterAudit -ClusterSelection $cluster -Settings $settings `
        -XccdfCatalog $xccdfCatalog -IncludeVcsaSsh:$IncludeVcsaSsh `
        -VmwareCredential $VmwareCredential -VcsaSshCredential $VcsaSshCredential
    $allResults.AddRange(@($batchResults))
    Write-AuditFooter -Results $allResults -OutputDir $outputDir -Timestamp $timestamp -Label $ClusterName
}
else {
    $allResults = Invoke-StigWizardLoop -Config $settings -SkipCertificateCheck:$skipCert `
        -NutanixCredential $NutanixCredential -VmwareCredential $VmwareCredential `
        -OnClusterSelected {
            param($WizardResult)
            Invoke-SingleClusterAudit -ClusterSelection $WizardResult.Cluster -Settings $settings `
                -XccdfCatalog $xccdfCatalog -IncludeVcsaSsh:$WizardResult.IncludeVcsaSsh `
                -NutanixCredential $WizardResult.NutanixCredential `
                -VmwareCredential $WizardResult.VmwareCredential `
                -VcsaSshCredential $VcsaSshCredential
        }

    if (@($allResults).Count -gt 0) {
        Write-AuditFooter -Results $allResults -OutputDir $outputDir -Timestamp $timestamp `
            -Label 'wizard-session'
    }
}

return $allResults
