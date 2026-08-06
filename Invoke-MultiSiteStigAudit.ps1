#Requires -Version 7.0
<#
.SYNOPSIS
    Multi-site Nutanix and VMware STIG compliance audit script.

.DESCRIPTION
    Audits three identical site layouts against applicable DISA STIG checklists:
      - Nutanix Acropolis Application Server STIG
      - Nutanix Acropolis GPOS STIG
      - VMware vSphere 8.0 ESXi STIG
      - VMware vSphere 8.0 vCenter STIG
      - VMware vSphere 8.0 vCenter Appliance component STIGs (Envoy, EAM, Lookup, VAMI,
        Perfcharts, Photon OS 4.0, PostgreSQL, STS, UI)

    Outputs pass/fail summary and detail tables per site and STIG, plus CSV/JSON exports.

.PARAMETER ConfigPath
    Path to sites JSON config (see config/sites.example.json).

.PARAMETER NutanixCredential
    Credential for Prism Central (used for all Nutanix clusters in config).

.PARAMETER VMwareCredential
    Credential for vCenter SSO (e.g. administrator@vsphere.local).

.PARAMETER VcsaSshCredential
    Optional credential for VCSA SSH appliance checks (root or admin).

.PARAMETER StigXmlPath
    Optional path to extracted DISA STIG XCCDF XML folder. When provided, remaining
    unautomated rules are listed as Manual with titles from the official checklist.

.PARAMETER SkipCertificateCheck
    Skip TLS certificate validation for lab environments.

.PARAMETER IncludeVcsaSsh
    Run SSH-based vCenter appliance STIG checks (requires SSH enabled on VCSA).

.PARAMETER ExportFormat
    Export formats: Console (default), Csv, Json, All

.EXAMPLE
    $ntx = Get-Credential -Message 'Prism Central'
    $vmw = Get-Credential -Message 'vCenter SSO'
    .\Invoke-MultiSiteStigAudit.ps1 -ConfigPath .\config\sites.json `
        -NutanixCredential $ntx -VmwareCredential $vmw -SkipCertificateCheck

.NOTES
    Requires: PowerShell 7+, VMware PowerCLI for VMware checks
    Optional: Posh-SSH for VCSA appliance checks, Nutanix PC 2024.3+ for native STIG API
    Official VMware InSpec baselines recommended for full vCenter appliance STIG coverage.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$ConfigPath,

    [Parameter(Mandatory)]
    [pscredential]$NutanixCredential,

    [Parameter(Mandatory)]
    [pscredential]$VmwareCredential,

    [pscredential]$VcsaSshCredential,

    [string]$StigXmlPath,

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

function Read-SiteConfig {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Config file not found: $Path"
    }
    Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
}

function Add-XccdfManualPlaceholders {
    param(
        [System.Collections.Generic.List[object]]$Results,
        [hashtable]$Catalog,
        [string]$SiteName,
        [string]$Target,
        [string[]]$StigNamePatterns
    )

    foreach ($stigKey in $Catalog.Keys) {
        $matched = $StigNamePatterns | Where-Object { $stigKey -like "*$_*" }
        if (-not $matched) { continue }

        $existingIds = $Results | Where-Object { $_.StigName -eq $stigKey } | ForEach-Object { $_.RuleId }
        foreach ($rule in $Catalog[$stigKey]) {
            if ($rule.RuleId -in $existingIds) { continue }
            $Results.Add((New-StigResult -Site $SiteName -Target $Target -StigName $stigKey `
                -RuleId $rule.RuleId -Severity $rule.Severity -Title $rule.Title `
                -Status 'Manual' -Details 'No automated check implemented; review check content in STIG.'))
        }
    }
}

$config = Read-SiteConfig -Path $ConfigPath
$allResults = [System.Collections.Generic.List[object]]::new()
$xccdfCatalog = @{}

if ($StigXmlPath -and (Test-Path $StigXmlPath)) {
    Write-Host "Loading STIG XCCDF catalog from $StigXmlPath ..." -ForegroundColor Cyan
    $xccdfCatalog = Import-StigXccdfCatalog -Path $StigXmlPath
    Write-Host "  Loaded $($xccdfCatalog.Keys.Count) STIG benchmark(s)" -ForegroundColor Gray
} elseif ($config.stigXmlPath -and (Test-Path $config.stigXmlPath)) {
    $StigXmlPath = $config.stigXmlPath
    Write-Host "Loading STIG XCCDF catalog from config path $StigXmlPath ..." -ForegroundColor Cyan
    $xccdfCatalog = Import-StigXccdfCatalog -Path $StigXmlPath
}

$outputDir = if ($config.outputPath) { $config.outputPath } else { Join-Path $scriptRoot 'reports' }
$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'

foreach ($site in @($config.sites)) {
    $siteName = $site.name
    Write-Host "`n########## SITE: $siteName ##########" -ForegroundColor White -BackgroundColor DarkBlue

    if ($site.nutanix) {
        $pc = $site.nutanix.prismCentral
        $ntxSession = Connect-NutanixPrism -Fqdn $pc.fqdn -Port ($pc.port ?? 9440) `
            -Credential $NutanixCredential -SkipCertificateCheck:$SkipCertificateCheck

        $clusterNames = @($site.nutanix.clusters | ForEach-Object { $_.name })

        Write-Host "`n[Nutanix] Native GPOS STIG scan via Prism Central Security API..." -ForegroundColor Cyan
        $gposResults = Invoke-NutanixNativeStigAudit -SiteName $siteName -Session $ntxSession `
            -ClusterNames $clusterNames -StigName 'Nutanix Acropolis GPOS'
        $allResults.AddRange($gposResults)

        foreach ($cluster in @($site.nutanix.clusters)) {
            Write-Host "[Nutanix] Application Server STIG checks for $($cluster.name)..." -ForegroundColor Cyan
            $appResults = Invoke-NutanixApplicationServerStigAudit -SiteName $siteName `
                -Session $ntxSession -ClusterName $cluster.name
            $allResults.AddRange($appResults)
        }

        if ($xccdfCatalog.Count -gt 0) {
            Add-XccdfManualPlaceholders -Results $allResults -Catalog $xccdfCatalog `
                -SiteName $siteName -Target $pc.fqdn `
                -StigNamePatterns @('Nutanix Acropolis Application Server', 'Nutanix Acropolis GPOS')
        }
    }

    if ($site.vmware) {
        $vc = $site.vmware.vCenter
        $viConn = Connect-VmwareStigSession -VCenterFqdn $vc.fqdn -Credential $VmwareCredential `
            -SkipCertificateCheck:$SkipCertificateCheck

        try {
            $clusterName = $site.vmware.esxiCluster.name
            Write-Host "`n[VMware] ESXi STIG checks for cluster $clusterName..." -ForegroundColor Cyan
            $esxiResults = Invoke-VmwareEsxiStigAudit -SiteName $siteName -VIConnection $viConn `
                -ClusterName $clusterName
            $allResults.AddRange($esxiResults)

            Write-Host "[VMware] vCenter STIG checks..." -ForegroundColor Cyan
            $vcResults = Invoke-VmwareVCenterStigAudit -SiteName $siteName -VIConnection $viConn
            $allResults.AddRange($vcResults)

            if ($IncludeVcsaSsh) {
                $sshCred = if ($VcsaSshCredential) { $VcsaSshCredential } else { $VmwareCredential }
                Write-Host "[VMware] VCSA appliance STIG checks via SSH..." -ForegroundColor Cyan
                $vcsaResults = Invoke-VmwareVcsaApplianceStigAudit -SiteName $siteName `
                    -VcsaFqdn $vc.fqdn -Credential $sshCred
                $allResults.AddRange($vcsaResults)
            } else {
                Write-Host "[VMware] Skipping VCSA SSH checks (use -IncludeVcsaSsh to enable)" -ForegroundColor Yellow
            }

            if ($xccdfCatalog.Count -gt 0) {
                Add-XccdfManualPlaceholders -Results $allResults -Catalog $xccdfCatalog `
                    -SiteName $siteName -Target $vc.fqdn -StigNamePatterns @(
                        'VMware vSphere 8.0 ESXi',
                        'VMware vSphere 8.0 vCenter',
                        'Photon OS',
                        'PostgreSQL',
                        'VAMI',
                        'Envoy',
                        'EAM',
                        'Lookup Service',
                        'STS',
                        'User Interface',
                        'Perfcharts'
                    )
            }
        } finally {
            Disconnect-VIServer -Server $viConn -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
        }
    }

    $siteResults = @($allResults | Where-Object Site -eq $siteName)
    Write-StigSummaryTable -Results $siteResults -Title "$siteName - Overall Summary"
    Write-StigDetailTable -Results $siteResults -Title "$siteName - Failures & Manual Reviews" -Filter FailManual
}

Write-Host "`n$('=' * 60)" -ForegroundColor Cyan
Write-Host "GLOBAL STIG AUDIT SUMMARY" -ForegroundColor Cyan
Write-StigSummaryTable -Results $allResults -Title 'All Sites Combined'

$allResults | Group-Object StigName | Sort-Object Name | ForEach-Object {
    Write-StigSummaryTable -Results $_.Group -Title $_.Name
}

Write-StigDetailTable -Results $allResults -Title 'Complete Check Results (All Sites)' -Filter All

if (-not (Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
}

$csvPath = Join-Path $outputDir "stig-audit-$timestamp.csv"
$jsonPath = Join-Path $outputDir "stig-audit-$timestamp.json"

if ($ExportFormat -in @('Csv', 'All', 'Console')) {
    Export-StigResults -Results $allResults -OutputPath $csvPath
}
if ($ExportFormat -in @('Json', 'All')) {
    $allResults | ConvertTo-Json -Depth 5 | Set-Content -Path $jsonPath -Encoding UTF8
    Write-Host "Exported JSON to $jsonPath" -ForegroundColor Green
}

Write-Host "`nAudit complete. Total checks: $($allResults.Count)" -ForegroundColor Green
Write-Host "  Pass:          $(@($allResults | Where-Object Status -eq 'Pass').Count)" -ForegroundColor Green
Write-Host "  Fail:          $(@($allResults | Where-Object Status -eq 'Fail').Count)" -ForegroundColor Red
Write-Host "  Manual:        $(@($allResults | Where-Object Status -eq 'Manual').Count)" -ForegroundColor Yellow
Write-Host "  NotApplicable: $(@($allResults | Where-Object Status -eq 'NotApplicable').Count)" -ForegroundColor DarkGray
Write-Host "  Error:         $(@($allResults | Where-Object Status -eq 'Error').Count)" -ForegroundColor Magenta

return $allResults
