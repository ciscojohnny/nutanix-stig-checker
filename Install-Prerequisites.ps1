#Requires -Version 7.0
<#
.SYNOPSIS
    Installs PowerShell modules required for STIG auditing.
#>
[CmdletBinding()]
param(
    [switch]$IncludeVcsaSsh
)

$modules = @(
    @{ Name = 'VMware.VimAutomation.Core'; Required = $true }
)

if ($IncludeVcsaSsh) {
    $modules += @{ Name = 'Posh-SSH'; Required = $true }
}

foreach ($mod in $modules) {
    if (-not (Get-Module -ListAvailable -Name $mod.Name)) {
        Write-Host "Installing $($mod.Name)..." -ForegroundColor Cyan
        Install-Module -Name $mod.Name -Scope CurrentUser -Force -AllowClobber
    } else {
        Write-Host "$($mod.Name) already installed." -ForegroundColor Green
    }
}

Write-Host "`nOptional for full VMware appliance STIG coverage:" -ForegroundColor Yellow
Write-Host "  - Cinc Auditor / InSpec 6.8+ with train-vmware plugin"
Write-Host "  - VMware vSphere 8.0 STIG baseline from Broadcom STIG documentation"
Write-Host "  - DISA STIG zip: U_VMW_vSphere_8-0_Y25M04_STIG.zip"
