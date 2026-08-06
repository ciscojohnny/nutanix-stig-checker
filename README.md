# Nutanix STIG Checker

PowerShell framework to audit Nutanix AHV and VMware vSphere 8.0 environments against DISA STIG checklists across multiple identical sites.

## Prerequisites

Install on the machine running the audit (Windows or PowerShell 7+ on macOS/Linux):

```powershell
Install-Module VMware.VimAutomation.Core -Scope CurrentUser
Install-Module Posh-SSH -Scope CurrentUser   # optional, for VCSA SSH checks
```

**Nutanix:** Prism Central 2024.3+ with Security Dashboard STIG scan enabled.

**VMware:** vCenter 8.x managing ESXi 8.x hosts. For full vCenter appliance STIG coverage, also install [VMware vSphere 8.0 STIG InSpec baselines](https://techdocs.broadcom.com/us/en/vmware-cis/vcf/stig/).

**STIG checklists (recommended):** Download and extract the official DISA zip:

- [VMware vSphere 8.0 STIG](https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_VMW_vSphere_8-0_Y25M04_STIG.zip)
- Nutanix Acropolis STIGs from [stigviewer.com/stigs](https://www.stigviewer.com/stigs) or DISA when published

Point `stigXmlPath` in config to the extracted XML folder to populate all remaining rules as Manual with official titles.

## Setup

1. Copy `config/sites.example.json` to `config/sites.json`
2. Update FQDNs for each site's Prism Central, Nutanix clusters, vCenter, and ESXi cluster name
3. Set `stigXmlPath` to your extracted DISA STIG XML directory

## Usage

```powershell
cd /Users/johmisti/Projects/nutanix-vmware-stig-audit

$ntx = Get-Credential -Message 'Prism Central service account'
$vmw = Get-Credential -Message 'vCenter SSO (administrator@vsphere.local)'

.\Invoke-MultiSiteStigAudit.ps1 `
    -ConfigPath .\config\sites.json `
    -NutanixCredential $ntx `
    -VmwareCredential $vmw `
    -SkipCertificateCheck `
    -IncludeVcsaSsh `
    -ExportFormat All
```

## Output

The script prints:

- Per-site summary (Pass / Fail / Manual / Error counts)
- Per-STIG summary across all sites
- Detailed `Format-Table` with RuleId, Severity, Status, Title, Details
- CSV and JSON exports under `./reports/`

## STIG Coverage

| Checklist | Method |
|-----------|--------|
| Nutanix Acropolis GPOS | Prism Central `/api/security/v4.1/report/stigs` native scan |
| Nutanix Acropolis Application Server | Prism API checks + manual placeholders |
| VMware vSphere 8.0 ESXi | PowerCLI advanced settings & services (per host) |
| VMware vSphere 8.0 vCenter | PowerCLI + manual SSO/logging checks |
| VCSA components (Photon, PostgreSQL, VAMI, Envoy, EAM, Lookup, STS, UI, Perfcharts) | SSH spot-checks + InSpec guidance |

For accreditation-grade vCenter appliance results, run the official VMware InSpec runner in parallel:

```powershell
./VMware_vSphere_8.0_STIG_ESXi_InSpec_Runner.ps1 -vcenter vcenter.example.mil -reportPath ./reports/inspec
```

## Site Layout (default config)

Each of 3 sites contains:

- 1x 3-node AHV cluster
- 2x 4-node AHV clusters
- 1x 3-node ESXi cluster (via vCenter)
