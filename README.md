# Nutanix STIG Checker

PowerShell tool to audit **one cluster at a time** against DISA STIG checklists. Clusters are discovered live from Prism Central, Prism Element, or vCenter — nothing is pre-defined in config.

| Workflow | Connect to | STIG checklists |
|----------|------------|-----------------|
| **AHV** | Prism Central or Prism Element | Acropolis Application Server, Acropolis GPOS |
| **ESXi** | Prism Central or Prism Element, then vCenter | ESXi, vCenter, optional VCSA appliance components |

## Setup

Optional settings only (`config/clusters.json`):

```powershell
Copy-Item .\config\clusters.example.json .\config\clusters.json
```

Configure `outputPath`, `stigXmlPath`, and `skipCertificateCheck` if needed. Cluster names and endpoints are entered at runtime.

For lab or self-signed Prism certificates, either set `"skipCertificateCheck": true` in `config/clusters.json` or pass `-SkipCertificateCheck` on the command line.

## Usage

### Interactive wizard (default)

```powershell
.\Invoke-StigAudit.ps1
```

**AHV flow:**
1. Select **Nutanix AHV**
2. Choose **Prism Central** or **Prism Element**
3. Enter FQDN/IP and port (default 9440)
4. Enter credentials
5. Pick a cluster from live inventory
6. Run audit

**ESXi flow:**
1. Select **VMware ESXi**
2. Choose **Prism Central** or **Prism Element**
3. Enter FQDN/IP, port, and credentials
4. Pick an **ESXi cluster** from Prism inventory (AHV clusters are filtered out)
5. Enter **vCenter** FQDN/IP and credentials (cluster name matched on vCenter)
6. Optional VCSA SSH checks
7. Run audit

### Direct mode (skip wizard)

```powershell
# AHV via Prism Central
.\Invoke-StigAudit.ps1 -Workflow AHV -PrismFqdn prism.example.mil -PrismEndpoint PC `
    -ClusterName prod-ahv -NutanixCredential (Get-Credential)

# AHV via Prism Element
.\Invoke-StigAudit.ps1 -Workflow AHV -PrismFqdn pe-node.example.mil -PrismEndpoint PE `
    -ClusterName local-cluster -NutanixCredential (Get-Credential)

# ESXi via vCenter
.\Invoke-StigAudit.ps1 -Workflow ESXi -VCenterFqdn vcenter.example.mil `
    -ClusterName ESXi-Prod -VmwareCredential (Get-Credential) -IncludeVcsaSsh
```

## Output

Pass/fail summary and detail tables per cluster, exported to `./reports/` as CSV.

## TLS / certificate errors (Prism)

Prism Central and Prism Element often use enterprise or self-signed certificates. If you see errors like `PartialChain` or `RemoteCertificateNameMismatch`:

```powershell
# One-time for this run
.\Invoke-StigAudit.ps1 -SkipCertificateCheck

# Or persist in config
Copy-Item .\config\clusters.example.json .\config\clusters.json
# Set "skipCertificateCheck": true in clusters.json
```

Use the **exact FQDN** that matches the certificate SAN/CN when possible (name mismatch errors). Certificate skipping is intended for lab and assessment environments only.
