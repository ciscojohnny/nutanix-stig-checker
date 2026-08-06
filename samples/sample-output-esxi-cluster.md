# Sample Output — VMware ESXi Cluster STIG Audit

> **Illustrative example only.** Values, rule IDs, and counts are representative of a typical run against vCenter. Your results will reflect your environment.

---

## Command

```powershell
.\Invoke-StigAudit.ps1
```

---

## Wizard interaction

```
================================================================
  Nutanix STIG Checker — Cluster Wizard
================================================================

Step 1: Select cluster type

  1. Nutanix AHV
     STIGs: Acropolis Application Server, Acropolis GPOS

  2. VMware ESXi
     STIGs: ESXi, vCenter, VCSA appliance components (optional SSH)
     Discover ESXi cluster via Prism, then connect to vCenter

Cluster type (1-2): 2

  VMware ESXi Cluster
  ESXi host PowerCLI checks + vCenter/VCSA appliance checks

  STIG checklists included:
    1. VMware vSphere 8.0 ESXi
    2. VMware vSphere 8.0 vCenter
    3. VMware vSphere 8.0 vCenter Appliance Photon OS 4.0
    4. VMware vSphere 8.0 vCenter Appliance PostgreSQL
    5. VMware vSphere 8.0 vCenter Appliance VAMI
    6. VMware vSphere 8.0 vCenter Appliance Envoy
    7. VMware vSphere 8.0 vCenter Appliance ESX Agent Manager (EAM)
    8. VMware vSphere 8.0 vCenter Appliance Lookup Service
    9. VMware vSphere 8.0 vCenter Appliance Secure Token Service (STS)
    10. VMware vSphere 8.0 vCenter Appliance User Interface (UI)
    11. VMware vSphere 8.0 vCenter Appliance Perfcharts

Step 2: Nutanix management endpoint (discover ESXi cluster)
  1. Prism Central  (lists all registered clusters)
  2. Prism Element   (local cluster on a single PE instance)

Endpoint type (1-2): 1

Prism Central FQDN or IP: prism-central.example.mil
Port [9440]:

Prism Central credentials required for AHV checks.
User: svc-stig-audit@example.mil
Password for user svc-stig-audit@example.mil: ********

Connecting to Prism Central at prism-central.example.mil:9440...
Retrieving ESXi cluster inventory...

Clusters discovered on Prism Central:
  1. ESXi-Prod-3node (3 nodes | AOS 6.8.1.5 | ESXi)

Cluster (1-1): 1

Step 3: vCenter connection
  ESXi cluster selected in Prism: ESXi-Prod-3node
vCenter FQDN or IP: vcenter.example.mil

vCenter SSO credentials required for ESXi checks.
User: administrator@vsphere.local
Password for user administrator@vsphere.local: ********

Connecting to vCenter at vcenter.example.mil...
Matching cluster on vCenter...
  Matched vCenter cluster: ESXi-Prod-3node (3 hosts)

Step 4: VCSA appliance STIG checks (SSH)
  Photon OS, PostgreSQL, VAMI, Envoy, EAM, Lookup, STS, UI, Perfcharts
Include VCSA SSH appliance checks? [Y/n]: y

VCSA SSH (root) — Cancel to reuse vCenter credential
User: root
Password for user root: ********

  Selected cluster:
    Name:       ESXi-Prod-3node
    Type:       ESXi
    Nodes:      3
    Discovered: Prism Central (prism-central.example.mil:9440)
    Endpoint:   vCenter (vcenter.example.mil:443)
    UUID:       domain-c7

  VMware ESXi Cluster
  ESXi host PowerCLI checks + vCenter/VCSA appliance checks

  STIG checklists included:
    1. VMware vSphere 8.0 ESXi
    ... (11 total)

Run STIG audit on this cluster? [Y/n]: y
```

---

## Audit execution

```
Starting audit: ESXi-Prod-3node [ESXi, 3 nodes — Prism Central → vCenter]

  Workflow: VMware ESXi Cluster
  STIGs:
    - VMware vSphere 8.0 ESXi
    - VMware vSphere 8.0 vCenter
    - VMware vSphere 8.0 vCenter Appliance Photon OS 4.0
    - VMware vSphere 8.0 vCenter Appliance PostgreSQL
    - VMware vSphere 8.0 vCenter Appliance VAMI
    - VMware vSphere 8.0 vCenter Appliance Envoy
    - VMware vSphere 8.0 vCenter Appliance ESX Agent Manager (EAM)
    - VMware vSphere 8.0 vCenter Appliance Lookup Service
    - VMware vSphere 8.0 vCenter Appliance Secure Token Service (STS)
    - VMware vSphere 8.0 vCenter Appliance User Interface (UI)
    - VMware vSphere 8.0 vCenter Appliance Perfcharts

  [1/3] VMware vSphere 8.0 ESXi (hosts in ESXi-Prod-3node)...
  [2/3] VMware vSphere 8.0 vCenter...
  [3/3] VCSA appliance component STIGs (SSH)...
```

---

## Results summary

```
================================================================
  Results: ESXi-Prod-3node [ESXi, 3 nodes — Prism Central → vCenter]
================================================================

=== Cluster Summary ===
  Fail           19
  Manual         28
  Pass           44

=== Check Details ===

Cluster           Target                         RuleId     Severity Status  Title
-------           ------                         ------     -------- ------  -----
ESXi-Prod-3node   esxi-01.example.mil (ESXi...)  V-256001   medium   Pass    ESXi must configure NTP.
ESXi-Prod-3node   esxi-01.example.mil (ESXi...)  V-256002   medium   Pass    ESXi must configure a syslog server.
ESXi-Prod-3node   esxi-01.example.mil (ESXi...)  V-256003   medium   Pass    ESXi shell timeout must be configured.
ESXi-Prod-3node   esxi-01.example.mil (ESXi...)  V-256004   medium   Pass    ESXi SSH must be disabled/stopped unless required.
ESXi-Prod-3node   esxi-01.example.mil (ESXi...)  V-256005   high     Pass    ESXi must disable MOB (Managed Object Browser).
ESXi-Prod-3node   esxi-01.example.mil (ESXi...)  V-256010   medium   Fail    ESXi must enable lockdown mode (normal or strict).
ESXi-Prod-3node   esxi-01.example.mil (ESXi...)  V-256012   high     Fail    ESXi must disable the ESXi Shell unless required.
ESXi-Prod-3node   esxi-02.example.mil (ESXi...)  V-256001   medium   Pass    ESXi must configure NTP.
ESXi-Prod-3node   esxi-02.example.mil (ESXi...)  V-256010   medium   Fail    ESXi must enable lockdown mode (normal or strict).
ESXi-Prod-3node   esxi-03.example.mil (ESXi...)  V-256001   medium   Pass    ESXi must configure NTP.
ESXi-Prod-3node   esxi-03.example.mil (ESXi...)  V-256010   medium   Fail    ESXi must enable lockdown mode (normal or strict).
ESXi-Prod-3node   vcenter.example.mil            V-256101   medium   Pass    vCenter must require HTTPS for client connections.
ESXi-Prod-3node   vcenter.example.mil            V-256102   medium   Manual  vCenter must have SSO configured.
ESXi-Prod-3node   vcenter.example.mil            V-256103   medium   Manual  vCenter must configure NTP.
ESXi-Prod-3node   vcenter.example.mil            V-256104   medium   Manual  vCenter must forward logs to remote syslog.
ESXi-Prod-3node   vcenter.example.mil            V-256201   medium   Pass    Photon OS must use FIPS-approved SSH ciphers.
ESXi-Prod-3node   vcenter.example.mil            V-256202   medium   Manual  Photon OS must display DOD login banner.
ESXi-Prod-3node   vcenter.example.mil            V-256203   medium   Pass    Photon OS auditd must be enabled.
ESXi-Prod-3node   vcenter.example.mil            V-256301   medium   Manual  PostgreSQL must require password authentication.
ESXi-Prod-3node   vcenter.example.mil            INFO-INspec low      Manual  Remaining controls via VMware InSpec baseline
... (additional rows omitted)
```

---

## Per-STIG breakdown

```
=== VMware vSphere 8.0 ESXi ===
  Fail           9
  Manual         3
  Pass           33

=== VMware vSphere 8.0 vCenter ===
  Fail           0
  Manual         5
  Pass           1

=== VMware vSphere 8.0 vCenter Appliance Photon OS 4.0 ===
  Fail           1
  Manual         4
  Pass           2

=== VMware vSphere 8.0 vCenter Appliance PostgreSQL ===
  Manual         2
  Pass           0

=== VMware vSphere 8.0 vCenter Appliance VAMI ===
  Pass           1
  Manual         1

=== VMware vSphere 8.0 vCenter Appliance Envoy ===
  Manual         2

=== VMware vSphere 8.0 vCenter Appliance ESX Agent Manager (EAM) ===
  Manual         2

=== VMware vSphere 8.0 vCenter Appliance Lookup Service ===
  Manual         2

=== VMware vSphere 8.0 vCenter Appliance Secure Token Service (STS) ===
  Manual         2

=== VMware vSphere 8.0 vCenter Appliance User Interface (UI) ===
  Manual         2

=== VMware vSphere 8.0 vCenter Appliance Perfcharts ===
  Manual         2
```

---

## Session footer

```
Audit another cluster? [Y/n]: n

============================================================
wizard-session
=== wizard-session ===
  Fail           19
  Manual         28
  Pass           44

Exported 91 results to .\reports\stig-audit-wizard-session-20260806-150215.csv

Total checks: 91
  Pass:   44
  Fail:   19
  Manual: 28
```

---

## CSV export (first rows)

| Cluster | Target | StigName | RuleId | Severity | Status | Title |
|---------|--------|----------|--------|----------|--------|-------|
| ESXi-Prod-3node | esxi-01.example.mil (ESXi-Prod-3node) | VMware vSphere 8.0 ESXi | V-256010 | medium | Fail | ESXi must enable lockdown mode (normal or strict). |
| ESXi-Prod-3node | esxi-01.example.mil (ESXi-Prod-3node) | VMware vSphere 8.0 ESXi | V-256005 | high | Pass | ESXi must disable MOB (Managed Object Browser). |
| ESXi-Prod-3node | vcenter.example.mil | VMware vSphere 8.0 vCenter | V-256101 | medium | Pass | vCenter must require HTTPS for client connections. |
| ESXi-Prod-3node | vcenter.example.mil | VMware vSphere 8.0 vCenter Appliance Photon OS 4.0 | V-256203 | medium | Pass | Photon OS auditd must be enabled. |

---

## Notes

- **Prism discovery** identifies ESXi clusters via hypervisor type before prompting for vCenter credentials.
- **ESXi checks** run per host in the selected vCenter cluster (3 hosts × ~15 automated checks = ~45 ESXi rows in this example).
- **vCenter checks** are cluster-level (one vCenter per audit).
- **VCSA appliance checks** require SSH enabled on the appliance; many component STIGs are flagged **Manual** with guidance to run VMware's official InSpec baselines for full accreditation coverage.
- If VCSA SSH is declined at Step 3, appliance component checks are skipped and the summary shows fewer total checks.
