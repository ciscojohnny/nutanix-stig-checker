# Sample Output — Nutanix AHV Cluster STIG Audit

> **Illustrative example only.** Values, rule IDs, and counts are representative of a typical run against Prism Central. Your results will reflect your environment.

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

Cluster type (1-2): 1

  Nutanix AHV Cluster
  Prism Central GPOS native scan + Application Server API/manual checks

  STIG checklists included:
    1. Nutanix Acropolis Application Server
    2. Nutanix Acropolis GPOS

Step 2: Nutanix management endpoint
  1. Prism Central  (lists all registered clusters)
  2. Prism Element   (local cluster on a single PE instance)

Endpoint type (1-2): 1

Prism Central FQDN or IP: prism-central.example.mil
Port [9440]:

Prism Central credentials required for AHV checks.
User: svc-stig-audit@example.mil
Password for user svc-stig-audit@example.mil: ********

Connecting to Prism Central at prism-central.example.mil:9440...
Retrieving cluster inventory...

Clusters discovered on Prism Central:
  1. AHV-Mgmt-3node (3 nodes | AOS 6.8.1.5)
  2. AHV-Prod-4node-A (4 nodes | AOS 6.8.1.5)
  3. AHV-Prod-4node-B (4 nodes | AOS 6.8.1.5)

Cluster (1-3): 1

  Selected cluster:
    Name:       AHV-Mgmt-3node
    Type:       AHV
    Nodes:      3
    Endpoint:   Prism Central (prism-central.example.mil:9440)
    UUID:       a1b2c3d4-e5f6-7890-abcd-ef1234567890

  Nutanix AHV Cluster
  Prism Central GPOS native scan + Application Server API/manual checks

  STIG checklists included:
    1. Nutanix Acropolis Application Server
    2. Nutanix Acropolis GPOS

Run STIG audit on this cluster? [Y/n]: y
```

---

## Audit execution

```
Starting audit: AHV-Mgmt-3node [AHV, 3 nodes — Prism Central]

  Workflow: Nutanix AHV Cluster
  STIGs:
    - Nutanix Acropolis Application Server
    - Nutanix Acropolis GPOS

  [1/2] Nutanix Acropolis GPOS (native PC STIG scan)...
  [2/2] Nutanix Acropolis Application Server...
```

---

## Results summary

```
================================================================
  Results: AHV-Mgmt-3node [AHV, 3 nodes — Prism Central]
================================================================

=== Cluster Summary ===
  Fail           11
  Manual         22
  Pass           92

=== Check Details ===

Cluster          Target                                              RuleId    Severity Status  Title
-------          ------                                              ------    -------- ------  -----
AHV-Mgmt-3node   prism-central.example.mil / AHV-Mgmt-3node        V-279533  medium   Pass    Nutanix OS must implement DOD-approved encryption for SSH sessions.
AHV-Mgmt-3node   prism-central.example.mil / AHV-Mgmt-3node        V-279546  medium   Fail    Nutanix OS must enforce the limit of three consecutive invalid logon attempts...
AHV-Mgmt-3node   prism-central.example.mil / AHV-Mgmt-3node        V-279547  medium   Pass    Nutanix OS must display the Standard Mandatory DOD Notice and Consent Banner...
AHV-Mgmt-3node   prism-central.example.mil / AHV-Mgmt-3node        V-279550  medium   Pass    Nutanix OS must configure audit.rules for account access actions.
AHV-Mgmt-3node   prism-central.example.mil / AHV-Mgmt-3node        V-279575  medium   Fail    Nutanix OS must configure audit log permissions for 0600 or less.
AHV-Mgmt-3node   prism-central.example.mil / AHV-Mgmt-3node        V-279418  medium   Pass    Nutanix AOS must have TLS enabled.
AHV-Mgmt-3node   prism-central.example.mil / AHV-Mgmt-3node        V-279450  medium   Pass    Nutanix AOS must configure Network Time Protocol (NTP).
AHV-Mgmt-3node   prism-central.example.mil / AHV-Mgmt-3node        V-279433  high     Pass    Nutanix AOS must use an enterprise user management system.
AHV-Mgmt-3node   prism-central.example.mil / AHV-Mgmt-3node        V-279440  medium   Pass    Nutanix AOS must use encryption when using LDAP for authentication.
AHV-Mgmt-3node   prism-central.example.mil / AHV-Mgmt-3node        V-279434  high     Manual  Nutanix AOS must use MFA via CAC authentication.
AHV-Mgmt-3node   prism-central.example.mil / AHV-Mgmt-3node        V-279422  medium   Manual  Nutanix AOS must display DOD Notice and Consent Banner.
AHV-Mgmt-3node   prism-central.example.mil / AHV-Mgmt-3node        V-279424  medium   Manual  Nutanix AOS must off-load log records onto a different system.
... (additional rows omitted)
```

---

## Per-STIG breakdown

```
=== Nutanix Acropolis GPOS ===
  Fail           7
  Manual         8
  Pass           81

=== Nutanix Acropolis Application Server ===
  Fail           4
  Manual         14
  Pass           11
```

---

## Session footer

```
Audit another cluster? [Y/n]: n

============================================================
wizard-session
=== wizard-session ===
  Fail           11
  Manual         22
  Pass           92

Exported 125 results to .\reports\stig-audit-wizard-session-20260806-144530.csv

Total checks: 125
  Pass:   92
  Fail:   11
  Manual: 22
```

---

## CSV export (first rows)

| Cluster | Target | StigName | RuleId | Severity | Status | Title |
|---------|--------|----------|--------|----------|--------|-------|
| AHV-Mgmt-3node | prism-central.example.mil / AHV-Mgmt-3node | Nutanix Acropolis GPOS | V-279533 | medium | Pass | Nutanix OS must implement DOD-approved encryption for SSH sessions. |
| AHV-Mgmt-3node | prism-central.example.mil / AHV-Mgmt-3node | Nutanix Acropolis GPOS | V-279546 | medium | Fail | Nutanix OS must enforce the limit of three consecutive invalid logon attempts... |
| AHV-Mgmt-3node | prism-central.example.mil / AHV-Mgmt-3node | Nutanix Acropolis Application Server | V-279418 | medium | Pass | Nutanix AOS must have TLS enabled. |

---

## Notes

- **GPOS checks** come from the Prism Central Security STIG API (native scan results per control).
- **Application Server checks** combine automated Prism API validation (TLS, NTP, LDAP/AD) with manual placeholders for controls that require policy review (MFA, CAC, DOD banner, etc.).
- Connecting via **Prism Element** instead of Prism Central follows the same flow; inventory typically shows the single local cluster on that PE instance.
