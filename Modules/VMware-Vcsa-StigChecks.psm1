#Requires -Version 7.0
Set-StrictMode -Version Latest

function Invoke-VcsaSshCommand {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$VcsaFqdn,
        [Parameter(Mandatory)][pscredential]$Credential,
        [Parameter(Mandatory)][string]$Command,
        [int]$Port = 22
    )

    if (-not (Get-Module -ListAvailable Posh-SSH)) {
        throw 'Posh-SSH module required for VCSA appliance checks. Install: Install-Module Posh-SSH -Scope CurrentUser'
    }
    Import-Module Posh-SSH -ErrorAction Stop | Out-Null

    $session = New-SSHSession -ComputerName $VcsaFqdn -Credential $Credential -Port $Port -AcceptKey -ErrorAction Stop
    try {
        $result = Invoke-SSHCommand -SessionId $session.SessionId -Command $Command -TimeOut 60
        if ($result.ExitStatus -ne 0 -and -not $result.Output) {
            throw "SSH command failed (exit $($result.ExitStatus)): $($result.Error)"
        }
        return ($result.Output -join "`n").Trim()
    } finally {
        Remove-SSHSession -SessionId $session.SessionId | Out-Null
    }
}

function Invoke-VmwareVcsaApplianceStigAudit {
    <#
    .SYNOPSIS
        SSH-based checks for vCenter Appliance component STIGs (Photon OS, PostgreSQL, services).
        Requires SSH enabled on VCSA and root or appropriate admin account.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SiteName,
        [Parameter(Mandatory)][string]$VcsaFqdn,
        [Parameter(Mandatory)][pscredential]$Credential
    )

    $results = [System.Collections.Generic.List[object]]::new()
    $target = $VcsaFqdn

    $componentChecks = @(
        @{
            StigName = 'VMware vSphere 8.0 vCenter Appliance Photon OS 4.0'
            RuleId = 'V-256201'; Title = 'Photon OS must use FIPS-approved SSH ciphers.'
            Command = "grep -Ei '^Ciphers|^MACs' /etc/ssh/sshd_config 2>/dev/null | head -5"
            Validate = {
                param($out)
                if ($out -match 'aes256-gcm|aes128-gcm') { return @{ Status = 'Pass'; Actual = $out } }
                if (-not $out) { return @{ Status = 'Manual'; Details = 'Could not read sshd_config' } }
                @{ Status = 'Fail'; Actual = $out }
            }
        },
        @{
            StigName = 'VMware vSphere 8.0 vCenter Appliance Photon OS 4.0'
            RuleId = 'V-256202'; Title = 'Photon OS must display DOD login banner.'
            Command = "grep -i banner /etc/ssh/sshd_config 2>/dev/null; test -f /etc/issue && head -3 /etc/issue"
            Validate = {
                param($out)
                if ($out -match 'banner|You are accessing') { return @{ Status = 'Pass'; Actual = $out } }
                @{ Status = 'Manual'; Details = 'Verify DOD banner configured for SSH/console' }
            }
        },
        @{
            StigName = 'VMware vSphere 8.0 vCenter Appliance Photon OS 4.0'
            RuleId = 'V-256203'; Title = 'Photon OS auditd must be enabled.'
            Command = 'systemctl is-active auditd 2>/dev/null || service auditd status 2>/dev/null | head -1'
            Validate = {
                param($out)
                if ($out -match 'active|running') { return @{ Status = 'Pass'; Actual = $out } }
                @{ Status = 'Fail'; Actual = $out }
            }
        },
        @{
            StigName = 'VMware vSphere 8.0 vCenter Appliance PostgreSQL'
            RuleId = 'V-256301'; Title = 'PostgreSQL must require password authentication.'
            Command = "grep -E '^password_encryption|^ssl' /var/vmware/vpostgres/current/pgdata/postgresql.conf 2>/dev/null | head -5"
            Validate = {
                param($out)
                if ($out -match 'scram-sha-256|md5|on') { return @{ Status = 'Pass'; Actual = $out } }
                @{ Status = 'Manual'; Details = 'Verify pg_hba.conf and postgresql.conf authentication settings' }
            }
        },
        @{
            StigName = 'VMware vSphere 8.0 vCenter Appliance VAMI'
            RuleId = 'V-256401'; Title = 'VAMI must use TLS.'
            Command = 'curl -skI https://localhost:5480 2>/dev/null | head -3'
            Validate = {
                param($out)
                if ($out -match 'HTTP/') { return @{ Status = 'Pass'; Actual = $out } }
                @{ Status = 'Manual'; Details = 'Verify VAMI TLS via browser or API' }
            }
        },
        @{
            StigName = 'VMware vSphere 8.0 vCenter Appliance Envoy'
            RuleId = 'V-256501'; Title = 'Envoy proxy must enforce TLS.'
            Command = 'vmon-cli --status envoy 2>/dev/null | head -3'
            Validate = {
                param($out)
                if ($out -match 'running|RunState') { return @{ Status = 'Manual'; Details = 'Envoy running - verify TLS policy via InSpec baseline' } }
                @{ Status = 'Manual'; Details = 'Verify Envoy configuration with VMware STIG InSpec profile' }
            }
        },
        @{
            StigName = 'VMware vSphere 8.0 vCenter Appliance ESX Agent Manager (EAM)'
            RuleId = 'V-256601'; Title = 'EAM service must be running securely.'
            Command = 'vmon-cli --status eam 2>/dev/null | head -3'
            Validate = {
                param($out)
                @{ Status = 'Manual'; Details = 'Use VMware vSphere 8.0 EAM InSpec profile for full validation' ; Actual = $out }
            }
        },
        @{
            StigName = 'VMware vSphere 8.0 vCenter Appliance Lookup Service'
            RuleId = 'V-256701'; Title = 'Lookup Service must use secure TLS.'
            Command = 'vmon-cli --status lookupsvc 2>/dev/null | head -3'
            Validate = {
                param($out)
                @{ Status = 'Manual'; Details = 'Use Lookup Service InSpec profile'; Actual = $out }
            }
        },
        @{
            StigName = 'VMware vSphere 8.0 vCenter Appliance Secure Token Service (STS)'
            RuleId = 'V-256801'; Title = 'STS must enforce token policy.'
            Command = 'vmon-cli --status sts 2>/dev/null | head -3'
            Validate = {
                param($out)
                @{ Status = 'Manual'; Details = 'Use STS InSpec profile with SSO admin module'; Actual = $out }
            }
        },
        @{
            StigName = 'VMware vSphere 8.0 vCenter Appliance User Interface (UI)'
            RuleId = 'V-256901'; Title = 'UI service must use secure session settings.'
            Command = 'vmon-cli --status vsphere-ui 2>/dev/null | head -3'
            Validate = {
                param($out)
                @{ Status = 'Manual'; Details = 'Use UI InSpec profile'; Actual = $out }
            }
        },
        @{
            StigName = 'VMware vSphere 8.0 vCenter Appliance Perfcharts'
            RuleId = 'V-257001'; Title = 'Perfcharts service security configuration.'
            Command = 'vmon-cli --status perfcharts 2>/dev/null | head -3'
            Validate = {
                param($out)
                @{ Status = 'Manual'; Details = 'Use Perfcharts InSpec profile'; Actual = $out }
            }
        }
    )

    foreach ($check in $componentChecks) {
        try {
            $output = Invoke-VcsaSshCommand -VcsaFqdn $VcsaFqdn -Credential $Credential -Command $check.Command
            $outcome = & $check.Validate $output
        } catch {
            $outcome = @{ Status = 'Error'; Details = $_.Exception.Message; Actual = '' }
        }

        $results.Add((New-StigResult -Site $SiteName -Target $target -StigName $check.StigName `
            -RuleId $check.RuleId -Severity 'medium' -Title $check.Title `
            -Status $outcome.Status -Details ($outcome.Details ?? '') -Actual ($outcome.Actual ?? '')))
    }

    # Placeholder entries for remaining appliance STIG controls (require InSpec/Cinc Auditor)
    $inspecComponents = @(
        'VMware vSphere 8.0 vCenter Appliance Photon OS 4.0',
        'VMware vSphere 8.0 vCenter Appliance PostgreSQL',
        'VMware vSphere 8.0 vCenter Appliance VAMI',
        'VMware vSphere 8.0 vCenter Appliance Envoy',
        'VMware vSphere 8.0 vCenter Appliance ESX Agent Manager (EAM)',
        'VMware vSphere 8.0 vCenter Appliance Lookup Service',
        'VMware vSphere 8.0 vCenter Appliance Secure Token Service (STS)',
        'VMware vSphere 8.0 vCenter Appliance User Interface (UI)',
        'VMware vSphere 8.0 vCenter Appliance Perfcharts'
    )

    foreach ($comp in $inspecComponents) {
        $results.Add((New-StigResult -Site $SiteName -Target $target -StigName $comp `
            -RuleId 'INFO-INspec' -Severity 'low' -Title 'Remaining controls via VMware InSpec baseline' `
            -Status 'Manual' -Details @"
For complete $comp coverage, run the official VMware vSphere 8.0 STIG InSpec profile:
  cinc-auditor exec /path/to/vmware-vsphere-8.0-stig-baseline -t ssh://$VcsaFqdn --sudo
See: https://techdocs.broadcom.com/us/en/vmware-cis/vcf/stig/
"@))
    }

    return $results
}

function Invoke-VmwareInspecRunner {
    <#
    .SYNOPSIS
        Optional wrapper to invoke official VMware InSpec runner if installed.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$VCenterFqdn,
        [Parameter(Mandatory)][string]$ReportPath,
        [string]$InspecBaselinePath = '/usr/share/stigs/vsphere/8.0/v2r4-stig/vsphere/inspec/vmware-vsphere-8.0-stig-baseline',
        [string]$RunnerScript = '/usr/share/stigs/vsphere/8.0/v2r4-stig/vsphere/powercli/VMware_vSphere_8.0_STIG_ESXi_InSpec_Runner.ps1'
    )

    if (-not (Test-Path $RunnerScript)) {
        Write-Warning "InSpec runner not found at $RunnerScript. Install VMware STIG tooling package."
        return @()
    }

    if (-not (Test-Path $ReportPath)) {
        New-Item -ItemType Directory -Path $ReportPath -Force | Out-Null
    }

    & $RunnerScript -vcenter $VCenterFqdn -reportPath $ReportPath -inspecPath $InspecBaselinePath
}

Export-ModuleMember -Function @(
    'Invoke-VcsaSshCommand',
    'Invoke-VmwareVcsaApplianceStigAudit',
    'Invoke-VmwareInspecRunner'
)
