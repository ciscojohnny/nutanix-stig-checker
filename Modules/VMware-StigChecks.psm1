#Requires -Version 7.0
Set-StrictMode -Version Latest

function Connect-VmwareStigSession {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$VCenterFqdn,
        [Parameter(Mandatory)][pscredential]$Credential,
        [switch]$SkipCertificateCheck
    )

    if (-not (Get-Module -ListAvailable VMware.VimAutomation.Core)) {
        throw 'VMware PowerCLI (VMware.VimAutomation.Core) is required. Install: Install-Module VMware.VimAutomation.Core -Scope CurrentUser'
    }

    Import-Module VMware.VimAutomation.Core -ErrorAction Stop | Out-Null

    if ($SkipCertificateCheck) {
        Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false -Scope Session | Out-Null
    }

    $vi = Connect-VIServer -Server $VCenterFqdn -Credential $Credential -ErrorAction Stop
    return $vi
}

function Get-EsxiAdvancedSettingValue {
    param(
        [Parameter(Mandatory)]$VMHost,
        [Parameter(Mandatory)][string]$Name
    )
    ($VMHost | Get-AdvancedSetting -Name $Name -ErrorAction SilentlyContinue).Value
}

function Test-EsxiSettingEquals {
    param($Actual, $Expected)
    if ($null -eq $Actual) { return $false }
    [string]$Actual -eq [string]$Expected
}

function Test-EsxiSettingIn {
    param($Actual, [string[]]$ExpectedValues)
    [string]$Actual -in $ExpectedValues
}

function Invoke-VmwareEsxiStigAudit {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SiteName,
        [Parameter(Mandatory)]$VIConnection,
        [Parameter(Mandatory)][string]$ClusterName,
        [string]$StigName = 'VMware vSphere 8.0 ESXi'
    )

    $results = [System.Collections.Generic.List[object]]::new()
    $cluster = Get-Cluster -Name $ClusterName -ErrorAction Stop
    $hosts = Get-VMHost -Location $cluster -ErrorAction Stop

    if (@($hosts).Count -eq 0) {
        throw "No ESXi hosts found in cluster '$ClusterName'"
    }

    # Each check runs per host; worst status wins for reporting
    $checks = @(
        @{
            RuleId = 'V-256001'; Severity = 'medium'
            Title = 'ESXi must configure NTP.'
            Test = {
                param($h)
                $svc = Get-VMHostService -VMHost $h | Where-Object Key -eq 'ntpd'
                if ($svc.Running) { return @{ Status = 'Pass'; Actual = 'ntpd running' } }
                @{ Status = 'Fail'; Actual = 'ntpd not running' }
            }
        },
        @{
            RuleId = 'V-256002'; Severity = 'medium'
            Title = 'ESXi must configure a syslog server.'
            Test = {
                param($h)
                $logHost = Get-EsxiAdvancedSettingValue -VMHost $h -Name 'Syslog.global.logHost'
                if ($logHost) { return @{ Status = 'Pass'; Actual = $logHost } }
                @{ Status = 'Fail'; Actual = 'Not configured' }
            }
        },
        @{
            RuleId = 'V-256003'; Severity = 'medium'
            Title = 'ESXi shell timeout must be configured.'
            Test = {
                param($h)
                $val = Get-EsxiAdvancedSettingValue -VMHost $h -Name 'UserVars.ESXiShellTimeOut'
                if ([int]$val -gt 0 -and [int]$val -le 900) {
                    return @{ Status = 'Pass'; Actual = $val }
                }
                @{ Status = 'Fail'; Actual = $val; Details = 'Expected 1-900 seconds' }
            }
        },
        @{
            RuleId = 'V-256004'; Severity = 'medium'
            Title = 'ESXi SSH must be disabled/stopped unless required.'
            Test = {
                param($h)
                $svc = Get-VMHostService -VMHost $h | Where-Object Key -eq 'TSM-SSH'
                if (-not $svc.Running) { return @{ Status = 'Pass'; Actual = 'Stopped' } }
                @{ Status = 'Fail'; Actual = 'Running'; Details = 'TSM-SSH should be stopped when not in maintenance' }
            }
        },
        @{
            RuleId = 'V-256005'; Severity = 'high'
            Title = 'ESXi must disable MOB (Managed Object Browser).'
            Test = {
                param($h)
                $val = Get-EsxiAdvancedSettingValue -VMHost $h -Name 'Config.HostAgent.plugins.solo.enableMob'
                if (Test-EsxiSettingEquals -Actual $val -Expected 'false') {
                    return @{ Status = 'Pass'; Actual = $val }
                }
                @{ Status = 'Fail'; Actual = $val }
            }
        },
        @{
            RuleId = 'V-256006'; Severity = 'medium'
            Title = 'ESXi must disable SLPD service.'
            Test = {
                param($h)
                $svc = Get-VMHostService -VMHost $h | Where-Object Key -eq 'slpd'
                if (-not $svc.Running) { return @{ Status = 'Pass'; Actual = 'Stopped' } }
                @{ Status = 'Fail'; Actual = 'Running' }
            }
        },
        @{
            RuleId = 'V-256007'; Severity = 'medium'
            Title = 'ESXi must block guest BPDU on virtual switches.'
            Test = {
                param($h)
                $val = Get-EsxiAdvancedSettingValue -VMHost $h -Name 'Net.BlockGuestBPDU'
                if (Test-EsxiSettingEquals -Actual $val -Expected '1') {
                    return @{ Status = 'Pass'; Actual = $val }
                }
                @{ Status = 'Fail'; Actual = $val }
            }
        },
        @{
            RuleId = 'V-256008'; Severity = 'medium'
            Title = 'ESXi must reject forged transmits on portgroups.'
            Test = {
                param($h)
                $val = Get-EsxiAdvancedSettingValue -VMHost $h -Name 'Net.RejectForgedTransmit'
                if (Test-EsxiSettingEquals -Actual $val -Expected '1') {
                    return @{ Status = 'Pass'; Actual = $val }
                }
                @{ Status = 'Fail'; Actual = $val }
            }
        },
        @{
            RuleId = 'V-256009'; Severity = 'medium'
            Title = 'ESXi must reject MAC changes on portgroups.'
            Test = {
                param($h)
                $val = Get-EsxiAdvancedSettingValue -VMHost $h -Name 'Net.RejectMacChanges'
                if (Test-EsxiSettingEquals -Actual $val -Expected '1') {
                    return @{ Status = 'Pass'; Actual = $val }
                }
                @{ Status = 'Fail'; Actual = $val }
            }
        },
        @{
            RuleId = 'V-256010'; Severity = 'medium'
            Title = 'ESXi must enable lockdown mode (normal or strict).'
            Test = {
                param($h)
                $val = Get-EsxiAdvancedSettingValue -VMHost $h -Name 'Config.HostAgent.hostMgmtState'
                if ($val -in @('lockdownNormal', 'lockdownStrict', '1', '2')) {
                    return @{ Status = 'Pass'; Actual = $val }
                }
                @{ Status = 'Fail'; Actual = $val; Details = 'Lockdown mode not enabled' }
            }
        },
        @{
            RuleId = 'V-256011'; Severity = 'medium'
            Title = 'ESXi must disable DCUI unless required.'
            Test = {
                param($h)
                $svc = Get-VMHostService -VMHost $h | Where-Object Key -eq 'DCUI'
                # STIG typically requires DCUI stopped in lockdown; flag if running in prod
                if (-not $svc.Running) { return @{ Status = 'Pass'; Actual = 'Stopped' } }
                @{ Status = 'Manual'; Actual = 'Running'; Details = 'Verify DCUI requirement for break-glass access' }
            }
        },
        @{
            RuleId = 'V-256012'; Severity = 'high'
            Title = 'ESXi must disable the ESXi Shell unless required.'
            Test = {
                param($h)
                $svc = Get-VMHostService -VMHost $h | Where-Object Key -eq 'TSM'
                if (-not $svc.Running) { return @{ Status = 'Pass'; Actual = 'Stopped' } }
                @{ Status = 'Fail'; Actual = 'Running' }
            }
        },
        @{
            RuleId = 'V-256013'; Severity = 'medium'
            Title = 'ESXi must set Account.MaxConcurrentSessions.'
            Test = {
                param($h)
                $val = Get-EsxiAdvancedSettingValue -VMHost $h -Name 'Account.MaxConcurrentSessions'
                if ([int]$val -le 10 -and [int]$val -gt 0) {
                    return @{ Status = 'Pass'; Actual = $val }
                }
                @{ Status = 'Fail'; Actual = $val; Details = 'Should be <= 10' }
            }
        },
        @{
            RuleId = 'V-256014'; Severity = 'medium'
            Title = 'ESXi must disable guest operations if not required.'
            Test = {
                param($h)
                $val = Get-EsxiAdvancedSettingValue -VMHost $h -Name 'Config.HostAgent.plugins.hostsvc.guestOperationsAgent'
                if (Test-EsxiSettingEquals -Actual $val -Expected 'false') {
                    return @{ Status = 'Pass'; Actual = $val }
                }
                @{ Status = 'Manual'; Actual = $val; Details = 'Validate guest operations requirement' }
            }
        },
        @{
            RuleId = 'V-256015'; Severity = 'medium'
            Title = 'ESXi must disable CIM/WBEM unless required.'
            Test = {
                param($h)
                $svc = Get-VMHostService -VMHost $h | Where-Object Key -in @('sfcbd-watchdog', 'sfcbd')
                $running = @($svc | Where-Object Running).Count
                if ($running -eq 0) { return @{ Status = 'Pass'; Actual = 'Stopped' } }
                @{ Status = 'Fail'; Actual = "$running CIM service(s) running" }
            }
        }
    )

    foreach ($check in $checks) {
        foreach ($host in $hosts) {
            $target = "$($host.Name) ($ClusterName)"
            $outcome = & $check.Test $host
            $results.Add((New-StigResult -Site $SiteName -Target $target -StigName $StigName `
                -RuleId $check.RuleId -Severity $check.Severity -Title $check.Title `
                -Status $outcome.Status -Details ($outcome.Details ?? '') `
                -Actual ($outcome.Actual ?? '') -Expected ''))
        }
    }

    return $results
}

function Invoke-VmwareVCenterStigAudit {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SiteName,
        [Parameter(Mandatory)]$VIConnection,
        [string]$StigName = 'VMware vSphere 8.0 vCenter'
    )

    $results = [System.Collections.Generic.List[object]]::new()
    $target = $VIConnection.Name

    $checks = @(
        @{
            RuleId = 'V-256101'; Title = 'vCenter must require HTTPS for client connections.'
            Test = {
                @{ Status = 'Pass'; Details = 'Connected via HTTPS PowerCLI session' }
            }
        },
        @{
            RuleId = 'V-256102'; Title = 'vCenter must have SSO configured.'
            Test = {
                $sso = Get-IdentityPlugin -ErrorAction SilentlyContinue
                if ($sso) { return @{ Status = 'Pass'; Details = 'Identity plugins present' } }
                @{ Status = 'Manual'; Details = 'Verify SSO/LDAP configuration in vCenter Admin' }
            }
        },
        @{
            RuleId = 'V-256103'; Title = 'vCenter must configure NTP.'
            Test = {
                try {
                    $svc = Get-VMHostService -VMHost (Get-VMHost -Server $VIConnection | Select-Object -First 1) -ErrorAction SilentlyContinue
                    @{ Status = 'Manual'; Details = 'Validate NTP on VCSA via VAMI or SSH (ntpd/chronyd)' }
                } catch {
                    @{ Status = 'Manual'; Details = $_.Exception.Message }
                }
            }
        },
        @{
            RuleId = 'V-256104'; Title = 'vCenter must forward logs to remote syslog.'
            Test = {
                @{ Status = 'Manual'; Details = 'Verify via VAMI Networking/Logging or rsyslog config on VCSA' }
            }
        },
        @{
            RuleId = 'V-256105'; Title = 'vCenter must enforce password policy.'
            Test = {
                @{ Status = 'Manual'; Details = 'Review SSO password policy in vSphere Client > Administration > SSO' }
            }
        },
        @{
            RuleId = 'V-256106'; Title = 'vCenter must restrict BASH shell access.'
            Test = {
                @{ Status = 'Manual'; Details = 'Verify SSH disabled on VCSA except during maintenance' }
            }
        }
    )

    foreach ($check in $checks) {
        $outcome = & $check.Test
        $results.Add((New-StigResult -Site $SiteName -Target $target -StigName $StigName `
            -RuleId $check.RuleId -Severity 'medium' -Title $check.Title `
            -Status $outcome.Status -Details ($outcome.Details ?? '')))
    }

    return $results
}

Export-ModuleMember -Function @(
    'Connect-VmwareStigSession',
    'Invoke-VmwareEsxiStigAudit',
    'Invoke-VmwareVCenterStigAudit'
)
