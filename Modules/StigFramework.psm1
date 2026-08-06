#Requires -Version 7.0
Set-StrictMode -Version Latest

function New-StigResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Site,
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][string]$StigName,
        [Parameter(Mandatory)][string]$RuleId,
        [Parameter()][string]$Severity = 'medium',
        [Parameter(Mandatory)][string]$Title,
        [ValidateSet('Pass', 'Fail', 'NotApplicable', 'Manual', 'Error', 'Skipped')]
        [Parameter(Mandatory)][string]$Status,
        [Parameter()][string]$Details = '',
        [Parameter()][string]$Expected = '',
        [Parameter()][string]$Actual = ''
    )

    [PSCustomObject]@{
        Site     = $Site
        Target   = $Target
        StigName = $StigName
        RuleId   = $RuleId
        Severity = $Severity
        Title    = $Title
        Status   = $Status
        Details  = $Details
        Expected = $Expected
        Actual   = $Actual
        CheckedAt = (Get-Date).ToString('o')
    }
}

function Import-StigXccdfCatalog {
    <#
    .SYNOPSIS
        Loads STIG rules from DISA XCCDF XML files (extracted from official STIG zip packages).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [string[]]$StigNameFilter
    )

    $files = if (Test-Path -LiteralPath $Path -PathType Leaf) {
        Get-Item -LiteralPath $Path
    } else {
        Get-ChildItem -LiteralPath $Path -Filter '*.xml' -Recurse -File
    }

    $catalog = @{}
    foreach ($file in $files) {
        [xml]$xml = Get-Content -LiteralPath $file.FullName -Raw
        $benchmark = $xml.Benchmark
        if (-not $benchmark) { continue }

        $stigTitle = $benchmark.title.'#text'
        if (-not $stigTitle) { $stigTitle = $benchmark.title }
        if (-not $stigTitle) { $stigTitle = $file.BaseName }

        if ($StigNameFilter -and ($StigNameFilter | Where-Object { $stigTitle -like "*$_*" }).Count -eq 0) {
            continue
        }

        $rules = @()
        $ruleNodes = $benchmark.SelectNodes('//Rule[@id]')
        foreach ($rule in $ruleNodes) {
            $vid = $rule.id
            if ($vid -notmatch '^V-\d+$') {
                $vidNode = $rule.SelectSingleNode('.//ident[@system="http://cyber.mil/cci"]')
                if ($vidNode) { $vid = $vidNode.'#text' }
            }

            $title = $rule.title.'#text'
            if (-not $title) { $title = $rule.title }
            $severity = ($rule.severity | ForEach-Object { $_.ToString().ToLower() }) ?? 'medium'
            $description = ($rule.description | Out-String).Trim()
            $checkText = ($rule.SelectNodes('.//check-content') | ForEach-Object { $_.InnerText }) -join "`n"

            $rules += [PSCustomObject]@{
                RuleId      = $vid
                Title       = $title
                Severity    = $severity
                Description = $description
                CheckContent = $checkText
                SourceFile  = $file.Name
            }
        }

        if ($rules.Count -gt 0) {
            $catalog[$stigTitle] = $rules
        }
    }

    return $catalog
}

function Get-DefaultStigCatalog {
    <#
    .SYNOPSIS
        Embedded STIG metadata when XCCDF files are not yet downloaded from DISA.
        Rule IDs align with stigviewer.com checklists (Aug 2026).
    #>
    [CmdletBinding()]
    param()

    @{
        'Nutanix Acropolis Application Server' = @(
            'V-279415','V-279416','V-279418','V-279421','V-279422','V-279423','V-279424',
            'V-279425','V-279426','V-279427','V-279430','V-279431','V-279433','V-279434',
            'V-279435','V-279438','V-279439','V-279440','V-279441','V-279442','V-279443',
            'V-279444','V-279445','V-279446','V-279447','V-279448','V-279450','V-279451',
            'V-279464','V-279486','V-279526'
        )
        'Nutanix Acropolis GPOS' = @(
            'V-279527','V-279529','V-279530','V-279531','V-279532','V-279533','V-279534',
            'V-279535','V-279536','V-279537','V-279538','V-279539','V-279540','V-279541',
            'V-279542','V-279543','V-279544','V-279545','V-279546','V-279547','V-279549',
            'V-279550','V-279551','V-279552','V-279553','V-279554','V-279555','V-279556',
            'V-279557','V-279558','V-279559','V-279560','V-279561','V-279562','V-279563',
            'V-279564','V-279565','V-279569','V-279570','V-279571','V-279572','V-279574',
            'V-279575','V-279576','V-279577','V-279578','V-279579','V-279584','V-279604',
            'V-279619','V-279620','V-279621','V-279627','V-279686'
        )
        'VMware vSphere 8.0 ESXi' = @()
        'VMware vSphere 8.0 vCenter' = @()
        'VMware vSphere 8.0 vCenter Appliance Photon OS 4.0' = @()
        'VMware vSphere 8.0 vCenter Appliance PostgreSQL' = @()
        'VMware vSphere 8.0 vCenter Appliance VAMI' = @()
        'VMware vSphere 8.0 vCenter Appliance UI' = @()
        'VMware vSphere 8.0 vCenter Appliance STS' = @()
        'VMware vSphere 8.0 vCenter Appliance Lookup Service' = @()
        'VMware vSphere 8.0 vCenter Appliance EAM' = @()
        'VMware vSphere 8.0 vCenter Appliance Envoy' = @()
        'VMware vSphere 8.0 vCenter Appliance Perfcharts' = @()
    }
}

function Write-StigSummaryTable {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Results,
        [string]$Title = 'STIG Audit Summary'
    )

    if (-not $Results -or $Results.Count -eq 0) {
        Write-Host "No results for: $Title" -ForegroundColor Yellow
        return
    }

    Write-Host "`n=== $Title ===" -ForegroundColor Cyan
    $summary = $Results | Group-Object Status | Sort-Object Name
    $summary | ForEach-Object {
        $color = switch ($_.Name) {
            'Pass' { 'Green' }
            'Fail' { 'Red' }
            'Manual' { 'Yellow' }
            'Error' { 'Magenta' }
            'NotApplicable' { 'DarkGray' }
            default { 'White' }
        }
        Write-Host ("  {0,-14} {1}" -f $_.Name, $_.Count) -ForegroundColor $color
    }
}

function Write-StigDetailTable {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Results,
        [string]$Title = 'STIG Check Results',
        [ValidateSet('All', 'Fail', 'FailManual')]
        [string]$Filter = 'All'
    )

    $filtered = switch ($Filter) {
        'Fail' { $Results | Where-Object Status -eq 'Fail' }
        'FailManual' { $Results | Where-Object Status -in @('Fail', 'Manual', 'Error') }
        default { $Results }
    }

    if (-not $filtered -or @($filtered).Count -eq 0) {
        Write-Host "No matching results for: $Title ($Filter)" -ForegroundColor Yellow
        return
    }

    Write-Host "`n=== $Title ===" -ForegroundColor Cyan
    $display = $filtered | Select-Object Site, Target, RuleId, Severity, Status, Title, Details
    $display | Format-Table -AutoSize -Wrap
}

function Export-StigResults {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Results,
        [Parameter(Mandatory)][string]$OutputPath
    )

    $dir = Split-Path -Parent $OutputPath
    if ($dir -and -not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }

    $Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    Write-Host "Exported $($Results.Count) results to $OutputPath" -ForegroundColor Green
}

function Invoke-SafeStigCheck {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][scriptblock]$Check,
        [Parameter(Mandatory)][hashtable]$ResultTemplate
    )

    try {
        $outcome = & $Check
        if ($outcome -is [hashtable]) {
            foreach ($key in $outcome.Keys) {
                $ResultTemplate[$key] = $outcome[$key]
            }
        }
    } catch {
        $ResultTemplate.Status = 'Error'
        $ResultTemplate.Details = $_.Exception.Message
    }

    New-StigResult @ResultTemplate
}

Export-ModuleMember -Function @(
    'New-StigResult',
    'Import-StigXccdfCatalog',
    'Get-DefaultStigCatalog',
    'Write-StigSummaryTable',
    'Write-StigDetailTable',
    'Export-StigResults',
    'Invoke-SafeStigCheck'
)
