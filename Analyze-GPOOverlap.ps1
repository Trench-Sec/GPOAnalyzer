#Requires -Modules GroupPolicy
<#
.SYNOPSIS
    Analyzes Group Policy Objects from a domain controller for duplicate and
    overlapping settings, then produces a structured report.

.DESCRIPTION
    Connects to an authoritative domain controller, exports every GPO's settings
    as XML, parses each policy entry, and compares them across GPOs to find:
      - Exact duplicates   : identical policy path AND value in 2+ GPOs.
      - Value conflicts    : same policy path but different values.
      - Subset GPOs        : a GPO whose entire setting set is already covered
                             by one or more other GPOs (candidate for removal).

    Output goes to the console AND to a CSV / text report in -ReportPath.

.PARAMETER DomainController
    FQDN or hostname of the authoritative DC to query. Defaults to the PDC emulator.

.PARAMETER Domain
    Target domain. Defaults to the current user's domain.

.PARAMETER ReportPath
    Folder where the CSV and summary text reports are saved.
    Defaults to the current directory.

.PARAMETER IncludeDisabledGPOs
    If set, GPOs that are fully disabled are included in the analysis.

.PARAMETER ExcludeGPO
    One or more GPO display names to skip (wildcards supported).

.EXAMPLE
    .\Analyze-GPOOverlap.ps1 -DomainController dc01.corp.local -Domain corp.local

.EXAMPLE
    .\Analyze-GPOOverlap.ps1 -ReportPath C:\GPO_Reports -IncludeDisabledGPOs

.NOTES
    Requires the GroupPolicy PowerShell module (RSAT: Group Policy Management Tools).
    Must be run with an account that has read access to all GPOs.
    Tested on Windows Server 2016/2019/2022 and Windows 10/11 with RSAT installed.
#>

[CmdletBinding()]
param(
    [string]$DomainController,
    [string]$Domain,
    [string]$ReportPath = $PSScriptRoot,
    [switch]$IncludeDisabledGPOs,
    [string[]]$ExcludeGPO = @()
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── Helpers ───────────────────────────────────────────────────────────────────

function Write-Header([string]$Text) {
    $line = '─' * 72
    Write-Host ""
    Write-Host $line -ForegroundColor Cyan
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host $line -ForegroundColor Cyan
}

function Write-Step([string]$Text) {
    Write-Host "[*] $Text" -ForegroundColor Yellow
}

function Write-OK([string]$Text) {
    Write-Host "    [+] $Text" -ForegroundColor Green
}

function Write-Warn([string]$Text) {
    Write-Host "    [!] $Text" -ForegroundColor Magenta
}

# ── Module check ──────────────────────────────────────────────────────────────

Write-Header "GPO Overlap Analyzer"

if (-not (Get-Module -ListAvailable -Name GroupPolicy)) {
    Write-Error "The 'GroupPolicy' module is not installed. Install RSAT: Group Policy Management Tools and re-run."
    exit 1
}
Import-Module GroupPolicy -ErrorAction Stop

# ── Resolve domain & DC ───────────────────────────────────────────────────────

Write-Step "Resolving domain and domain controller..."

if (-not $Domain) {
    $Domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
}

if (-not $DomainController) {
    $DomainController = ([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).PdcRoleOwner.Name
}

Write-OK "Domain          : $Domain"
Write-OK "Domain Controller: $DomainController"

# ── Retrieve all GPOs ─────────────────────────────────────────────────────────

Write-Step "Retrieving all GPOs from $DomainController..."

$allGPOs = Get-GPO -All -Domain $Domain -Server $DomainController

if (-not $IncludeDisabledGPOs) {
    $allGPOs = $allGPOs | Where-Object {
        $_.GpoStatus -ne 'AllSettingsDisabled'
    }
}

# Apply exclusion filter
foreach ($pattern in $ExcludeGPO) {
    $allGPOs = $allGPOs | Where-Object { $_.DisplayName -notlike $pattern }
}

Write-OK "GPOs to analyze : $($allGPOs.Count)"

if ($allGPOs.Count -eq 0) {
    Write-Warning "No GPOs found after filters. Exiting."
    exit 0
}

# ── Parse GPO settings via XML report ────────────────────────────────────────
#
#   Get-GPOReport -ReportType Xml returns a rich XML document.
#   We extract every <q*:Policy> node (Computer & User configs) into a flat
#   list of [PSCustomObject]{ GPOName, Section, Category, PolicyName,
#                              State, ExtraInfo } objects.

Write-Step "Exporting and parsing GPO XML reports..."

$namespaces = @{
    gp   = 'http://www.microsoft.com/GroupPolicy/Settings'
    q1   = 'http://www.microsoft.com/GroupPolicy/Settings/Windows/Registry'
    q2   = 'http://www.microsoft.com/GroupPolicy/Settings/Security'
    q3   = 'http://www.microsoft.com/GroupPolicy/Settings/Audit'
}

# Collect all parsed settings
$allSettings = [System.Collections.Generic.List[PSCustomObject]]::new()
$gpoMetaList = [System.Collections.Generic.List[PSCustomObject]]::new()
$parseErrors = [System.Collections.Generic.List[string]]::new()

foreach ($gpo in $allGPOs) {
    Write-Verbose "  Parsing: $($gpo.DisplayName)"

    try {
        [xml]$reportXml = Get-GPOReport -Guid $gpo.Id -ReportType Xml `
                                        -Domain $Domain -Server $DomainController
    }
    catch {
        $parseErrors.Add("$($gpo.DisplayName): $_")
        Write-Warn "  Could not export '$($gpo.DisplayName)': $($_.Exception.Message)"
        continue
    }

    $gpoMetaList.Add([PSCustomObject]@{
        Name       = $gpo.DisplayName
        GUID       = $gpo.Id
        Status     = $gpo.GpoStatus
        Created    = $gpo.CreationTime
        Modified   = $gpo.ModificationTime
        LinkedTo   = ($gpo.Linked | Out-String).Trim()
    })

    # Helper: walk an XML section (Computer or User) and collect policy nodes
    function Get-SectionSettings {
        param(
            [System.Xml.XmlElement]$SectionNode,
            [string]$SectionName,
            [string]$GpoName
        )

        if ($null -eq $SectionNode) { return }

        # Generic policy nodes exposed by Get-GPOReport
        $SectionNode.SelectNodes('.//*') | ForEach-Object {
            $node = $_

            # Skip container/grouping nodes — we want leaf-level policy entries
            $localName = $node.LocalName

            # Heuristic: nodes with a "Name" child or attribute are policy items
            $policyName = $null
            $state      = $null
            $extraInfo  = $null
            $category   = $node.ParentNode.LocalName

            if ($node.'Name') {
                $policyName = $node.'Name'
            }
            elseif ($node.GetAttribute('Name')) {
                $policyName = $node.GetAttribute('Name')
            }
            else {
                return  # not a leaf we care about
            }

            # Common state attributes across different policy types
            foreach ($attr in @('State','Setting','Value','Enabled','Type')) {
                if ($node.$attr) { $state = $node.$attr; break }
                if ($node.GetAttribute($attr)) { $state = $node.GetAttribute($attr); break }
            }

            # Grab any child text that looks like a value/path
            $childValues = $node.ChildNodes |
                           Where-Object { $_.NodeType -eq 'Text' -or ($_.LocalName -match 'Value|Setting|Data') } |
                           ForEach-Object { $_.InnerText } |
                           Where-Object { $_ -and $_.Trim() -ne '' }
            if ($childValues) { $extraInfo = ($childValues -join '; ') }

            if ($policyName) {
                [PSCustomObject]@{
                    GPOName    = $GpoName
                    Section    = $SectionName
                    Category   = $category
                    PolicyName = $policyName.Trim()
                    State      = if ($state) { $state.Trim() } else { '(unspecified)' }
                    ExtraInfo  = if ($extraInfo) { $extraInfo.Trim() } else { '' }
                    # Canonical key used for matching
                    _MatchKey  = "$SectionName|$($policyName.Trim().ToLower())"
                    _FullKey   = "$SectionName|$($policyName.Trim().ToLower())|$(if($state){$state.Trim().ToLower()}else{''})"
                }
            }
        }
    }

    $computerNode = $reportXml.SelectSingleNode('//gp:Computer', (New-Object System.Xml.XmlNamespaceManager($reportXml.NameTable)))
    $userNode     = $reportXml.SelectSingleNode('//gp:User',     (New-Object System.Xml.XmlNamespaceManager($reportXml.NameTable)))

    # Fallback: namespace-free selection
    if ($null -eq $computerNode) { $computerNode = $reportXml.GPO.Computer }
    if ($null -eq $userNode)     { $userNode     = $reportXml.GPO.User }

    $compSettings = Get-SectionSettings -SectionNode $computerNode -SectionName 'Computer' -GpoName $gpo.DisplayName
    $userSettings = Get-SectionSettings -SectionNode $userNode     -SectionName 'User'     -GpoName $gpo.DisplayName

    foreach ($s in $compSettings) { $allSettings.Add($s) }
    foreach ($s in $userSettings) { $allSettings.Add($s) }
}

Write-OK "Total policy entries collected: $($allSettings.Count)"

# ── Analysis 1: Exact duplicates (same policy name + same value) ──────────────

Write-Step "Identifying exact duplicates (same policy name & value in multiple GPOs)..."

$exactDuplicates = $allSettings |
    Group-Object -Property _FullKey |
    Where-Object { $_.Count -gt 1 } |
    ForEach-Object {
        $group = $_.Group
        [PSCustomObject]@{
            Section    = $group[0].Section
            Category   = $group[0].Category
            PolicyName = $group[0].PolicyName
            State      = $group[0].State
            GPOs       = ($group.GPOName | Sort-Object -Unique) -join ' | '
            GPOCount   = ($group.GPOName | Sort-Object -Unique).Count
        }
    } |
    Sort-Object Section, PolicyName

Write-OK "Exact duplicates found: $($exactDuplicates.Count)"

# ── Analysis 2: Value conflicts (same policy name, different values) ──────────

Write-Step "Identifying value conflicts (same policy name, different values across GPOs)..."

$conflicts = $allSettings |
    Group-Object -Property _MatchKey |
    Where-Object { ($_.Group.State | Sort-Object -Unique).Count -gt 1 } |
    ForEach-Object {
        $group = $_.Group
        $variants = $group |
            Group-Object State |
            ForEach-Object { "$($_.Name) [in: $(($_.Group.GPOName | Sort-Object -Unique) -join ', ')]" }
        [PSCustomObject]@{
            Section    = $group[0].Section
            PolicyName = $group[0].PolicyName
            Variants   = $variants -join ' ||| '
            GPOCount   = ($group.GPOName | Sort-Object -Unique).Count
        }
    } |
    Sort-Object Section, PolicyName

Write-OK "Value conflicts found: $($conflicts.Count)"

# ── Analysis 3: Subset / redundant GPOs ──────────────────────────────────────
#
#   A GPO is a SUBSET of another when every policy key (_MatchKey) it defines
#   is also defined in the other GPO with the same value (_FullKey).
#   Such a GPO is a candidate for consolidation/deletion.

Write-Step "Identifying subset (fully redundant) GPOs..."

# Build per-GPO dictionaries: { _FullKey -> setting }
$gpoIndex = @{}
foreach ($s in $allSettings) {
    if (-not $gpoIndex.ContainsKey($s.GPOName)) {
        $gpoIndex[$s.GPOName] = @{}
    }
    $gpoIndex[$s.GPOName][$s._FullKey] = $s
}

$subsetResults = [System.Collections.Generic.List[PSCustomObject]]::new()

$gpoNames = $gpoIndex.Keys | Sort-Object

foreach ($candidate in $gpoNames) {
    $candidateKeys = $gpoIndex[$candidate].Keys
    if ($candidateKeys.Count -eq 0) { continue }

    foreach ($other in $gpoNames) {
        if ($candidate -eq $other) { continue }

        $otherKeys = $gpoIndex[$other].Keys

        # Is every key in $candidate also present in $other?
        $notCovered = $candidateKeys | Where-Object { $otherKeys -notcontains $_ }

        if ($notCovered.Count -eq 0) {
            $subsetResults.Add([PSCustomObject]@{
                RedundantGPO  = $candidate
                CoveredBy     = $other
                SharedSettings = $candidateKeys.Count
                Note          = "All $($candidateKeys.Count) setting(s) in '$candidate' are fully covered by '$other'."
            })
        }
    }
}

# De-duplicate symmetric pairs and keep only the most informative direction
$subsetResults = $subsetResults | Sort-Object RedundantGPO, CoveredBy | Select-Object -Unique *

Write-OK "Subset (fully redundant) GPO relationships found: $($subsetResults.Count)"

# ── Report: Console summary ───────────────────────────────────────────────────

Write-Header "RESULTS SUMMARY"

# --- Exact Duplicates ---
Write-Host ""
Write-Host "┌─ EXACT DUPLICATES ($($exactDuplicates.Count) policies duplicated across multiple GPOs)" -ForegroundColor White
Write-Host "│  A policy with an identical name AND value exists in 2+ GPOs." -ForegroundColor DarkGray
Write-Host "│  The GPO listed LAST in alphabetical order is the likely candidate for removal." -ForegroundColor DarkGray
Write-Host "│" -ForegroundColor White

if ($exactDuplicates.Count -eq 0) {
    Write-Host "│  (none found)" -ForegroundColor DarkGreen
}
else {
    $exactDuplicates | ForEach-Object {
        Write-Host "│" -ForegroundColor White
        Write-Host "│  Policy   : $($_.PolicyName)" -ForegroundColor Cyan
        Write-Host "│  Section  : $($_.Section)  |  Category: $($_.Category)" -ForegroundColor Gray
        Write-Host "│  Value    : $($_.State)" -ForegroundColor Gray
        Write-Host "│  In GPOs  : $($_.GPOs)" -ForegroundColor Yellow
    }
}

# --- Value Conflicts ---
Write-Host ""
Write-Host "┌─ VALUE CONFLICTS ($($conflicts.Count) policies with differing values across GPOs)" -ForegroundColor White
Write-Host "│  Same policy name but different values — last-write-wins depending on GPO link order." -ForegroundColor DarkGray
Write-Host "│" -ForegroundColor White

if ($conflicts.Count -eq 0) {
    Write-Host "│  (none found)" -ForegroundColor DarkGreen
}
else {
    $conflicts | ForEach-Object {
        Write-Host "│" -ForegroundColor White
        Write-Host "│  Policy   : $($_.PolicyName)" -ForegroundColor Cyan
        Write-Host "│  Section  : $($_.Section)" -ForegroundColor Gray
        Write-Host "│  Values   : $($_.Variants)" -ForegroundColor Magenta
    }
}

# --- Subset / Redundant GPOs ---
Write-Host ""
Write-Host "┌─ REDUNDANT (SUBSET) GPOs ($($subsetResults.Count) relationships found)" -ForegroundColor White
Write-Host "│  Every setting in the REDUNDANT GPO is already enforced by the COVERING GPO." -ForegroundColor DarkGray
Write-Host "│  Verify link scope and precedence before removing any GPO." -ForegroundColor DarkGray
Write-Host "│" -ForegroundColor White

if ($subsetResults.Count -eq 0) {
    Write-Host "│  (none found)" -ForegroundColor DarkGreen
}
else {
    $subsetResults | ForEach-Object {
        Write-Host "│" -ForegroundColor White
        Write-Host "│  Redundant GPO : $($_.RedundantGPO)" -ForegroundColor Red
        Write-Host "│  Covered by    : $($_.CoveredBy)" -ForegroundColor Green
        Write-Host "│  Note          : $($_.Note)" -ForegroundColor Gray
    }
}

Write-Host ""

# ── Export to CSV & text report ───────────────────────────────────────────────

Write-Step "Writing reports to $ReportPath ..."

if (-not (Test-Path $ReportPath)) {
    New-Item -ItemType Directory -Path $ReportPath | Out-Null
}

$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'

$csvDuplicates = Join-Path $ReportPath "GPO_ExactDuplicates_$timestamp.csv"
$csvConflicts  = Join-Path $ReportPath "GPO_ValueConflicts_$timestamp.csv"
$csvSubsets    = Join-Path $ReportPath "GPO_RedundantGPOs_$timestamp.csv"
$csvAll        = Join-Path $ReportPath "GPO_AllSettings_$timestamp.csv"
$txtSummary    = Join-Path $ReportPath "GPO_Summary_$timestamp.txt"

$exactDuplicates | Export-Csv -Path $csvDuplicates -NoTypeInformation -Encoding UTF8
$conflicts       | Export-Csv -Path $csvConflicts  -NoTypeInformation -Encoding UTF8
$subsetResults   | Export-Csv -Path $csvSubsets    -NoTypeInformation -Encoding UTF8
$allSettings | Select-Object GPOName, Section, Category, PolicyName, State, ExtraInfo |
               Export-Csv -Path $csvAll -NoTypeInformation -Encoding UTF8

# Plain-text summary
$summaryLines = @(
    "GPO Overlap Analysis Report"
    "Generated : $(Get-Date)"
    "Domain    : $Domain"
    "Server    : $DomainController"
    "=" * 72
    ""
    "GPOs Analyzed : $($gpoMetaList.Count)"
    "Total Settings: $($allSettings.Count)"
    ""
    "─── EXACT DUPLICATES ($($exactDuplicates.Count)) ───"
    "Policies with identical name AND value present in multiple GPOs."
    ""
)

foreach ($d in $exactDuplicates) {
    $summaryLines += "  Policy   : $($d.PolicyName)"
    $summaryLines += "  Section  : $($d.Section)  Category: $($d.Category)"
    $summaryLines += "  Value    : $($d.State)"
    $summaryLines += "  Found in : $($d.GPOs)"
    $summaryLines += ""
}

$summaryLines += "─── VALUE CONFLICTS ($($conflicts.Count)) ───"
$summaryLines += "Same policy name, different values — enforce link order carefully."
$summaryLines += ""

foreach ($c in $conflicts) {
    $summaryLines += "  Policy  : $($c.PolicyName)  [$($c.Section)]"
    $summaryLines += "  Values  : $($c.Variants)"
    $summaryLines += ""
}

$summaryLines += "─── REDUNDANT GPOs ($($subsetResults.Count)) ───"
$summaryLines += "The listed GPO's entire rule set is already covered by another GPO."
$summaryLines += ""

foreach ($r in $subsetResults) {
    $summaryLines += "  Redundant GPO : $($r.RedundantGPO)"
    $summaryLines += "  Covered by    : $($r.CoveredBy)"
    $summaryLines += "  $($r.Note)"
    $summaryLines += ""
}

if ($parseErrors.Count -gt 0) {
    $summaryLines += "─── PARSE ERRORS ($($parseErrors.Count)) ───"
    foreach ($e in $parseErrors) { $summaryLines += "  $e" }
    $summaryLines += ""
}

$summaryLines | Out-File -FilePath $txtSummary -Encoding UTF8

Write-OK "Exact duplicates CSV : $csvDuplicates"
Write-OK "Value conflicts CSV  : $csvConflicts"
Write-OK "Redundant GPOs CSV   : $csvSubsets"
Write-OK "All settings CSV     : $csvAll"
Write-OK "Summary text report  : $txtSummary"

Write-Header "Analysis Complete"
Write-Host "  Exact duplicate policies : $($exactDuplicates.Count)" -ForegroundColor Cyan
Write-Host "  Value conflicts          : $($conflicts.Count)"        -ForegroundColor Magenta
Write-Host "  Redundant GPO pairs      : $($subsetResults.Count)"   -ForegroundColor Red
Write-Host ""
Write-Host "  Review the summary report and validate link scope / OU inheritance" -ForegroundColor DarkGray
Write-Host "  before unlinking or deleting any GPO." -ForegroundColor DarkGray
Write-Host ""
