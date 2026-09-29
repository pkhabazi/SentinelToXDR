<#
.SYNOPSIS
    Measures the module against a real content repository and writes every number the
    docs quote to a JSON file, so each one can be diffed rather than trusted.

.DESCRIPTION
    Every significant bug in this project was found by running over the public
    Azure/Azure-Sentinel corpus or against a live tenant WITH A GREEN TEST SUITE -
    corrupted custom details on 863 rules, 94 rules losing their display name, an
    apostrophe in a comment blanking a query, 150 rules graded deployable that could not
    run, and the undocumented API constraints this release is about. The suite found
    none of them. This script is how the numbers quoted in README, CHANGELOG and the docs
    get measured rather than estimated.

    It reports:

      Layer 0     files read vs rules read vs objects produced. Documented in
                  docs/Validation.md as the arithmetic invariant; it has caught two
                  silent-loss bugs. Every rule read must come back with a verdict.
      Verdicts    the Ready / Review / NeedsWork / Blocked distribution, and the data tiers.
      Constraints how many rules each API constraint affects, and how many would be refused.
      Window      how many rules can only migrate by way of a property removed 2026-10-01.
      Rescues     two counts the docs quote as 'what fixing X would buy': rules carrying a
                  tactic with no technique (kept since 2026-09-15), and rules refused only
                  because Sentinel splits a registry key/value or file name/hash across two
                  entities that Graph wants in one.
      Performance wall time and peak working set, for the release record.

    Nothing here reaches past the public cmdlets. The impact classification is read from
    src/Data/MigrationReadiness.psd1 directly, because the constraint list must be DERIVED
    from data rather than typed here - a hardcoded list stops being complete the first time
    a constraint is added, and a short list in this script understates the problem in public.

.PARAMETER Path
    The content repository to read. Falls back to $env:SENTINELTOXDR_CORPUS. There is no
    default: the scope of the numbers has to be an argument someone chose.

.PARAMETER ReportPath
    Optional CSV of the per-rule assessment.

.PARAMETER SummaryPath
    Optional JSON of every aggregate figure, with the corpus commit and the date. This is
    what the docs are diffed against.

.EXAMPLE
    pwsh tests/Integration/Measure-Corpus.ps1 -Path /path/to/Azure-Sentinel -ReportPath ./validation/corpus.csv -SummaryPath ./validation/corpus.summary.json
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$Path = $env:SENTINELTOXDR_CORPUS,

    [Parameter()]
    [string]$ReportPath,

    [Parameter()]
    [string]$SummaryPath
)

$ErrorActionPreference = 'Stop'
$started = Get-Date

if (-not $Path) { throw 'Pass -Path or set SENTINELTOXDR_CORPUS. The scope of a published number has to be stated.' }
if (-not (Test-Path -LiteralPath $Path)) { throw "Corpus path not found: $Path" }

if (-not (Get-Module -Name SentinelToXDR)) {
    Import-Module -Name (Join-Path $PSScriptRoot '../../src/SentinelToXDR.psd1') -Force
}
$repoRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
$readiness = Import-PowerShellDataFile -Path (Join-Path $repoRoot 'src/Data/MigrationReadiness.psd1')

# Read exactly the path given. There used to be a convenience here that silently
# redirected a repository root to its Solutions folder, which meant the same command
# produced 3,671 rules or 5,161 depending on a rule nobody could see. Numbers that go
# into the README have to state their scope, so the scope is the argument.
$root = (Resolve-Path -LiteralPath $Path).Path
Write-Host "Reading $root" -ForegroundColor Cyan

$corpusCommit = ''
try { $corpusCommit = (& git -C $root log -1 --format='%h %ci' 2>$null) } catch { $corpusCommit = '' }

$candidateFiles = @(Get-ChildItem -LiteralPath $root -Recurse -File -Include '*.yaml', '*.yml', '*.json' -ErrorAction SilentlyContinue)
Write-Host "  $($candidateFiles.Count) candidate file(s) (yaml/yml/json)" -ForegroundColor DarkGray

$rules = @(Get-SentinelAnalyticsRule -Path $root -Recurse -WarningAction SilentlyContinue -ErrorAction SilentlyContinue)
Write-Host "  $($rules.Count) rule(s) read" -ForegroundColor Cyan

$assessed = @($rules | Test-XDRMigrationReadiness -PassThruDetection -WarningAction SilentlyContinue -ErrorAction SilentlyContinue)
Write-Host "  $($assessed.Count) assessed`n" -ForegroundColor Cyan

# ---- Layer 0: the arithmetic has to balance ---------------------------------
Write-Host '==== Layer 0: rules read vs objects produced ====' -ForegroundColor Cyan
$balanced = $rules.Count -eq $assessed.Count
Write-Host ("  files {0}   read {1}   assessed {2}   {3}" -f $candidateFiles.Count, $rules.Count, $assessed.Count,
    $(if ($balanced) { 'BALANCED' } else { "LOST $($rules.Count - $assessed.Count)" })) `
    -ForegroundColor $(if ($balanced) { 'Green' } else { 'Red' })
if (-not $balanced) {
    Write-Warning 'Rules went in and did not come out. That is a silent-loss bug; stop and find it before quoting any number below.'
}

$total = [Math]::Max($assessed.Count, 1)
function Get-Pct { param([int]$N) [Math]::Round($N / $total * 100, 1) }

# ---- Verdicts and tiers -------------------------------------------------------
Write-Host "`n==== Verdict distribution ====" -ForegroundColor Cyan
$verdicts = [ordered]@{}
foreach ($v in @('Ready', 'Review', 'NeedsWork', 'Blocked')) {
    $n = @($assessed | Where-Object { $_.Verdict -eq $v }).Count
    $verdicts[$v] = $n
    Write-Host ("  {0,-10} {1,6}  {2,5:N1}%" -f $v, $n, (Get-Pct $n))
}
$tiers = [ordered]@{}
foreach ($t in @('DefenderOnly', 'Mixed', 'SentinelOnly', '')) {
    $n = @($assessed | Where-Object { [string]$_.DataTier -eq $t }).Count
    $tiers[$(if ($t) { $t } else { 'None' })] = $n
}
$defenderTier = @($assessed | Where-Object { $_.DataTier -eq 'DefenderOnly' })
$readyOfDefender = @($defenderTier | Where-Object { $_.Verdict -eq 'Ready' }).Count
Write-Host ("  tiers: DefenderOnly {0}, Mixed {1}, SentinelOnly {2}, none {3}; Ready is reachable by the {0} Defender-tier rules and {4} reach it" -f `
        $tiers['DefenderOnly'], $tiers['Mixed'], $tiers['SentinelOnly'], $tiers['None'], $readyOfDefender) -ForegroundColor DarkGray

# ---- The API constraints ------------------------------------------------------
# Counted from the raw diagnostics, so this reports what the CONVERTER decided. Both
# lists are DERIVED from MigrationReadiness.psd1, not typed. 'Refused' is the High ones:
# a Medium constraint (a truncated tactic) still deploys.
Write-Host "`n==== Undocumented API constraints ====" -ForegroundColor Cyan
$apiRules = @($readiness.Rules | Where-Object { $_.Capability -eq 'Custom detection API requirements' })
$constraintNames = @($apiRules | ForEach-Object { [string]$_.TargetValue })
$refusedNames = @($apiRules | Where-Object { $_.Impact -eq 'High' } | ForEach-Object { [string]$_.TargetValue })

$hits = [ordered]@{}
foreach ($name in $constraintNames) { $hits[$name] = 0 }
$refused = 0
$inWindow = 0
$window = $readiness.DeprecationWindow
$pairRescue = 0
$tacticNoTechnique = 0

foreach ($row in $assessed) {
    $diags = @($row.Detection.Diagnostics)
    $targets = @($diags | ForEach-Object { [string]$_.TargetValue })
    foreach ($name in $constraintNames) {
        if ($targets -contains $name) { $hits[$name]++ }
    }
    $refusals = @($targets | Where-Object { $_ -in $refusedNames })
    if ($refusals.Count -gt 0) { $refused++ }
    if (@($targets | Where-Object { $_ -in @($window.AppliesToConstraints) }).Count -gt 0) { $inWindow++ }

    # A rule refused ONLY on weak identifiers, every one of which is on an entity Sentinel
    # splits in two (key/value, name/hash) and whose partner is also mapped. Merging the
    # pair into one Graph entry would rescue it. Upper bound: assumes the partner columns
    # are sufficient together.
    if ($refusals.Count -gt 0 -and @($refusals | Where-Object { $_ -ne 'EntityIdentifierWeak' }).Count -eq 0) {
        $weak = @($diags | Where-Object { $_.TargetValue -eq 'EntityIdentifierWeak' })
        $sourceTypes = @($row.Detection.SourceRule.EntityMappings | ForEach-Object { [string]$_.entityType })
        $allPairs = $weak.Count -gt 0 -and @($weak | Where-Object {
                $_.Reason -notmatch "maps entity '(RegistryKey|RegistryValue|File|FileHash)'" }).Count -eq 0
        $hasPartner = (($sourceTypes -contains 'RegistryKey') -and ($sourceTypes -contains 'RegistryValue')) -or
                      (($sourceTypes -contains 'File') -and ($sourceTypes -contains 'FileHash'))
        if ($allPairs -and $hasPartner) { $pairRescue++ }
    }

    # Counted on what was EMITTED: a tactic entry with an empty techniques collection is
    # what the service refused until 2026-09-15 and what the module now carries.
    $emittedTactics = @($row.Detection.Rule.detectionAction.alertTemplate.tactics)
    if ($emittedTactics.Count -gt 0 -and @($emittedTactics | Where-Object { @($_.techniques).Count -eq 0 }).Count -gt 0) { $tacticNoTechnique++ }
}
foreach ($name in $constraintNames) {
    Write-Host ("  {0,-24} {1,6}  {2,5:N1}%  {3}" -f $name, $hits[$name], (Get-Pct $hits[$name]), $(if ($name -in $refusedNames) { 'refused' } else { 'deploys' }))
}
Write-Host ("  {0,-24} {1,6}  {2,5:N1}%" -f 'WOULD BE REFUSED', $refused, (Get-Pct $refused)) -ForegroundColor Yellow

Write-Host "`n==== Deprecation window ====" -ForegroundColor Cyan
Write-Host ("  {0} rule(s) ({1:N1}%) can only migrate today by way of a property removed on {2}" -f `
        $inWindow, (Get-Pct $inWindow), $window.Date) -ForegroundColor Yellow

Write-Host "`n==== Rescues ====" -ForegroundColor Cyan
Write-Host ("  {0} rule(s) carry a tactic with no technique (kept since 2026-09-15; dropped before)" -f $tacticNoTechnique)
Write-Host ("  {0} rule(s) refused only on a split registry/file pair that one merged entry would rescue (upper bound)" -f $pairRescue)

if ($ReportPath) {
    $assessed | Select-Object RuleName, Verdict, Score, Kind, DataTier,
        @{ N = 'SourcePath'; E = { [string]$_.SourcePath -replace [regex]::Escape($root), '<corpus>' } } |
        Export-Csv -LiteralPath $ReportPath -NoTypeInformation -Encoding utf8
    Write-Host "`nPer-rule CSV: $ReportPath" -ForegroundColor DarkGray
}

$elapsed = (Get-Date) - $started
# PeakWorkingSet64 reads 0 on macOS; WorkingSet64 at the end of the run is the honest
# figure that is available everywhere.
$process = [System.Diagnostics.Process]::GetCurrentProcess()
$process.Refresh()
$summary = [ordered]@{
    MeasuredOn        = (Get-Date).ToString('yyyy-MM-dd')
    CorpusPath        = $root
    CorpusCommit      = [string]$corpusCommit
    CandidateFiles    = $candidateFiles.Count
    RulesRead         = $rules.Count
    RulesAssessed     = $assessed.Count
    Layer0Balanced    = $balanced
    Verdicts          = $verdicts
    VerdictPercent    = [ordered]@{}
    DataTiers         = $tiers
    ReadyOfDefenderTier = $readyOfDefender
    Constraints       = $hits
    ConstraintPercent = [ordered]@{}
    WouldBeRefused    = $refused
    WouldBeRefusedPercent = (Get-Pct $refused)
    DeprecationWindowDate = [string]$window.Date
    InDeprecationWindow   = $inWindow
    InDeprecationWindowPercent = (Get-Pct $inWindow)
    TacticWithoutTechnique = $tacticNoTechnique
    PairMergeRescueUpperBound = $pairRescue
    ElapsedMinutes    = [Math]::Round($elapsed.TotalMinutes, 1)
    WorkingSetMB      = [Math]::Round($process.WorkingSet64 / 1MB)
    ManagedHeapMB     = [Math]::Round([GC]::GetTotalMemory($false) / 1MB)
}
foreach ($v in $verdicts.Keys) { $summary.VerdictPercent[$v] = Get-Pct $verdicts[$v] }
foreach ($c in $hits.Keys) { $summary.ConstraintPercent[$c] = Get-Pct $hits[$c] }

if ($SummaryPath) {
    $summary | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $SummaryPath -Encoding utf8
    Write-Host "Summary JSON: $SummaryPath" -ForegroundColor DarkGray
}

Write-Host ("`nMeasured {0} in {1:N1} minute(s); working set {2} MB, managed heap {3} MB." -f $summary.MeasuredOn, $elapsed.TotalMinutes, $summary.WorkingSetMB, $summary.ManagedHeapMB) -ForegroundColor DarkGray
