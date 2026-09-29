#Requires -Version 7.0
<#
.SYNOPSIS
    Assesses a set of Sentinel analytics rules and writes a self-contained HTML report.

.DESCRIPTION
    The engine behind the assess-migration skill. Imports the SentinelToXDR module from this
    repository, runs Test-XDRMigrationReadiness over -Path, and writes two files:

      <OutputFolder>/assessment.json   the verdicts, findings and the aggregated summary
      <OutputFolder>/assessment.html   one page, no CDN, no external font: verdict split,
                                       what blocks the rest, the 2026-10-01 window, data
                                       tiers, estate prerequisites, one row per rule

    Every verdict and every count comes from the module. This script aggregates and
    renders; it decides nothing.

.PARAMETER Path
    File or folder of Sentinel analytics rules (community YAML, ARM JSON, Content Hub).

.PARAMETER Recurse
    Search subfolders.

.PARAMETER OutputFolder
    Where the two files land. Created if missing. Defaults to ./out/assessment.

.PARAMETER Title
    Report heading.

.EXAMPLE
    pwsh -NoProfile -File .claude/skills/assess-migration/scripts/Invoke-MigrationAssessment.ps1 -Path ./Samples
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0)]
    [string[]]$Path,

    [Parameter()]
    [switch]$Recurse,

    [Parameter()]
    [string]$OutputFolder = './out/assessment',

    [Parameter()]
    [string]$Title = 'Sentinel to Defender XDR migration assessment'
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# 1. Run the engine
# ---------------------------------------------------------------------------
$repoRoot = Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..' -AdditionalChildPath '..', '..', '..')
$manifest = Join-Path -Path $repoRoot -ChildPath 'src' -AdditionalChildPath 'SentinelToXDR.psd1'
if (-not (Test-Path -LiteralPath $manifest)) { throw "Module manifest not found at $manifest" }
Import-Module $manifest -Force
$moduleVersion = (Get-Module SentinelToXDR).Version.ToString()

$sw = [System.Diagnostics.Stopwatch]::StartNew()
$readinessParams = @{ Path = $Path; WarningAction = 'SilentlyContinue' }
if ($Recurse) { $readinessParams['Recurse'] = $true }
$results = @(Test-XDRMigrationReadiness @readinessParams)
$sw.Stop()

if ($results.Count -eq 0) { throw "No analytics rules found under: $($Path -join ', ')" }

# The readiness data file carries the deprecation window and the verdict descriptions.
$readinessData = Import-PowerShellDataFile -Path (Join-Path -Path $repoRoot -ChildPath 'src' -AdditionalChildPath 'Data', 'MigrationReadiness.psd1')
$window = $readinessData.DeprecationWindow

# ---------------------------------------------------------------------------
# 2. Aggregate
# ---------------------------------------------------------------------------
$verdictOrder = @('Blocked', 'NeedsWork', 'Review', 'Ready')
$verdictMeaning = @{}
foreach ($v in $readinessData.Verdicts) { $verdictMeaning[$v.Name] = $v.Description }

$counts = [ordered]@{}
foreach ($v in $verdictOrder) { $counts[$v] = @($results | Where-Object Verdict -eq $v).Count }
$total = $results.Count

$tierCounts = [ordered]@{}
foreach ($t in @('DefenderOnly', 'Mixed', 'SentinelOnly')) {
    $tierCounts[$t] = @($results | Where-Object DataTier -eq $t).Count
}
$tierCounts['(none)'] = $total - ($tierCounts.Values | Measure-Object -Sum).Sum

# What blocks the rest: one row per finding summary, counting RULES not findings.
# Blocking and High drive Blocked/NeedsWork; Medium drives Review. Low never drives a verdict.
$blockerRows = foreach ($impact in @('Blocking', 'High', 'Medium')) {
    $summaries = @($results | ForEach-Object {
        $rule = $_
        @($rule.Findings | Where-Object { $_.Impact -eq $impact -and -not $_.EstateLevel } |
            Select-Object -ExpandProperty Summary -Unique) | ForEach-Object {
                [PSCustomObject]@{ Rule = $rule.RuleName; Summary = $_ }
            }
    })
    foreach ($group in ($summaries | Group-Object Summary | Sort-Object Count -Descending)) {
        $remedy = ($results.Findings | Where-Object { $_.Summary -eq $group.Name } | Select-Object -First 1).Remedy
        [PSCustomObject]@{
            Impact   = $impact
            Summary  = $group.Name
            Rules    = $group.Count
            InWindow = ($window.AppliesToSummaries -contains $group.Name)
            Remedy   = [string]$remedy
        }
    }
}
$blockerRows = @($blockerRows)

# Estate-level prerequisites: reported once, with the number of rules waiting on them.
$estatePairs = @($results | ForEach-Object {
    $rule = $_
    @($rule.Findings | Where-Object EstateLevel | Select-Object -ExpandProperty Summary -Unique) |
        ForEach-Object { [PSCustomObject]@{ Rule = $rule.RuleName; Summary = $_ } }
})
$estateRows = @($estatePairs | Group-Object Summary | ForEach-Object {
    $name = $_.Name
    $remedy = @($results.Findings | Where-Object { $_.Summary -eq $name -and $_.Remedy })
    [PSCustomObject]@{
        Summary = $name
        Rules   = $_.Count
        Remedy  = if ($remedy.Count -gt 0) { [string]$remedy[0].Remedy } else { '' }
    }
})

# Rules inside the 2026-10-01 window.
$windowRules = @($results | Where-Object {
    $r = $_
    @($r.Findings | Where-Object { $window.AppliesToSummaries -contains $_.Summary }).Count -gt 0
})

# Per-rule rows, worst first.
$rank = @{ Blocked = 0; NeedsWork = 1; Review = 2; Ready = 3 }
$ruleRows = @($results | Sort-Object @{ E = { $rank[[string]$_.Verdict] } }, @{ E = { $_.Score } }, RuleName | ForEach-Object {
    $r = $_
    $seenSummary = [System.Collections.Generic.HashSet[string]]::new()
    $drivers = @($r.Findings | Where-Object { $_.Impact -in 'Blocking', 'High', 'Medium' } |
        Sort-Object @{ E = { @{ Blocking = 0; High = 1; Medium = 2 }[[string]$_.Impact] } } |
        Where-Object { $seenSummary.Add([string]$_.Summary) } |
        ForEach-Object {
            [PSCustomObject]@{
                Impact      = $_.Impact
                Summary     = $_.Summary
                Reason      = $_.Reason
                Remedy      = $_.Remedy
                EstateLevel = $_.EstateLevel
            }
        })
    [PSCustomObject]@{
        RuleName   = $r.RuleName
        Verdict    = $r.Verdict
        Score      = $r.Score
        Kind       = $r.Kind
        DataTier   = $r.DataTier
        InWindow   = ($windowRules.RuleName -contains $r.RuleName)
        SourcePath = $r.SourcePath
        SourceFile = if ($r.SourcePath) { Split-Path $r.SourcePath -Leaf } else { '' }
        Findings   = $drivers
    }
})

$summary = [ordered]@{
    Title            = $Title
    GeneratedAt      = (Get-Date).ToString('yyyy-MM-dd HH:mm')
    Source           = ($Path | ForEach-Object { (Resolve-Path $_).Path }) -join ', '
    ModuleVersion    = $moduleVersion
    ElapsedSeconds   = [math]::Round($sw.Elapsed.TotalSeconds, 1)
    Total            = $total
    Verdicts         = $counts
    VerdictMeaning   = $verdictMeaning
    DataTiers        = $tierCounts
    DeprecationDate  = $window.Date
    RulesInWindow    = $windowRules.Count
    Blockers         = $blockerRows
    EstatePrereqs    = $estateRows
    Rules            = $ruleRows
}

# ---------------------------------------------------------------------------
# 3. Write JSON
# ---------------------------------------------------------------------------
if (-not (Test-Path -LiteralPath $OutputFolder)) { New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null }
$jsonPath = Join-Path -Path $OutputFolder -ChildPath 'assessment.json'
$summary | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $jsonPath -Encoding utf8

# ---------------------------------------------------------------------------
# 4. Render HTML
# ---------------------------------------------------------------------------
function Esc([object]$s) { [System.Net.WebUtility]::HtmlEncode([string]$s) }
function Pct([int]$n) { if ($total -eq 0) { '0%' } else { '{0:0}%' -f ($n * 100.0 / $total) } }

# Status palette: verdicts are states, so they wear status colours, each with an icon + label.
$vColor = @{ Ready = '#0ca30c'; Review = '#fab219'; NeedsWork = '#ec835a'; Blocked = '#d03b3b' }
$vIcon  = @{ Ready = '&#10003;'; Review = '&#9679;'; NeedsWork = '&#9650;'; Blocked = '&#10006;' }
$vLabel = @{ Ready = 'Ready'; Review = 'Review'; NeedsWork = 'Needs work'; Blocked = 'Blocked' }
$vDo    = @{ Ready = 'Deploy it.'; Review = 'Check one prerequisite, usually estate-wide.'; NeedsWork = 'Decide, or add the field it names.'; Blocked = 'Replace with a native Defender capability.' }
$iColor = @{ Blocking = '#d03b3b'; High = '#ec835a'; Medium = '#fab219' }

# Stacked verdict bar: flex segments, 2px gaps, direct labels where they fit.
$segments = ''
foreach ($v in $verdictOrder) {
    $n = $counts[$v]; if ($n -eq 0) { continue }
    $pct = [math]::Round($n * 100.0 / $total, 2)
    $label = if ($pct -ge 9) { "$($vLabel[$v]) $n" } else { $n }
    $segments += "<div class='seg' style='flex:$n 1 0;background:$($vColor[$v])' title='$($vLabel[$v]): $n rules ($(Pct $n))'>$label</div>"
}
$verdictBar = "<div class='vbar' role='img' aria-label='Verdict split'>$segments</div>"

# Tiles
$tiles = ($verdictOrder | ForEach-Object {
    $v = $_
    "<div class='tile' style='--c:$($vColor[$v])'><div class='tile-n'>$($counts[$v])</div><div class='tile-l'><span class='ic'>$($vIcon[$v])</span>$($vLabel[$v]) <span class='muted'>$(Pct $counts[$v])</span></div><div class='tile-d'>$(Esc $vDo[$v])</div></div>"
}) -join ''

# Blockers Pareto
$maxRules = [math]::Max(1, (($blockerRows | Measure-Object Rules -Maximum).Maximum))
$blockerHtml = ''
foreach ($impact in @('Blocking', 'High', 'Medium')) {
    $rows = @($blockerRows | Where-Object Impact -eq $impact)
    if ($rows.Count -eq 0) { continue }
    $heading = switch ($impact) {
        'Blocking' { 'Cannot migrate' }
        'High'     { 'Refused by the service, or behaves differently (Needs work)' }
        'Medium'   { 'Prerequisite or confirmation (Review)' }
    }
    $blockerHtml += "<h3 class='impact' style='--c:$($iColor[$impact])'>$heading</h3>"
    foreach ($row in $rows) {
        $w = [math]::Round(($row.Rules / $maxRules) * 100, 1)
        $flag = if ($row.InWindow) { "<span class='pill'>closes $($window.Date)</span>" } else { '' }
        $blockerHtml += @"
<details class='blk'>
  <summary>
    <span class='blk-label'>$(Esc $row.Summary) $flag</span>
    <span class='blk-bar'><span class='blk-fill' style='width:$w%;background:$($iColor[$impact])'></span></span>
    <span class='blk-n'>$($row.Rules) <span class='muted'>rule$(if ($row.Rules -ne 1) { 's' })</span></span>
  </summary>
  <p class='remedy'><strong>What to do:</strong> $(Esc $row.Remedy)</p>
</details>
"@
    }
}

# Estate prerequisites
$estateHtml = if ($estateRows.Count -eq 0) { "<p class='muted'>None.</p>" } else {
    ($estateRows | ForEach-Object {
        "<details class='blk'><summary><span class='blk-label'>$(Esc $_.Summary)</span><span class='blk-n'>$($_.Rules) <span class='muted'>rules wait on this</span></span></summary><p class='remedy'>$(Esc $_.Remedy)</p></details>"
    }) -join ''
}

# Data tiers
$tierHtml = (@('DefenderOnly', 'Mixed', 'SentinelOnly') | ForEach-Object {
    $n = $tierCounts[$_]
    $w = [math]::Round(($n / [math]::Max(1, $total)) * 100, 1)
    $note = switch ($_) {
        'DefenderOnly' { 'Native Defender tables. Fixed lookback, frequency 1H/3H/12H/24H.' }
        'Mixed'        { 'One Defender table forfeits custom frequency for the whole rule.' }
        'SentinelOnly' { 'Needs Sentinel data in the Defender portal. Keeps custom frequency.' }
    }
    "<div class='tier'><div class='tier-h'><span>$_</span><span>$n <span class='muted'>$(Pct $n)</span></span></div><div class='blk-bar'><span class='blk-fill' style='width:$w%;background:#5b7fb5'></span></div><div class='muted small'>$note</div></div>"
}) -join ''

# Per-rule table
$ruleHtml = ($ruleRows | ForEach-Object {
    $r = $_
    $why = if ($r.Findings.Count -eq 0) { "<span class='muted'>Converts cleanly.</span>" } else {
        "<ul class='why'>" + (($r.Findings | ForEach-Object {
            $tag = if ($_.EstateLevel) { " <span class='muted small'>(estate-wide)</span>" } else { '' }
            "<li><span class='dot' style='background:$($iColor[$_.Impact])'></span>$(Esc $_.Summary)$tag</li>"
        }) -join '') + '</ul>'
    }
    $detail = if ($r.Findings.Count -eq 0) { '' } else {
        "<details class='rule-detail'><summary>Why, and what to change</summary>" + (($r.Findings | ForEach-Object {
            "<div class='finding'><div class='f-h' style='--c:$($iColor[$_.Impact])'>$(Esc $_.Summary)</div><p class='small'>$(Esc $_.Reason)</p>" +
            $(if ($_.Remedy) { "<p class='small remedy'><strong>Fix:</strong> $(Esc $_.Remedy)</p>" } else { '' }) + '</div>'
        }) -join '') + '</details>'
    }
    $win = if ($r.InWindow) { "<span class='pill'>closes $($window.Date)</span>" } else { '' }
    @"
<tr class='row' data-verdict='$($r.Verdict)'>
  <td class='v'><span class='badge' style='--c:$($vColor[$r.Verdict])'><span class='ic'>$($vIcon[$r.Verdict])</span>$($vLabel[$r.Verdict])</span></td>
  <td class='name'><div>$(Esc $r.RuleName) $win</div><div class='muted small mono'>$(Esc $r.SourceFile) &middot; $(Esc $r.Kind) &middot; $(Esc $r.DataTier)</div></td>
  <td class='why-cell'>$why$detail</td>
</tr>
"@
}) -join ''

$filterButtons = "<button class='fb on' data-f='all'>All $total</button>" + (($verdictOrder | ForEach-Object {
    "<button class='fb' data-f='$_' style='--c:$($vColor[$_])'><span class='ic'>$($vIcon[$_])</span>$($vLabel[$_]) $($counts[$_])</button>"
}) -join '')

$deployable = $counts['Ready'] + $counts['Review']

$html = @"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>$(Esc $Title)</title>
<style>
  :root { --ink:#1b1b1a; --ink2:#4a4a48; --muted:#7a7a77; --line:#e4e4e0; --surface:#fcfcfb; --card:#ffffff; --accent:#5b7fb5; }
  * { box-sizing:border-box }
  body { margin:0; padding:32px 24px 64px; font:15px/1.5 -apple-system, "Segoe UI", system-ui, sans-serif; color:var(--ink); background:var(--surface) }
  main { max-width:1180px; margin:0 auto }
  h1 { font-size:28px; margin:0 0 4px; letter-spacing:-.01em }
  h2 { font-size:19px; margin:40px 0 12px }
  h3.impact { font-size:14px; text-transform:uppercase; letter-spacing:.06em; color:var(--ink2); margin:22px 0 8px; padding-left:12px; border-left:4px solid var(--c) }
  .muted { color:var(--muted) } .small { font-size:13px } .mono { font-family: ui-monospace, Menlo, monospace; font-size:12px }
  .meta { color:var(--muted); font-size:14px }
  .hero { display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr)); gap:12px; margin:24px 0 16px }
  .tile { background:var(--card); border:1px solid var(--line); border-top:4px solid var(--c); border-radius:8px; padding:14px 16px }
  .tile-n { font-size:40px; font-weight:700; line-height:1.05; letter-spacing:-.02em }
  .tile-l { font-weight:600; margin-top:4px } .tile-d { color:var(--muted); font-size:13px; margin-top:2px }
  .ic { display:inline-block; width:1.2em; color:var(--c) }
  .vbar { display:flex; gap:2px; height:44px; margin:4px 0 0 }
  .seg { display:flex; align-items:center; padding:0 10px; color:#fff; font-weight:600; font-size:15px; border-radius:4px; min-width:14px; overflow:hidden; white-space:nowrap }
  .headline { font-size:17px; margin:8px 0 0 }
  .headline b { font-weight:700 }
  .card { background:var(--card); border:1px solid var(--line); border-radius:8px; padding:18px 20px }
  .grid2 { display:grid; grid-template-columns:1fr 1fr; gap:16px } @media (max-width:800px){ .grid2{ grid-template-columns:1fr } }
  .callout { border-left:4px solid #d03b3b; background:#fff5f5; padding:12px 16px; border-radius:6px; margin:14px 0 }
  .blk { border-bottom:1px solid var(--line); padding:6px 0 } .blk:last-child { border-bottom:0 }
  .blk summary { display:grid; grid-template-columns:minmax(220px,2fr) 3fr 90px; gap:14px; align-items:center; cursor:pointer; list-style:none }
  .blk summary::-webkit-details-marker { display:none }
  .blk-label { font-size:14px } .blk-n { text-align:right; font-weight:600; white-space:nowrap }
  .blk-bar { display:block; height:14px; background:#f0f0ed; border-radius:4px; overflow:hidden }
  .blk-fill { display:block; height:100%; border-radius:4px }
  .remedy { margin:8px 0 6px; color:var(--ink2); font-size:14px }
  .pill { display:inline-block; font-size:11px; font-weight:600; color:#8a1f1f; background:#fde3e3; border-radius:999px; padding:1px 8px; margin-left:6px; vertical-align:middle; white-space:nowrap }
  .tier { margin:10px 0 } .tier-h { display:flex; justify-content:space-between; font-weight:600; margin-bottom:4px }
  .filters { display:flex; flex-wrap:wrap; gap:8px; margin:0 0 12px }
  .fb { --c:var(--ink2); font:inherit; font-size:14px; padding:6px 12px; border:1px solid var(--line); background:var(--card); border-radius:999px; cursor:pointer }
  .fb.on { border-color:var(--ink); background:var(--ink); color:#fff } .fb.on .ic { color:#fff }
  table { width:100%; border-collapse:collapse; background:var(--card); border:1px solid var(--line); border-radius:8px; overflow:hidden }
  th { text-align:left; font-size:12px; text-transform:uppercase; letter-spacing:.06em; color:var(--muted); padding:10px 12px; border-bottom:1px solid var(--line) }
  td { padding:12px; border-bottom:1px solid var(--line); vertical-align:top } tr:last-child td { border-bottom:0 }
  td.v { width:130px } td.name { width:34% }
  .badge { display:inline-block; font-weight:600; font-size:13px; color:var(--c); border:1px solid var(--c); border-radius:999px; padding:2px 10px; white-space:nowrap }
  ul.why { margin:0; padding:0; list-style:none } ul.why li { margin:0 0 3px } .dot { display:inline-block; width:9px; height:9px; border-radius:50%; margin-right:8px; vertical-align:middle }
  .rule-detail { margin-top:6px } .rule-detail summary { cursor:pointer; color:var(--accent); font-size:13px }
  .finding { margin:10px 0 0; padding:8px 12px; background:#fafaf8; border-radius:6px } .f-h { font-weight:600; font-size:14px; border-left:3px solid var(--c); padding-left:8px }
  .finding p { margin:6px 0 0 }
  footer { margin-top:48px; color:var(--muted); font-size:13px; border-top:1px solid var(--line); padding-top:14px }
  @media print { .filters{display:none} }
</style>
</head>
<body>
<main>
  <h1>$(Esc $Title)</h1>
  <div class="meta">$($total) analytics rules from <span class="mono">$(Esc $summary.Source)</span> &middot; assessed $(Esc $summary.GeneratedAt) in $($summary.ElapsedSeconds)s &middot; SentinelToXDR $moduleVersion</div>

  <div class="hero">$tiles</div>
  $verdictBar
  <p class="headline"><b>$deployable of $total</b> can be deployed as custom detections today ($(Pct $deployable)), <b>$($counts['Review'])</b> of them after one prerequisite check. <b>$($counts['NeedsWork'])</b> need a decision or a field added first. <b>$($counts['Blocked'])</b> cannot become a custom detection.</p>

  $(if ($windowRules.Count -gt 0) { "<div class='callout'><strong>$($windowRules.Count) rule$(if ($windowRules.Count -ne 1) {'s'}) can only migrate by way of a property Microsoft removes on $($window.Date).</strong> $(Esc $window.Detail)</div>" })

  <h2>What blocks the rest</h2>
  <div class="card">
    <p class="muted small" style="margin:0 0 6px">Counted per rule. A rule takes its worst finding as its verdict; the rest still apply. Click a row for what to change.</p>
    $blockerHtml
  </div>

  <div class="grid2">
    <div>
      <h2>Estate-wide prerequisites</h2>
      <div class="card"><p class="muted small" style="margin:0 0 6px">Checked once for the tenant, not per rule.</p>$estateHtml</div>
    </div>
    <div>
      <h2>Where the data lives</h2>
      <div class="card">$tierHtml</div>
    </div>
  </div>

  <h2>Every rule</h2>
  <div class="filters">$filterButtons</div>
  <table>
    <thead><tr><th>Verdict</th><th>Rule</th><th>Why</th></tr></thead>
    <tbody>$ruleHtml</tbody>
  </table>

  <footer>
    Verdicts, findings and remedies are computed by the SentinelToXDR PowerShell module (Test-XDRMigrationReadiness), from Microsoft's published parity documentation and eight custom detection API constraints observed on a live tenant. The KQL scans are heuristics over text; only Test-XDRDetectionQuery proves a query runs in a tenant. This page aggregates the module's output and adds nothing to it.
  </footer>
</main>
<script>
  document.querySelectorAll('.fb').forEach(function (b) {
    b.addEventListener('click', function () {
      document.querySelectorAll('.fb').forEach(function (x) { x.classList.remove('on'); });
      b.classList.add('on');
      var f = b.dataset.f;
      document.querySelectorAll('tr.row').forEach(function (r) { r.style.display = (f === 'all' || r.dataset.verdict === f) ? '' : 'none'; });
    });
  });
</script>
</body>
</html>
"@

$htmlPath = Join-Path -Path $OutputFolder -ChildPath 'assessment.html'
$html | Set-Content -LiteralPath $htmlPath -Encoding utf8

# ---------------------------------------------------------------------------
# 5. Console summary (what the skill reads back)
# ---------------------------------------------------------------------------
Write-Output ''
Write-Output "Assessed $total rules in $($summary.ElapsedSeconds)s (SentinelToXDR $moduleVersion)"
foreach ($v in $verdictOrder) { Write-Output ('  {0,-10} {1,4}  {2}' -f $v, $counts[$v], (Pct $counts[$v])) }
Write-Output "  In the $($window.Date) window: $($windowRules.Count)"
Write-Output ''
Write-Output 'Top blockers (rules affected):'
$blockerRows | Where-Object Impact -in 'Blocking', 'High' | Select-Object -First 6 | ForEach-Object { Write-Output ('  {0,3}  {1}' -f $_.Rules, $_.Summary) }
Write-Output ''
Write-Output "JSON: $((Resolve-Path $jsonPath).Path)"
Write-Output "HTML: $((Resolve-Path $htmlPath).Path)"
