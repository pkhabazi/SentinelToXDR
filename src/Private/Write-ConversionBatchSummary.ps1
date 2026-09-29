function Get-ConversionBatchAggregate {
    <#
    .SYNOPSIS
        Aggregates per-rule conversion diagnostics across a batch into stable totals.

    .DESCRIPTION
        Pure, side-effect-free summarizer. Takes a collection of per-rule result
        records (each: RuleName, Guid, Diagnostics[]) and returns an ordered
        aggregate object with:
          - TotalRules / RulesWithGaps / TotalDiagnostics
          - ByAction      : Action  -> count   (only actions seen; sorted count desc, name asc)
          - BySeverity    : Severity-> count
          - ByCapability  : 'Feature :: Capability' -> count
          - PerRule[]     : one record per rule with per-Action counts + NeedsAttention flag

        Determinism: every grouping is sorted by count descending, then key ascending,
        so the output is byte-stable for a given input regardless of hashtable order.

        A rule "needs attention" when it has any Dropped / Unsupported / RequiresReview
        diagnostic (the actions that imply manual follow-up).

    .PARAMETER Results
        Collection of per-rule records. Each must expose RuleName, Guid and a
        Diagnostics collection (each diagnostic having Action / Severity / Feature /
        Capability). May be empty.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Results
    )

    # Actions that flag a rule for manual review.
    $attentionActions = @('Dropped', 'Unsupported', 'RequiresReview')

    $byAction     = @{}
    $bySeverity   = @{}
    $byCapability = @{}
    $perRule      = [System.Collections.Generic.List[object]]::new()
    $totalDiagnostics = 0
    $rulesWithGaps    = 0

    foreach ($r in $Results) {
        $diags = @($r.Diagnostics)
        $totalDiagnostics += $diags.Count
        if ($diags.Count -gt 0) { $rulesWithGaps++ }

        # Per-rule per-action counts (all six known actions, so the table is uniform).
        $ruleActions = [ordered]@{
            Dropped        = 0
            Unsupported    = 0
            RequiresReview = 0
            Constrained    = 0
            Rounded        = 0
            Mapped         = 0
        }

        foreach ($d in $diags) {
            $action = [string]$d.Action
            $sev    = [string]$d.Severity
            $feat   = [string]$d.Feature
            $capRaw = [string]$d.Capability
            # Join with ' :: ' only when BOTH parts are present; otherwise use the
            # non-empty part alone so we never produce a leading/trailing separator.
            if ($feat -and $capRaw) { $cap = "$feat :: $capRaw" }
            elseif ($feat)          { $cap = $feat }
            else                    { $cap = $capRaw }

            if ($byAction.ContainsKey($action))   { $byAction[$action]++ }   else { $byAction[$action] = 1 }
            if ($bySeverity.ContainsKey($sev))     { $bySeverity[$sev]++ }     else { $bySeverity[$sev] = 1 }
            if ($byCapability.ContainsKey($cap))   { $byCapability[$cap]++ }   else { $byCapability[$cap] = 1 }

            if ($ruleActions.Contains($action)) { $ruleActions[$action]++ }
        }

        $needsAttention = [bool]($diags | Where-Object { $_.Action -in $attentionActions })

        $perRule.Add([PSCustomObject][ordered]@{
            RuleName       = [string]$r.RuleName
            Guid           = [string]$r.Guid
            Total          = $diags.Count
            Dropped        = $ruleActions['Dropped']
            Unsupported    = $ruleActions['Unsupported']
            RequiresReview = $ruleActions['RequiresReview']
            Constrained    = $ruleActions['Constrained']
            Rounded        = $ruleActions['Rounded']
            Mapped         = $ruleActions['Mapped']
            NeedsAttention = $needsAttention
        })
    }

    # Deterministic sort helper: count desc, then key asc.
    $sortMap = {
        param($map)
        $ordered = [ordered]@{}
        $map.GetEnumerator() |
            Sort-Object @{ Expression = { $_.Value }; Descending = $true }, @{ Expression = { $_.Key }; Descending = $false } |
            ForEach-Object { $ordered[$_.Key] = $_.Value }
        $ordered
    }

    [PSCustomObject][ordered]@{
        TotalRules       = @($Results).Count
        RulesWithGaps    = $rulesWithGaps
        TotalDiagnostics = $totalDiagnostics
        ByAction         = (& $sortMap $byAction)
        BySeverity       = (& $sortMap $bySeverity)
        ByCapability     = (& $sortMap $byCapability)
        PerRule          = $perRule.ToArray()
    }
}

function Write-ConversionBatchSummary {
    <#
    .SYNOPSIS
        Writes a single aggregated batch summary (JSON + Markdown) across many converted rules.

    .DESCRIPTION
        Given a collection of per-rule result records (RuleName, Guid, Diagnostics[])
        accumulated across one conversion run and a base path, writes:
          <base>.summary.json — machine-readable totals: total rules, rules-with-gaps,
                                counts by Action / Severity / Feature::Capability, plus a
                                per-rule index (ruleName/guid -> counts by Action).
          <base>.summary.md   — human-readable: a headline, an Action table, a
                                Feature/Capability table, a Severity breakdown, and a
                                per-rule table; rules needing manual attention are flagged.

        Opt-in; callers only invoke it when batch reporting is requested.

        DETERMINISM: no timestamp is emitted by default (mirrors Write-ConversionReport,
        which writes no timestamp, so reports are byte-stable / testable). A timestamp can
        be supplied explicitly via -GeneratedFor for non-test callers; when omitted the
        metadata block carries a $null generatedFor and all aggregations are sorted
        deterministically (count desc, then name asc).

    .PARAMETER Results
        Collection of per-rule records (RuleName, Guid, Diagnostics). May be empty.

    .PARAMETER BasePath
        Base path; '.summary.json' / '.summary.md' are appended after stripping any
        existing extension.

    .PARAMETER GeneratedFor
        Optional, injectable label for the metadata block (e.g. a timestamp or run id).
        Omitted by default to keep output deterministic for tests.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Results,

        [Parameter(Mandatory)]
        [string]$BasePath,

        [Parameter()]
        [AllowNull()]
        [string]$GeneratedFor = $null
    )

    # Strip the trailing extension so '<base>.yaml' becomes '<base>.summary.json' / '.md'.
    $directory = [System.IO.Path]::GetDirectoryName($BasePath)
    $stem      = [System.IO.Path]::GetFileNameWithoutExtension($BasePath)
    $base      = if ($directory) { Join-Path $directory $stem } else { $stem }

    $jsonPath = "$base.summary.json"
    $mdPath   = "$base.summary.md"

    $agg = Get-ConversionBatchAggregate -Results $Results

    # ---- JSON summary -------------------------------------------------------
    $jsonObj = [ordered]@{
        metadata = [ordered]@{
            generatedFor     = $GeneratedFor
            totalRules       = $agg.TotalRules
            rulesWithGaps    = $agg.RulesWithGaps
            totalDiagnostics = $agg.TotalDiagnostics
        }
        byAction     = $agg.ByAction
        bySeverity   = $agg.BySeverity
        byCapability = $agg.ByCapability
        perRule      = $agg.PerRule
    }
    $json = ConvertTo-Json -InputObject $jsonObj -Depth 6
    if ($PSCmdlet.ShouldProcess($jsonPath, 'Write batch summary (JSON)')) {
        Set-Content -LiteralPath $jsonPath -Value $json -Encoding utf8NoBOM
        Write-Verbose "Batch summary written to: $jsonPath"
    }

    # ---- Markdown summary ---------------------------------------------------
    # Escape pipe / newline in free-text cells (mirrors Write-ConversionReport).
    $esc = { param($v) if ($null -ne $v) { ([string]$v) -replace '\r?\n', ' ' -replace '\|', '\|' } else { '' } }

    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add('# Conversion batch summary')
    $lines.Add('')
    $lines.Add("$($agg.TotalRules) rule(s) converted, $($agg.RulesWithGaps) with gaps, $($agg.TotalDiagnostics) total diagnostic(s).")
    $lines.Add('')

    # The dated window, on the surface a plain conversion run produces. Someone who
    # never exports a readiness report would otherwise only meet this date buried in a
    # per-rule remedy, and it is the one finding here with a deadline attached.
    $window = (Get-MigrationReadinessData).DeprecationWindow
    if ($window -and $window.AppliesToConstraints) {
        $applies = @($window.AppliesToConstraints)
        $affected = @($Results | Where-Object {
                @($_.Diagnostics | Where-Object { $_.TargetValue -in $applies }).Count -gt 0
            }).Count
        if ($affected -gt 0) {
            $lines.Add("> **Deadline $($window.Date).** $affected rule(s) $($window.Summary -replace '^Rules that ', '')")
            $lines.Add('>')
            $lines.Add("> $($window.Detail)")
            $lines.Add('')
        }
    }

    # Action breakdown.
    $lines.Add('## Diagnostics by action')
    $lines.Add('')
    $lines.Add('| Action | Count |')
    $lines.Add('| --- | --- |')
    if ($agg.ByAction.Count -eq 0) {
        $lines.Add('| (none) | 0 |')
    } else {
        foreach ($k in $agg.ByAction.Keys) { $lines.Add("| $k | $($agg.ByAction[$k]) |") }
    }
    $lines.Add('')

    # Feature/Capability breakdown.
    $lines.Add('## Diagnostics by feature / capability')
    $lines.Add('')
    $lines.Add('| Feature :: Capability | Count |')
    $lines.Add('| --- | --- |')
    if ($agg.ByCapability.Count -eq 0) {
        $lines.Add('| (none) | 0 |')
    } else {
        foreach ($k in $agg.ByCapability.Keys) { $lines.Add("| $(& $esc $k) | $($agg.ByCapability[$k]) |") }
    }
    $lines.Add('')

    # Severity breakdown.
    $lines.Add('## Diagnostics by severity')
    $lines.Add('')
    $lines.Add('| Severity | Count |')
    $lines.Add('| --- | --- |')
    if ($agg.BySeverity.Count -eq 0) {
        $lines.Add('| (none) | 0 |')
    } else {
        foreach ($k in $agg.BySeverity.Keys) { $lines.Add("| $k | $($agg.BySeverity[$k]) |") }
    }
    $lines.Add('')

    # Per-rule index.
    $lines.Add('## Per-rule breakdown')
    $lines.Add('')
    $lines.Add('| Rule | GUID | Dropped | Unsupported | RequiresReview | Constrained | Rounded | Mapped | Needs attention |')
    $lines.Add('| --- | --- | --- | --- | --- | --- | --- | --- | --- |')
    foreach ($p in $agg.PerRule) {
        $attn = if ($p.NeedsAttention) { 'YES' } else { '' }
        $lines.Add("| $(& $esc $p.RuleName) | $(& $esc $p.Guid) | $($p.Dropped) | $($p.Unsupported) | $($p.RequiresReview) | $($p.Constrained) | $($p.Rounded) | $($p.Mapped) | $attn |")
    }

    $markdown = $lines -join [System.Environment]::NewLine
    if ($PSCmdlet.ShouldProcess($mdPath, 'Write batch summary (Markdown)')) {
        Set-Content -LiteralPath $mdPath -Value $markdown -Encoding utf8NoBOM
        Write-Verbose "Batch summary written to: $mdPath"
    }
}
