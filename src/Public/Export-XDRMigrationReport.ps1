function Export-XDRMigrationReport {
    <#
    .SYNOPSIS
        Writes a migration readiness report from Test-XDRMigrationReadiness results.

    .DESCRIPTION
        Turns the per-rule verdicts into something you can hand to someone else:

          Csv       For the spreadsheet, and for diffing two assessments.
          Markdown  For the ticket or the pull request.
          Html      A single self-contained page. No external scripts, fonts or styles, so
                    it opens from a file share or an email attachment and still renders.

        The format is chosen from the file extension unless -Format says otherwise.

        Every report leads with the counts by verdict, because that is the number the person
        asking "how big is this migration" wants. The per-rule detail follows, worst first.

    .PARAMETER Result
        Readiness results from Test-XDRMigrationReadiness. Accepts pipeline input.

    .PARAMETER Path
        Output file. The extension picks the format: .csv, .md, .html.

    .PARAMETER Format
        Override the format implied by the extension.

    .PARAMETER Title
        Report heading. Defaults to a generic one.

    .PARAMETER PassThru
        Emit the results so the pipeline can continue.

    .EXAMPLE
        Test-XDRMigrationReadiness -Path ./rules -Recurse | Export-XDRMigrationReport -Path ./report.html

        The shareable version.

    .EXAMPLE
        Test-XDRMigrationReadiness -Path ./rules -Recurse |
            Export-XDRMigrationReport -Path ./report.csv -Title 'Contoso SOC migration'

        The spreadsheet version.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSObject]$Result,

        [Parameter(Mandatory, Position = 0)]
        [string]$Path,

        [Parameter()]
        [ValidateSet('Csv', 'Markdown', 'Html')]
        [string]$Format,

        [Parameter()]
        [string]$Title = 'Sentinel to Defender XDR migration readiness',

        [Parameter()]
        [switch]$PassThru,

        # The HTML report prints when it was generated. Two runs over the same input then
        # differ by that one line, which is exactly what a byte-comparison test cannot
        # tolerate. Pass a fixed value to make the output reproducible; the default is now.
        [Parameter()]
        [datetime]$GeneratedOn
    )

    begin {
        $results = [System.Collections.Generic.List[object]]::new()

        if (-not $Format) {
            $Format = switch ([System.IO.Path]::GetExtension($Path).ToLowerInvariant()) {
                '.csv'      { 'Csv' }
                '.md'       { 'Markdown' }
                '.markdown' { 'Markdown' }
                '.html'     { 'Html' }
                '.htm'      { 'Html' }
                default     { 'Html' }
            }
        }

        # Worst first: a report nobody scrolls should still show the problems.
        $verdictOrder = @{ 'Blocked' = 0; 'NeedsWork' = 1; 'Review' = 2; 'Ready' = 3 }

    }

    process {
        if ($null -ne $Result) { $results.Add($Result) }
    }

    end {
        if ($results.Count -eq 0) {
            Write-Warning 'No readiness results were supplied; nothing was written.'
            return
        }

        # Worst verdict, then lowest score, then — and this tiebreak earns its keep at
        # estate scale — the rules that have something rule-specific to say before the ones
        # waiting only on a tenant prerequisite. Both score the same (one Medium finding
        # each), so without this a rule that needs a human sorts below one that does not,
        # purely on alphabetical order.
        $sorted = $results.ToArray() | Sort-Object `
            @{ Expression = { $verdictOrder[[string]$_.Verdict] } }, `
            @{ Expression = { $_.Score } }, `
            @{ Expression = { -(@(Get-RuleSummary -Row $_).Count) } }, `
            @{ Expression = { $_.RuleName } }

        $summary = [ordered]@{}
        foreach ($name in @('Blocked', 'NeedsWork', 'Review', 'Ready')) {
            $summary[$name] = @($sorted | Where-Object { $_.Verdict -eq $name }).Count
        }
        $total = $sorted.Count

        if (-not $PSCmdlet.ShouldProcess($Path, "Write $Format migration readiness report")) {
            if ($PassThru) { $sorted }
            return
        }

        # After ShouldProcess, so -WhatIf leaves the disk untouched - folder included.
        $folder = Split-Path -Path $Path -Parent
        if ($folder -and -not (Test-Path -LiteralPath $folder)) {
            New-Item -ItemType Directory -Path $folder -Force | Out-Null
        }

        switch ($Format) {
            'Csv' {
                # Every free-text cell goes through the same guard: a rule name beginning
                # with '=' is a formula the moment the CSV is opened in a spreadsheet, and
                # rule names come from community content.
                $sorted |
                    Select-Object @{ Name = 'RuleName'; Expression = { ConvertTo-SafeReportText $_.RuleName -Format Csv } },
                        Verdict, Score,
                        @{ Name = 'Kind'; Expression = { ConvertTo-SafeReportText $_.Kind -Format Csv } },
                        DataTier,
                        @{ Name = 'Headline'; Expression = { ConvertTo-SafeReportText (($_.Headline) -join '; ') -Format Csv } },
                        @{ Name = 'Reasons'; Expression = { ConvertTo-SafeReportText ((Get-BlockingReason -Row $_) -join ' ') -Format Csv } },
                        @{ Name = 'ChangesRequired'; Expression = { ConvertTo-SafeReportText ((Get-RuleRemedy -Row $_) -join ' ') -Format Csv } },
                        BlockingCount, HighCount, MediumCount, LowCount,
                        @{ Name = 'Id'; Expression = { ConvertTo-SafeReportText $_.Id -Format Csv } },
                        @{ Name = 'SourcePath'; Expression = { ConvertTo-SafeReportText $_.SourcePath -Format Csv } } |
                    Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding utf8
            }

            'Markdown' {
                $lines = [System.Collections.Generic.List[string]]::new()
                $lines.Add("# $Title")
                $lines.Add('')
                $lines.Add("$total rule(s) assessed.")
                $lines.Add('')
                $lines.Add('| Verdict | Rules | Meaning |')
                $lines.Add('| --- | ---: | --- |')
                $lines.Add("| Ready | $($summary['Ready']) | Converts cleanly. Deploy it. |")
                $lines.Add("| Review | $($summary['Review']) | Behaves the same provided the prerequisites hold. |")
                $lines.Add("| NeedsWork | $($summary['NeedsWork']) | Converts, but behaves differently. Needs a decision. |")
                $lines.Add("| Blocked | $($summary['Blocked']) | Cannot become a custom detection. |")
                $lines.Add('')
                $deprecation = Get-DeprecationNote -Results $sorted
                if ($deprecation) {
                    $lines.Add("## Deadline: $($deprecation.Date)")
                    $lines.Add('')
                    $lines.Add("**$($deprecation.RuleCount) rule(s)** — $($deprecation.Summary)")
                    $lines.Add('')
                    $lines.Add($deprecation.Detail)
                    $lines.Add('')
                }

                $estateNotes = @(Get-EstateNote -Results $sorted)
                if ($estateNotes.Count -gt 0) {
                    $lines.Add('## Tenant prerequisites')
                    $lines.Add('')
                    $lines.Add('Checked once for the whole tenant, not per rule. Everything below is on top of these.')
                    $lines.Add('')
                    foreach ($note in $estateNotes) {
                        $lines.Add("- **$($note.RuleCount) rule(s)** — $($note.Summary)")
                    }
                    $lines.Add('')
                }

                $lines.Add('## Rules')
                $lines.Add('')
                $lines.Add('| Rule | Verdict | Data tier | What to know | Why | Changes required |')
                $lines.Add('| --- | --- | --- | --- | --- | --- |')
                foreach ($row in $sorted) {
                    # Pipes, newlines and angle brackets all break or hijack a table row.
                    $headline = ConvertTo-SafeReportText ((Get-RuleSummary -Row $row) -join '; ') -Format Markdown
                    $name = ConvertTo-SafeReportText $row.RuleName -Format Markdown
                    $why = ConvertTo-SafeReportText ((Get-BlockingReason -Row $row) -join ' ') -Format Markdown
                    $change = ConvertTo-SafeReportText ((Get-RuleRemedy -Row $row) -join ' ') -Format Markdown
                    $lines.Add("| $name | $($row.Verdict) | $($row.DataTier) | $headline | $why | $change |")
                }
                Set-Content -LiteralPath $Path -Value ($lines -join [Environment]::NewLine) -Encoding utf8NoBOM
            }

            'Html' {
                $stamp = if ($PSBoundParameters.ContainsKey('GeneratedOn')) { $GeneratedOn } else { Get-Date }
                Set-Content -LiteralPath $Path -Encoding utf8NoBOM -Value (
                    New-ReadinessReportHtml -Results $sorted -Summary $summary -Title $Title -GeneratedOn $stamp)
            }
        }

        Write-Verbose ("Export-XDRMigrationReport: $total rule(s) written to '$Path' " +
            "(Ready $($summary['Ready']), Review $($summary['Review']), " +
            "NeedsWork $($summary['NeedsWork']), Blocked $($summary['Blocked']))")

        if ($PassThru) { $sorted }
    }
}

# Three helpers, one rule between them: what the report SHOWS and what the report EXPLAINS
# must be the same set of findings. A bullet with no explanation sends the reader back to
# the tool; an explanation for a bullet that was hoisted out is just noise.

# What this rule needs that the next rule might not. Estate-level findings are excluded —
# they are reported once for the whole run, because a column repeating the same sentence on
# every row stops being read by the third one.
function Get-RuleSummary {
    param([PSObject]$Row)

    $findings = @($Row.Findings | Where-Object { $_.Impact -in 'Blocking', 'High', 'Medium' -and -not $_.EstateLevel })
    if ($findings.Count -gt 0) {
        return @($findings | Select-Object -ExpandProperty Summary -Unique)
    }
    # No Findings on the object (an older result, or a hand-built row): fall back to the
    # headline rather than showing nothing.
    if (-not $Row.PSObject.Properties['Findings']) { return @($Row.Headline) }
    return @()
}

# The Summary is a label — 'Cannot be migrated' — the right size for a column and useless as
# an answer. The Reason is the answer: which rule kind, which entity type, which dropped
# setting, and often what to do instead. Same filter as Get-RuleSummary, deliberately.
function Get-BlockingReason {
    param([PSObject]$Row)

    @($Row.Findings |
        Where-Object { $_.Impact -in 'Blocking', 'High', 'Medium' -and -not $_.EstateLevel } |
        ForEach-Object { [string]$_.Reason } |
        Where-Object { $_ } |
        Select-Object -Unique)
}

# What the migration asks of you for this rule. Get-BlockingReason says what happened;
# this says what to change. Deduplicated, because five findings can share one remedy.
function Get-RuleRemedy {
    param([PSObject]$Row)

    @($Row.Findings |
        Where-Object { $_.Impact -in 'Blocking', 'High', 'Medium' -and -not $_.EstateLevel } |
        ForEach-Object { [string]$_.Remedy } |
        Where-Object { $_ } |
        Select-Object -Unique)
}

# The tenant prerequisites: one line each, with the number of rules waiting on them.
function Get-EstateNote {
    param([object[]]$Results)

    $notes = @{}
    foreach ($row in $Results) {
        foreach ($finding in @($row.Findings | Where-Object { $_.EstateLevel })) {
            $key = [string]$finding.Summary
            if (-not $key) { continue }
            if (-not $notes.ContainsKey($key)) { $notes[$key] = 0 }
            $notes[$key]++
        }
    }
    $notes.GetEnumerator() | Sort-Object -Property Value -Descending |
        ForEach-Object { [PSCustomObject]@{ Summary = $_.Key; RuleCount = $_.Value } }
}


# The dated migration window. Two of the API's requirements name a deprecated property
# as the acceptable alternative, and both are removed on a date that is now weeks away -
# so for the rules below there is a deadline attached, which no per-rule remedy conveys
# as well as one line saying how many of them there are. Everything about it is data
# (MigrationReadiness.psd1, DeprecationWindow); nothing here knows a finding by name.
function Get-DeprecationNote {
    param([object[]]$Results)

    $window = (Get-MigrationReadinessData).DeprecationWindow
    if (-not $window -or -not $window.AppliesToSummaries) { return $null }

    $applies = @($window.AppliesToSummaries)
    $count = 0
    foreach ($row in $Results) {
        $hit = @($row.Findings | Where-Object { $_.Summary -in $applies })
        if ($hit.Count -gt 0) { $count++ }
    }
    if ($count -eq 0) { return $null }

    [PSCustomObject]@{
        Date      = [string]$window.Date
        Summary   = [string]$window.Summary
        Detail    = [string]$window.Detail
        RuleCount = $count
    }
}


function New-ReadinessReportHtml {
    <#
    .SYNOPSIS
        Renders readiness results as a single self-contained HTML page.

    .DESCRIPTION
        Everything is inline: no external stylesheet, script or font. The page has to render
        from a file share, an email attachment or a laptop with no network, which rules out
        a CDN. It also has to be readable on a projector, which drives the type size and the
        contrast.

        All rule-supplied text (names, reasons) is HTML-encoded. A community rule name can
        contain angle brackets, and a report that renders them is a report that can be made
        to lie.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [object[]]$Results,

        [Parameter(Mandatory)]
        [object]$Summary,

        [Parameter(Mandatory)]
        [string]$Title,

        [Parameter()]
        [datetime]$GeneratedOn = (Get-Date)
    )

    function ConvertTo-HtmlText {
        param([object]$Value)
        # HtmlEncode alone leaves bidirectional overrides in place; the shared helper
        # strips them first.
        return ConvertTo-SafeReportText $Value -Format Html
    }

    $total = $Results.Count
    $generated = $GeneratedOn.ToString('yyyy-MM-dd HH:mm')

    $verdictMeaning = @{
        'Ready'     = 'Converts cleanly. Deploy it.'
        'Review'    = 'Behaves the same, provided the prerequisites hold.'
        'NeedsWork' = 'Converts, but behaves differently. Needs a decision.'
        'Blocked'   = 'Cannot become a custom detection.'
    }

    $cards = foreach ($name in @('Ready', 'Review', 'NeedsWork', 'Blocked')) {
        $count = [int]$Summary[$name]
        $percent = if ($total -gt 0) { [Math]::Round(($count / $total) * 100) } else { 0 }
        @"
    <div class="card $($name.ToLower())">
      <div class="count">$count</div>
      <div class="label">$name</div>
      <div class="percent">$percent% of rules</div>
      <div class="meaning">$(ConvertTo-HtmlText $verdictMeaning[$name])</div>
    </div>
"@
    }

    # One panel, not one sentence per row. These are checked once for the tenant, and
    # seeing "12 rules" against a prerequisite is what makes it actionable — a column
    # repeating it 12 times is what makes it invisible.
    $deprecation = Get-DeprecationNote -Results $Results
    $deprecationBlock = if ($deprecation) {
        @"
  <div class="deadline">
    <h2>Deadline: $(ConvertTo-HtmlText $deprecation.Date)</h2>
    <p><strong>$($deprecation.RuleCount) rule(s)</strong> &mdash; $(ConvertTo-HtmlText $deprecation.Summary)</p>
    <p>$(ConvertTo-HtmlText $deprecation.Detail)</p>
  </div>
"@
    } else { '' }

    $estateNotes = @(Get-EstateNote -Results $Results)
    $estateBlock = if ($estateNotes.Count -gt 0) {
        $lines = ($estateNotes | ForEach-Object {
                "<li><strong>$($_.RuleCount) rule(s)</strong> &mdash; $(ConvertTo-HtmlText $_.Summary)</li>"
            }) -join ''
        @"
  <div class="estate">
    <h2>Tenant prerequisites</h2>
    <p>Checked once for the whole tenant, not per rule. Everything in the table below is on top of these.</p>
    <ul>$lines</ul>
  </div>
"@
    } else { '' }

    $rows = foreach ($row in $Results) {
        $summaries = @(Get-RuleSummary -Row $row)
        $items = if ($summaries.Count -gt 0) {
            '<ul>' + (($summaries | ForEach-Object { "<li>$(ConvertTo-HtmlText $_)</li>" }) -join '') + '</ul>'
        } elseif (@($row.Findings | Where-Object { $_.EstateLevel }).Count -gt 0) {
            # Nothing specific to THIS rule, but it is still waiting on the prerequisite
            # above. 'Nothing to review' here would read as 'ready to deploy'.
            '<span class="none">only the tenant prerequisite above</span>'
        } else {
            '<span class="none">nothing to review</span>'
        }

        # Blocked and High findings carry the actual explanation. Show it, so the report
        # answers "why" without the reader having to re-run the assessment.
        $reasons = @(Get-BlockingReason -Row $row)
        if ($reasons.Count -gt 0) {
            $items += '<div class="why">' +
                (($reasons | ForEach-Object { "<p>$(ConvertTo-HtmlText $_)</p>" }) -join '') + '</div>'
        }

        # The column someone planning a migration actually works from.
        $remedies = @(Get-RuleRemedy -Row $row)
        $changes = if ($remedies.Count -gt 0) {
            '<ul>' + (($remedies | ForEach-Object { "<li>$(ConvertTo-HtmlText $_)</li>" }) -join '') + '</ul>'
        } elseif (@($row.Findings | Where-Object { $_.EstateLevel }).Count -gt 0) {
            '<span class="none">nothing, once the prerequisite holds</span>'
        } else {
            '<span class="none">none</span>'
        }
        @"
      <tr class="$($row.Verdict.ToLower())">
        <td class="rule">$(ConvertTo-HtmlText $row.RuleName)</td>
        <td><span class="pill $($row.Verdict.ToLower())">$(ConvertTo-HtmlText $row.Verdict)</span></td>
        <td class="tier">$(ConvertTo-HtmlText $row.DataTier)</td>
        <td class="what">$items</td>
        <td class="change">$changes</td>
      </tr>
"@
    }

    @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>$(ConvertTo-HtmlText $Title)</title>
<style>
  :root {
    --ready: #1a7f37; --review: #9a6700; --needswork: #bc4c00; --blocked: #cf222e;
    --ink: #1f2328; --muted: #656d76; --line: #d1d9e0; --bg: #ffffff; --panel: #f6f8fa;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --ready: #3fb950; --review: #d29922; --needswork: #db6d28; --blocked: #f85149;
      --ink: #e6edf3; --muted: #8d96a0; --line: #30363d; --bg: #0d1117; --panel: #161b22;
    }
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; padding: 2rem 1.5rem; background: var(--bg); color: var(--ink);
    font: 16px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
  }
  .wrap { max-width: 1200px; margin: 0 auto; }
  h1 { font-size: 1.75rem; margin: 0 0 .25rem; letter-spacing: -0.01em; }
  .sub { color: var(--muted); margin: 0 0 2rem; font-size: .95rem; }
  .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); gap: 1rem; margin-bottom: 2.5rem; }
  .card { background: var(--panel); border: 1px solid var(--line); border-radius: 10px; padding: 1.25rem; border-top: 4px solid var(--muted); }
  .card.ready { border-top-color: var(--ready); }
  .card.review { border-top-color: var(--review); }
  .card.needswork { border-top-color: var(--needswork); }
  .card.blocked { border-top-color: var(--blocked); }
  .count { font-size: 2.5rem; font-weight: 650; line-height: 1; letter-spacing: -0.02em; }
  .card.ready .count { color: var(--ready); }
  .card.review .count { color: var(--review); }
  .card.needswork .count { color: var(--needswork); }
  .card.blocked .count { color: var(--blocked); }
  .label { font-weight: 600; margin-top: .4rem; }
  .percent { color: var(--muted); font-size: .85rem; }
  .meaning { color: var(--muted); font-size: .85rem; margin-top: .6rem; }
  .tablewrap { overflow-x: auto; border: 1px solid var(--line); border-radius: 10px; }
  table { border-collapse: collapse; width: 100%; min-width: 780px; }
  th { text-align: left; padding: .75rem 1rem; background: var(--panel); border-bottom: 1px solid var(--line); font-size: .8rem; text-transform: uppercase; letter-spacing: .04em; color: var(--muted); }
  td { padding: .8rem 1rem; border-bottom: 1px solid var(--line); vertical-align: top; }
  tr:last-child td { border-bottom: 0; }
  .rule { font-weight: 550; max-width: 24rem; }
  .tier { color: var(--muted); font-size: .9rem; white-space: nowrap; }
  .pill { display: inline-block; padding: .15rem .6rem; border-radius: 999px; font-size: .8rem; font-weight: 600; color: #fff; white-space: nowrap; }
  .pill.ready { background: var(--ready); }
  .pill.review { background: var(--review); }
  .pill.needswork { background: var(--needswork); }
  .pill.blocked { background: var(--blocked); }
  .what ul { margin: 0; padding-left: 1.1rem; }
  .what li { margin: .1rem 0; }
  .deadline { background: var(--panel); border: 1px solid var(--line); border-left: 4px solid var(--needswork);
            border-radius: 10px; padding: 1rem 1.25rem; margin-bottom: 1.25rem; }
  .deadline h2 { font-size: 1.05rem; margin: 0 0 .3rem; }
  .deadline p { margin: 0 0 .6rem; font-size: .9rem; }
  .deadline p:last-child { margin-bottom: 0; color: var(--muted); font-size: .88rem; }
  .estate { background: var(--panel); border: 1px solid var(--line); border-left: 4px solid var(--review);
            border-radius: 10px; padding: 1rem 1.25rem; margin-bottom: 2rem; }
  .estate h2 { font-size: 1.05rem; margin: 0 0 .3rem; }
  .estate p { margin: 0 0 .6rem; color: var(--muted); font-size: .88rem; }
  .estate ul { margin: 0; padding-left: 1.1rem; }
  .estate li { margin: .2rem 0; font-size: .92rem; }
  .change ul { margin: 0; padding-left: 1.1rem; }
  .change li { margin: .15rem 0; font-size: .92rem; }
  .change { border-left: 3px solid var(--review); }
  .why { margin: .45rem 0 0; padding-left: .7rem; border-left: 2px solid var(--line); }
  .why p { margin: .3rem 0; font-size: .86rem; color: var(--muted); }
  .none { color: var(--muted); font-style: italic; }
  footer { margin-top: 2rem; color: var(--muted); font-size: .85rem; }
  footer code { background: var(--panel); padding: .1rem .35rem; border-radius: 4px; }
</style>
</head>
<body>
<div class="wrap">
  <h1>$(ConvertTo-HtmlText $Title)</h1>
  <p class="sub">$total rule(s) assessed &middot; generated $generated</p>

  <div class="cards">
$($cards -join "`n")
  </div>

$deprecationBlock
$estateBlock

  <div class="tablewrap">
    <table>
      <thead>
        <tr><th>Rule</th><th>Verdict</th><th>Data tier</th><th>What to know</th><th>Changes required</th></tr>
      </thead>
      <tbody>
$($rows -join "`n")
      </tbody>
    </table>
  </div>

  <footer>
    Generated by <code>SentinelToXDR</code>. Verdicts come from the conversion diagnostics,
    classified in <code>src/Data/MigrationReadiness.psd1</code> &mdash; edit that file if you
    disagree with how a finding is weighted.
  </footer>
</div>
</body>
</html>
"@
}
