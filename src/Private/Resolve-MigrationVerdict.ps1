function Resolve-MigrationVerdict {
    <#
    .SYNOPSIS
        Turns a rule's conversion diagnostics into a migration verdict.

    .DESCRIPTION
        The converter records what it did to a rule. This decides what that means for the
        person doing the migration, by classifying each diagnostic against the impact table
        in src/Data/MigrationReadiness.psd1 and taking the worst impact found.

        The classification lives in data because it is a judgement call, not a fact. Two
        diagnostics fire on nearly every rule (the ATT&CK coverage page not showing custom
        detections, and confirming technique ids are accepted). They are real, but they say
        nothing about any particular rule, so they are classified Low and never drive a
        verdict. Without that distinction every rule comes out amber and the report is
        worthless.

    .PARAMETER Diagnostics
        The diagnostic records from a conversion.

    .OUTPUTS
        PSCustomObject with Verdict, Score, Findings (classified), and per-impact counts.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter()]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]$Diagnostics
    )

    $readiness = Get-MigrationReadinessData

    # Classify one diagnostic: first matching rule wins, omitted fields match anything.
    function Get-DiagnosticImpact {
        param([object]$Diagnostic)

        foreach ($rule in $readiness.Rules) {
            if ($rule.Contains('Severity')   -and $Diagnostic.Severity   -ne $rule.Severity)   { continue }
            if ($rule.Contains('Action')     -and $Diagnostic.Action     -ne $rule.Action)     { continue }
            if ($rule.Contains('Capability') -and $Diagnostic.Capability -ne $rule.Capability) { continue }
            if ($rule.Contains('Feature')    -and $Diagnostic.Feature    -ne $rule.Feature)    { continue }
            # TargetValue is what separates one classification of the same capability from
            # another — a Mixed data tier costs the rule its custom frequency, a
            # Sentinel-only tier does not. Without this the two share one summary and the
            # interesting case reads like the routine one.
            if ($rule.Contains('TargetValue') -and $Diagnostic.TargetValue -ne $rule.TargetValue) { continue }
            return [PSCustomObject]@{
                Impact      = [string]$rule.Impact
                Summary     = [string]$rule.Summary
                Remedy      = [string]$rule.Remedy
                EstateLevel = [bool]$rule.EstateLevel
            }
        }
        return [PSCustomObject]@{ Impact = [string]$readiness.DefaultImpact; Summary = ''; Remedy = ''; EstateLevel = $false }
    }

    $findings = [System.Collections.Generic.List[object]]::new()
    $counts = [ordered]@{ Blocking = 0; High = 0; Medium = 0; Low = 0 }

    foreach ($diagnostic in @($Diagnostics)) {
        if ($null -eq $diagnostic) { continue }
        $classified = Get-DiagnosticImpact -Diagnostic $diagnostic
        if ($counts.Contains($classified.Impact)) { $counts[$classified.Impact]++ }

        $findings.Add([PSCustomObject]@{
            Impact     = $classified.Impact
            Summary    = if ($classified.Summary) { $classified.Summary } else { $diagnostic.Capability }
            Capability = $diagnostic.Capability
            Action     = $diagnostic.Action
            Severity   = $diagnostic.Severity
            Reason     = $diagnostic.Reason
            # What the migration actually asks of you. Reason says what happened to the
            # rule; Remedy says what to change to make it work in Defender XDR. The second
            # is the one someone doing a migration is reading for.
            Remedy     = [string]$classified.Remedy
            # A tenant-wide prerequisite, true for a whole class of rules at once. It still
            # counts toward the verdict — the rule genuinely cannot be deployed blind — but
            # a report that repeats it on every row buries the findings that differ.
            EstateLevel = [bool]$classified.EstateLevel
        })
    }

    # Worst impact present decides the verdict.
    $verdict = $readiness.Verdicts | Where-Object { $_.Trigger -and $counts[$_.Trigger] -gt 0 } | Select-Object -First 1
    if (-not $verdict) {
        $verdict = $readiness.Verdicts | Where-Object { -not $_.Trigger } | Select-Object -First 1
    }

    $weights = $readiness.ScoreWeights
    $score = [int]$weights.Start
    foreach ($impact in @('Blocking', 'High', 'Medium', 'Low')) {
        $score -= ($counts[$impact] * [int]$weights[$impact])
    }
    if ($score -lt 0) { $score = 0 }

    # What a human should actually read: the findings that drove the verdict.
    $headline = @($findings |
        Where-Object { $_.Impact -in 'Blocking', 'High', 'Medium' } |
        Select-Object -ExpandProperty Summary -Unique)

    [PSCustomObject]@{
        Verdict       = [string]$verdict.Name
        Description   = [string]$verdict.Description
        Score         = $score
        BlockingCount = $counts['Blocking']
        HighCount     = $counts['High']
        MediumCount   = $counts['Medium']
        LowCount      = $counts['Low']
        Headline      = $headline
        Findings      = $findings.ToArray()
    }
}
