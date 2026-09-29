function Resolve-GraphTactic {
    <#
    .SYNOPSIS
        Builds the Graph alertTemplate.tactics collection from Sentinel tactics and techniques.

    .DESCRIPTION
        The Graph model carries a COLLECTION of tactics, each holding its own techniques:

            tactics:
              - tactic: Execution
                techniques:
                  - technique: T1059.001

        The service accepts exactly ONE entry in that collection, and that entry must carry
        at least one technique. Neither limit is documented; both were found by POSTing a
        rule to a live tenant and reading the 400. They are recorded, with their provenance
        and the exact service error text, as TacticConstraints in
        src/Data/GraphDetectionRule.psd1, so lifting either one is a data edit.

        This function was originally built to the modelled shape and carried every tactic.
        It models a collection; it does not accept one. The module's own capability data had
        said so all along - 'Link multiple MITRE tactics' is State = Planned in
        CustomDetectionCapabilities.psd1 - and was overridden on the strength of the model.

        More mappable tactics than the limit allows: the first in source order is kept and
        the rest are dropped, reported as TacticsTruncated. The rule still deploys and still
        detects the same activity; what is lost is ATT&CK breadth on the alert.

        A tactic carrying NO techniques is emitted as it stands, with an empty techniques
        collection, because that is what the service accepts and stores. Between 2026-08-19
        and 2026-09-15 it did not: a bare tactic was refused, so the tactic had to be
        dropped and the rule reported as needing a relevantTechniques entry. Probing on
        2026-09-15 showed the requirement gone, and continuing to drop the tactic would now
        throw away ATT&CK data the service would have taken. See TacticConstraints.

        Sentinel keeps tactics and techniques as two flat, unrelated lists, with nothing
        saying which technique belongs to which tactic. Rather than invent an association,
        the full technique list is attached to the tactic that is kept.

        Tactic name mapping comes from src/Data/GraphDetectionRule.psd1.

    .PARAMETER Tactics
        Sentinel tactic names.

    .PARAMETER Techniques
        Validated MITRE technique IDs (parents and subtechniques).

    .PARAMETER RuleName
        Rule display name, used in diagnostic text.

    .PARAMETER DiagnosticSink
        A List[object] the function appends conversion diagnostics to.

    .OUTPUTS
        An array holding a single ordered hashtable shaped as a Graph mitreTactic object,
        or $null when no acceptable tactics payload could be built.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        [AllowEmptyCollection()]
        [string[]]$Tactics,

        [Parameter()]
        [AllowNull()]
        [AllowEmptyCollection()]
        [string[]]$Techniques,

        [Parameter()]
        [string]$RuleName = '',

        [Parameter()]
        [AllowNull()]
        [object]$DiagnosticSink
    )

    $map = Get-GraphDetectionRuleMap
    $tacticMap = $map.Tactics
    $constraints = $map.TacticConstraints
    $docRef = 'https://learn.microsoft.com/graph/api/resources/security-mitretactic?view=graph-rest-beta'

    function Add-TacticDiagnostic {
        param([string]$Severity, [string]$Action, [object]$SourceValue, [object]$TargetValue, [string]$Reason)
        if ($null -eq $DiagnosticSink) { return }
        $record = New-ConversionDiagnostic -Feature 'Alert enrichment' -Capability 'Link multiple MITRE tactics' `
            -Severity $Severity -Action $Action -SourceValue $SourceValue -TargetValue $TargetValue `
            -Reason $Reason -DocReference $docRef
        $DiagnosticSink.Add($record)
        Write-Warning $record.Reason
    }

    $sourceTactics = @($Tactics | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $techniqueList = @($Techniques | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })

    if ($sourceTactics.Count -eq 0 -and $techniqueList.Count -eq 0) { return $null }

    $mapped = [System.Collections.Generic.List[string]]::new()
    $unmapped = [System.Collections.Generic.List[string]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($tactic in $sourceTactics) {
        if (-not $tacticMap.ContainsKey($tactic)) {
            $unmapped.Add($tactic)
            continue
        }
        $graphTactic = $tacticMap[$tactic]
        if ([string]::IsNullOrWhiteSpace($graphTactic)) {
            $unmapped.Add($tactic)
            continue
        }
        # Two Sentinel tactics can map onto one Graph tactic (ImpairProcessControl and
        # InhibitResponseFunction both land on Impact). Emit each Graph tactic once.
        if ($seen.Add($graphTactic)) { $mapped.Add($graphTactic) }
    }

    if ($unmapped.Count -gt 0) {
        Add-TacticDiagnostic -Severity 'Warning' -Action 'Dropped' -SourceValue ($unmapped -join ', ') -TargetValue $null `
            -Reason ("Rule '$RuleName' has $($unmapped.Count) MITRE tactic(s) [$($unmapped -join ', ')] with no " +
            "Defender XDR equivalent. They were dropped from the tactics collection.")
    }

    if ($mapped.Count -eq 0) {
        if ($techniqueList.Count -eq 0) { return $null }
        # Techniques with no tactic to hang them off cannot be expressed: the Graph model
        # nests techniques inside a tactic.
        Add-TacticDiagnostic -Severity 'Warning' -Action 'Dropped' -SourceValue ($techniqueList -join ', ') -TargetValue $null `
            -Reason ("Rule '$RuleName' has $($techniqueList.Count) MITRE technique(s) but no mappable tactic. " +
            "The Graph model nests techniques inside a tactic, so the techniques could not be carried. " +
            "Add a tactic to the source rule to keep them.")
        return $null
    }

    # Constraint 1. Keep the first tactics in source order up to the documented limit; the
    # limit is data so that a future increase needs no code change. The full technique list
    # goes on every tactic kept, because constraint 2 applies to each of them and Sentinel
    # does not record which technique belongs to which tactic.
    $maxTactics = [int]$constraints.MaxTactics
    $kept = @($mapped | Select-Object -First $maxTactics)

    if ($mapped.Count -gt $maxTactics) {
        $lost = @($mapped | Select-Object -Skip $maxTactics)
        New-ApiConstraintDiagnostic -Constraint 'TacticsTruncated' -Action 'Constrained' `
            -SourceValue ($mapped -join ', ') -DiagnosticSink $DiagnosticSink `
            -Reason ("Rule '$RuleName' maps to $($mapped.Count) MITRE tactics but the custom detection API " +
            "accepts $maxTactics ('$($constraints.MaxTacticsError)'). Kept [$($kept -join ', ')]; dropped " +
            "[$($lost -join ', ')]. The detection still fires on the same activity - what is lost is the " +
            "ATT&CK breadth recorded on the alert.") | Out-Null
    }

    # A mitreTechnique is one parent plus its subtechniques, per the Graph model. Emitting
    # each subtechnique as a technique of its own is what the service quietly normalised on
    # 2026-08-24 - and what got mistaken for the service discarding data. Build the
    # documented shape directly, so what is sent is what is stored.
    $shape = $map.TechniqueShape
    $parents = [System.Collections.Generic.List[string]]::new()
    $subsByParent = @{}
    foreach ($technique in $techniqueList) {
        $parent = if ($technique -match $shape.SubtechniquePattern) { $Matches[1] } else { $technique }
        if (-not $subsByParent.ContainsKey($parent)) {
            $parents.Add($parent)
            $subsByParent[$parent] = [System.Collections.Generic.List[string]]::new()
        }
        if ($parent -ne $technique -and -not $subsByParent[$parent].Contains($technique)) {
            $subsByParent[$parent].Add($technique)
        }
    }

    # An empty subTechniques collection is emitted rather than omitted: the service stores
    # it as empty, and a round trip that compares sent against stored should see no drift.
    $techniqueObjects = @(foreach ($parent in $parents) {
            [ordered]@{ technique = $parent; subTechniques = @($subsByParent[$parent]) }
        })

    $result = [System.Collections.Generic.List[object]]::new()
    foreach ($tactic in $kept) {
        $result.Add([ordered]@{
                tactic     = $tactic
                techniques = $techniqueObjects
            })
    }

    return @($result)
}
