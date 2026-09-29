function ConvertTo-GraphDetectionRule {
    <#
    .SYNOPSIS
        Renders resolved conversion decisions into a Graph detectionRule object.

    .DESCRIPTION
        Builds the microsoft.graph.security.detectionRule shape that
        POST /security/rules/detectionRules accepts:

            id, displayName, description, status,
            queryCondition { queryText },
            schedule { frequency },
            detectionAction { alertTemplate { title, description, severity,
                                              recommendedActions, tactics[],
                                              entityMappings{}, customDetails{} } }

        The decisions (guid, severity, frequency, title, techniques, custom details) come
        from ConvertFrom-SentinelToCustomDetection, so this function does no rule
        interpretation of its own beyond shaping. Entity mappings and tactics are resolved
        here because their Graph representation is structurally different from the legacy
        one, not merely renamed.

        Deprecated properties are never emitted. Microsoft removes isEnabled, detectorId,
        schedule.period, alertTemplate.category, alertTemplate.mitreTechniques,
        alertTemplate.impactedAssets and detectionAction.responseActions on 2026-10-01;
        the deprecation list is data in src/Data/GraphDetectionRule.psd1.

    .PARAMETER Decision
        The decisions hashtable produced by ConvertFrom-SentinelToCustomDetection -DecisionRef.

    .PARAMETER DiagnosticSink
        A List[object] the function appends its own diagnostics to.

    .PARAMETER RecommendedAction
        Optional text for alertTemplate.recommendedActions. Sentinel analytics rules have
        no equivalent field, so it is only set when the caller supplies one.

    .OUTPUTS
        An ordered hashtable ready to serialize as JSON or YAML.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Decision,

        [Parameter()]
        [AllowNull()]
        [object]$DiagnosticSink,

        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$RecommendedAction
    )

    $map = Get-GraphDetectionRuleMap

    # ---- status --------------------------------------------------------------
    $status = if ($Decision.IsEnabled) { $map.Status.WhenEnabled } else { $map.Status.WhenDisabled }

    # ---- severity ------------------------------------------------------------
    # Graph uses lower-case severity values; Sentinel uses Title Case.
    $sourceSeverity = [string]$Decision.Severity
    $severity = $null
    foreach ($key in $map.Severity.Keys) {
        if ($key -ieq $sourceSeverity) { $severity = $map.Severity[$key]; break }
    }
    if (-not $severity) {
        $severity = $map.Severity['Medium']
        if ($null -ne $DiagnosticSink) {
            $record = New-ConversionDiagnostic -Feature 'Alert enrichment' -Capability 'Enrich alerts with custom details' `
                -Severity 'Warning' -Action 'RequiresReview' -SourceValue $sourceSeverity -TargetValue $severity `
                -Reason ("Rule '$($Decision.DisplayName)' has severity '$sourceSeverity', which is not one of the " +
                "Defender XDR alert severities (informational, low, medium, high). Defaulted to '$severity'.") `
                -DocReference 'https://learn.microsoft.com/graph/api/resources/security-alerttemplate?view=graph-rest-beta'
            $DiagnosticSink.Add($record)
            Write-Warning $record.Reason
        }
    }

    # ---- schedule ------------------------------------------------------------
    # schedule.frequency is an ISO 8601 Duration. The '0/1H/3H/12H/24H' enum is the
    # deprecated schedule.period and is never emitted.
    $schedule = [ordered]@{ frequency = [string]$Decision.FrequencyIso }

    # ---- alert template ------------------------------------------------------
    $alertTemplate = [ordered]@{
        title       = [string]$Decision.AlertTitle
        description = [string]$Decision.Description
        severity    = $severity
    }

    if (-not [string]::IsNullOrWhiteSpace($RecommendedAction)) {
        $alertTemplate['recommendedActions'] = $RecommendedAction
    }

    # Watermark the sink so the required-field check below can see which constraint
    # findings THIS rule raised, without depending on the sink being per-rule.
    $sinkMark = if ($null -ne $DiagnosticSink) { $DiagnosticSink.Count } else { 0 }

    $tactics = Resolve-GraphTactic -Tactics @($Decision.Tactics) -Techniques @($Decision.Techniques) `
        -RuleName ([string]$Decision.DisplayName) -DiagnosticSink $DiagnosticSink
    # Re-wrap with @(): PowerShell unrolls a single-element array returned from a
    # function, and a lone hashtable serializes as a YAML mapping instead of a
    # one-item sequence, which the API rejects.
    if ($tactics) { $alertTemplate['tactics'] = @($tactics) }

    $entityMappings = Resolve-GraphEntityMapping -EntityMappings @($Decision.EntityMappings) `
        -RuleName ([string]$Decision.DisplayName) -DiagnosticSink $DiagnosticSink
    if ($entityMappings -and $entityMappings.Count -gt 0) { $alertTemplate['entityMappings'] = $entityMappings }

    # customDetails is an open type: a flat map of detail name -> query column.
    if ($null -ne $Decision.CustomDetails -and $Decision.CustomDetails.Keys.Count -gt 0) {
        $customDetails = [ordered]@{}
        foreach ($key in $Decision.CustomDetails.Keys) {
            $customDetails[[string]$key] = [string]$Decision.CustomDetails[$key]
        }
        $alertTemplate['customDetails'] = $customDetails
    }

    # ---- what the service requires, as opposed to what it documents ----------
    # Constraints 3 and 4: tactics-or-category and entityMappings-or-impactedAssets.
    # Both alternatives are deprecated and removed on 2026-10-01, and this module
    # never emits either, so for its output these are hard requirements.
    #
    # A rule can reach here having converted perfectly, validated against
    # CustomDetection.schema.json and run cleanly in advanced hunting, and still be
    # refused on deployment. Saying so now, with the field to add, is the whole
    # reason 1.0.0 waited. Driven entirely from RequiredAlertTemplateFields so that
    # a lifted requirement is a data edit.
    $raised = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    if ($null -ne $DiagnosticSink) {
        for ($i = $sinkMark; $i -lt $DiagnosticSink.Count; $i++) {
            $raised.Add([string]$DiagnosticSink[$i].TargetValue) | Out-Null
        }
    }

    foreach ($required in $map.RequiredAlertTemplateFields) {
        $field = [string]$required.Field
        if ($alertTemplate.Contains($field)) { continue }

        $supersededBy = [string]$required.SupersededBy
        if ($supersededBy -and $raised.Contains($supersededBy)) { continue }

        New-ApiConstraintDiagnostic -Constraint ([string]$required.Constraint) -Action 'Unsupported' `
            -SourceValue $null -DiagnosticSink $DiagnosticSink `
            -Reason ("Rule '$($Decision.DisplayName)' produced no $field, and the custom detection API " +
            "requires it ('$($required.Error)'). $($required.SourceRuleFix) The only alternative the " +
            "service accepts is the deprecated $($required.DeprecatedAlternative) property, which is " +
            "removed on $($required.AlternativeRemovalDate) and which this module never emits.") | Out-Null
    }

    # Constraint 7: at least one ASSET entity, or an IP, across the whole mapping. A rule
    # mapping only a file, a URL or a registry value is refused however well-formed those
    # mappings are. Unlike the per-entity identifier check this is a property of the
    # entityMappings object as a whole, so it belongs here rather than in the resolver.
    # Only meaningful when there ARE mappings - with none, constraint 4 has already fired
    # and saying it twice helps nobody.
    $requiredKinds = $map.RequiredEntityKinds
    if ($requiredKinds -and $alertTemplate.Contains('entityMappings')) {
        $present = @($alertTemplate['entityMappings'].Keys)
        $asset = @($present | Where-Object { $_ -in @($requiredKinds.Collections) })
        if ($asset.Count -eq 0) {
            New-ApiConstraintDiagnostic -Constraint ([string]$requiredKinds.Constraint) -Action 'Unsupported' `
                -SourceValue ($present -join ', ') -DiagnosticSink $DiagnosticSink `
                -Reason ("Rule '$($Decision.DisplayName)' maps only [$($present -join ', ')], and the custom " +
                "detection API requires at least one asset entity or an IP ('$($requiredKinds.Error)'). " +
                [string]$requiredKinds.SourceRuleFix) | Out-Null
        }
    }

    # The service refuses an id that does not begin with a letter (RuleIdPolicy in the
    # data file, observed 2026-09-16), which is most GUIDs. Keep an acceptable id as-is so
    # a re-run maps to the same detection; otherwise prefix and sanitise, and say so.
    $ruleId = [string]$Decision.Guid
    $policy = $map.RuleIdPolicy
    if ($policy -and $ruleId -and $ruleId -notmatch $policy.Pattern) {
        $sanitised = [regex]::Replace($ruleId, '[^A-Za-z0-9_-]', '-')
        $candidate = [string]$policy.Prefix + $sanitised
        if ($candidate.Length -gt [int]$policy.MaxLength) { $candidate = $candidate.Substring(0, [int]$policy.MaxLength) }
        if ($null -ne $DiagnosticSink) {
            $DiagnosticSink.Add((New-ConversionDiagnostic -Feature 'Rules management' -Capability 'Manage rules from API' `
                -Severity 'Info' -Action 'Mapped' -SourceValue $ruleId -TargetValue ([string]$policy.Constraint) `
                -Reason ("The custom detection id is '$candidate': the service requires a rule id that begins with a letter " +
                "(letters, digits, dashes, underscores, at most $($policy.MaxLength) characters), and the source id '$ruleId' " +
                'does not. The mapping is deterministic, so a re-run updates the same detection.') `
                -DocReference 'docs/API-Constraints.md'))
        }
        $ruleId = $candidate
    }

    [ordered]@{
        id             = $ruleId
        displayName    = [string]$Decision.DisplayName
        description    = [string]$Decision.Description
        status         = $status
        queryCondition = [ordered]@{ queryText = [string]$Decision.QueryText }
        schedule       = $schedule
        detectionAction = [ordered]@{ alertTemplate = $alertTemplate }
    }
}
