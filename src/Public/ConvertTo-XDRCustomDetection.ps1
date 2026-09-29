function ConvertTo-XDRCustomDetection {
    <#
    .SYNOPSIS
        Converts Microsoft Sentinel analytics rules to Microsoft Defender XDR custom detections.

    .DESCRIPTION
        Takes Sentinel analytics rules from any supported source and produces custom
        detections in the shape the target accepts, with a structured diagnostic for every
        mapping decision the conversion had to make.

        Input can be a file (community YAML, ARM resource, ARM deployment template, REST
        response), a rule object from Get-SentinelAnalyticsRule, or any parsed rule object.
        A single file may contain many rules; every rule in it is converted.

        Output shape is selected with -Format:

          Graph          (default) microsoft.graph.security.detectionRule, the shape
                         POST /security/rules/detectionRules accepts. Carries the full
                         tactics collection, typed entity mappings and an ISO 8601
                         schedule frequency. This is what Deploy/New-XDRCustomDetection
                         sends and what Export-XDRCustomDetection writes.

          XDRConverter   The legacy flat YAML shape (guid, ruleName, alertTitle,
                         alertCategory, frequency enum, impactedEntities) used by the
                         XDRConverter module. Retained for existing pipelines. It cannot
                         express multiple tactics or typed entity columns, and it uses
                         properties Microsoft removes on 2026-10-01.

        Serialization is selected with -As: Yaml (default), Json, or Object. The Object
        form carries the rule, its diagnostics and the source rule together, which is what
        you want when assessing an estate rather than emitting files.

        Rules that cannot become a custom detection at all (Fusion, MLBehaviorAnalytics,
        ThreatIntelligence, MicrosoftSecurityIncidentCreation, Anomaly, or any rule with no
        query) produce a Blocking diagnostic and no output object. They are reported, never
        silently converted into an empty detection.

    .PARAMETER InputFile
        Path to a Sentinel analytics rule file (.yaml, .yml, .json).

    .PARAMETER InputObject
        A rule object: either one from Get-SentinelAnalyticsRule or a raw parsed rule.
        Accepts pipeline input.

    .PARAMETER Format
        Output rule shape: Graph (default) or XDRConverter.

    .PARAMETER As
        Serialization: Yaml (default), Json, or Object.

    .PARAMETER OutputFile
        Write the serialized detection to this path instead of the pipeline. Only valid
        when the input yields a single rule.

    .PARAMETER UseDisplayNameAsFilename
        Name output files after the rule display name (sanitized to CamelCase).

    .PARAMETER UseIdAsFilename
        Name output files after the rule GUID.

    .PARAMETER OutputFolder
        Folder for output files when using a naming switch. Defaults to the temp directory.

    .PARAMETER AlertTitle
        Override the alert title. Sentinel rules have no separate alert title, so the rule
        name is used by default.

    .PARAMETER AlertCategory
        Override the single alertCategory. Only meaningful for -Format XDRConverter; the
        Graph shape carries every tactic and needs no category choice.

    .PARAMETER RecommendedAction
        Text for the Graph alertTemplate.recommendedActions field. Sentinel has no
        equivalent, so it is only set when supplied.

    .PARAMETER Guid
        Override the rule id.

    .PARAMETER Enabled
        Override whether the detection is turned on.

    .PARAMETER Severity
        Override the alert severity.

    .PARAMETER Force
        Suppress interactive confirmation prompts. Warnings are still emitted.

    .PARAMETER SuggestRemediationActions
        Emit the informational note that custom detections support native remediation
        actions. Off by default; nothing is ever fabricated in the output.

    .PARAMETER WriteReport
        Also write a companion .report.json and .report.md next to the output file.

    .PARAMETER WriteBatchSummary
        Aggregate diagnostics across every rule processed in this invocation into one
        summary. Requires -BatchSummaryPath.

    .PARAMETER BatchSummaryPath
        Base path for the aggregated batch summary.

    .EXAMPLE
        ConvertTo-XDRCustomDetection -InputFile ./MyRule.yaml

        Converts one rule and writes the Graph detection YAML to the pipeline.

    .EXAMPLE
        Get-SentinelAnalyticsRule -Path ./Solutions -Recurse |
            ConvertTo-XDRCustomDetection -As Object -Force -WarningAction SilentlyContinue

        Converts a whole content tree, keeping the diagnostics with each rule.

    .EXAMPLE
        ConvertTo-XDRCustomDetection -InputFile ./MyRule.yaml -As Json |
            Set-Content ./MyRule.json

        Produces a deploy-ready Graph payload.

    .EXAMPLE
        Get-SentinelAnalyticsRule -Path ./rules | ConvertTo-XDRCustomDetection -As Object -Force |
            New-XDRCustomDetection -WhatIf

        Full pipeline: read, convert, and preview the deployment.
    #>
    [CmdletBinding(DefaultParameterSetName = 'File', SupportsShouldProcess)]
    [OutputType([string], [PSCustomObject])]
    param(
        [Parameter(Mandatory, ParameterSetName = 'File', HelpMessage = 'Path to the Sentinel rule file (.yaml, .yml, or .json)')]
        [Parameter(Mandatory, ParameterSetName = 'FileByDisplayName', HelpMessage = 'Path to the Sentinel rule file (.yaml, .yml, or .json)')]
        [Parameter(Mandatory, ParameterSetName = 'FileById', HelpMessage = 'Path to the Sentinel rule file (.yaml, .yml, or .json)')]
        [ValidateScript({
            if (-not (Test-Path -LiteralPath $_ -PathType Leaf)) {
                throw "InputFile '$_' was not found or is not a file. Provide a path to a Sentinel rule file (.yaml, .yml, or .json)."
            }
            $true
        })]
        [string]$InputFile,

        [Parameter(Mandatory, ParameterSetName = 'Object', ValueFromPipeline, HelpMessage = 'Parsed Sentinel rule object')]
        [Parameter(Mandatory, ParameterSetName = 'ObjectByDisplayName', ValueFromPipeline, HelpMessage = 'Parsed Sentinel rule object')]
        [Parameter(Mandatory, ParameterSetName = 'ObjectById', ValueFromPipeline, HelpMessage = 'Parsed Sentinel rule object')]
        [ValidateNotNull()]
        [PSObject]$InputObject,

        [Parameter(HelpMessage = 'Output rule shape: Graph (default) or XDRConverter')]
        [ValidateSet('Graph', 'XDRConverter')]
        [string]$Format = 'Graph',

        [Parameter(HelpMessage = 'Serialization: Yaml (default), Json, or Object')]
        [ValidateSet('Yaml', 'Json', 'Object')]
        [string]$As = 'Yaml',

        [Parameter(ParameterSetName = 'File', HelpMessage = 'Path to the output file')]
        [Parameter(ParameterSetName = 'Object', HelpMessage = 'Path to the output file')]
        [string]$OutputFile,

        [Parameter(Mandatory, ParameterSetName = 'ObjectByDisplayName', HelpMessage = 'Use the display name as the output filename')]
        [Parameter(Mandatory, ParameterSetName = 'FileByDisplayName', HelpMessage = 'Use the display name as the output filename')]
        [switch]$UseDisplayNameAsFilename,

        [Parameter(Mandatory, ParameterSetName = 'ObjectById', HelpMessage = 'Use the rule GUID as the output filename')]
        [Parameter(Mandatory, ParameterSetName = 'FileById', HelpMessage = 'Use the rule GUID as the output filename')]
        [switch]$UseIdAsFilename,

        [Parameter(ParameterSetName = 'ObjectByDisplayName', HelpMessage = 'Folder to write output files')]
        [Parameter(ParameterSetName = 'ObjectById', HelpMessage = 'Folder to write output files')]
        [Parameter(ParameterSetName = 'FileByDisplayName', HelpMessage = 'Folder to write output files')]
        [Parameter(ParameterSetName = 'FileById', HelpMessage = 'Folder to write output files')]
        [string]$OutputFolder,

        [Parameter(HelpMessage = 'Override the alert title (Sentinel rules have no separate alertTitle)')]
        [string]$AlertTitle,

        [Parameter(HelpMessage = 'Override the alertCategory (XDRConverter format only)')]
        [ValidateSet(
            'CredentialAccess', 'DefenseEvasion', 'Discovery', 'Execution', 'Exfiltration',
            'Impact', 'InitialAccess', 'LateralMovement', 'Persistence', 'PrivilegeEscalation',
            'Collection', 'CommandAndControl', 'SuspiciousActivity'
        )]
        [string]$AlertCategory,

        [Parameter(HelpMessage = 'Text for the Graph alertTemplate.recommendedActions field')]
        [string]$RecommendedAction,

        [Parameter(HelpMessage = 'Override the rule id')]
        [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
        [string]$Guid,

        [Parameter(HelpMessage = 'Override whether the detection is turned on')]
        [bool]$Enabled,

        [Parameter(HelpMessage = 'Override the alert severity')]
        [ValidateSet('Informational', 'Low', 'Medium', 'High')]
        [string]$Severity,

        [Parameter(HelpMessage = 'Suppress interactive confirmation prompts for mapping gaps')]
        [switch]$Force,

        [Parameter(HelpMessage = 'Surface the native Defender XDR remediation-actions enrichment-opportunity diagnostic. Off by default.')]
        [switch]$SuggestRemediationActions,

        [Parameter(HelpMessage = 'Also write a companion <output>.report.json and .report.md describing the conversion diagnostics.')]
        [switch]$WriteReport,

        [Parameter(HelpMessage = 'Accumulate diagnostics across every rule processed in this invocation and write one aggregated batch summary. Requires -BatchSummaryPath.')]
        [switch]$WriteBatchSummary,

        [Parameter(HelpMessage = 'Base path for the aggregated batch summary written when -WriteBatchSummary is set.')]
        [string]$BatchSummaryPath
    )

    begin {
        # Ids seen so far in this batch. Two source rules with the same id would deploy as
        # one detection and a 409, and nothing said so; the second one is flagged here.
        $seenRuleIds = [System.Collections.Generic.Dictionary[string,string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        # Output paths already claimed in this batch, so two rules whose names CamelCase to
        # the same string do not overwrite each other (Export-XDRCustomDetection had this
        # guard; this path did not).
        $claimedTargets = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        # Tactic->category map for the pre-conversion ShouldContinue check. Only the
        # XDRConverter shape has to collapse tactics to one category, so only that path
        # prompts; the Graph shape carries them all.
        $tacticToCategory = @{
            'Collection'              = 'Collection'
            'CommandAndControl'       = 'CommandAndControl'
            'CredentialAccess'        = 'CredentialAccess'
            'DefenseEvasion'          = 'DefenseEvasion'
            'Discovery'               = 'Discovery'
            'Execution'               = 'Execution'
            'Exfiltration'            = 'Exfiltration'
            'Impact'                  = 'Impact'
            'InitialAccess'           = 'InitialAccess'
            'LateralMovement'         = 'LateralMovement'
            'Persistence'             = 'Persistence'
            'PrivilegeEscalation'     = 'PrivilegeEscalation'
            'PreAttack'               = 'SuspiciousActivity'
            'Reconnaissance'          = 'SuspiciousActivity'
            'ResourceDevelopment'     = 'SuspiciousActivity'
            'ImpairProcessControl'    = 'SuspiciousActivity'
            'InhibitResponseFunction' = 'SuspiciousActivity'
        }

        if ($WriteBatchSummary -and -not $BatchSummaryPath) {
            Write-Warning '-WriteBatchSummary was specified without -BatchSummaryPath; no batch summary will be written.'
        }

        # Resolve output paths to file-system paths once, here. The writers below mix
        # provider cmdlets with [System.IO.Path] calls, and on Windows a PowerShell drive
        # path (TestDrive:\out, or any New-PSDrive) lost its drive on the way and was
        # written to the root of the current disk: 'TestDrive:\GuidOut' became
        # 'D:\GuidOut' on the CI runner. A resolved path means the same thing to both.
        # A relative path resolves against the PowerShell location, as it did before.
        $resolvePath = { param($p) $PSCmdlet.SessionState.Path.GetUnresolvedProviderPathFromPSPath($p) }
        if ($OutputFile)       { $OutputFile       = & $resolvePath $OutputFile }
        if ($OutputFolder)     { $OutputFolder     = & $resolvePath $OutputFolder }
        if ($BatchSummaryPath) { $BatchSummaryPath = & $resolvePath $BatchSummaryPath }

        $batchResults = [System.Collections.Generic.List[object]]::new()
    }

    process {
        # ------------------------------------------------------------------
        # 1. Resolve the input into one or more (normalized rule, raw rule) pairs.
        #    A single file can hold many rules, so everything below loops.
        # ------------------------------------------------------------------
        $normalizedRules = @(
            if ($PSCmdlet.ParameterSetName -like 'File*') {
                Import-SentinelRuleFile -Path $InputFile
            } elseif ($InputObject.PSObject.TypeNames -contains 'SentinelToXDR.SentinelRule') {
                $InputObject
            } else {
                ConvertTo-NormalizedSentinelRule -InputObject $InputObject -SourceFormat 'Object'
            }
        )

        if ($normalizedRules.Count -eq 0) { return }

        if ($normalizedRules.Count -gt 1 -and $OutputFile) {
            Write-Warning ("The input yielded $($normalizedRules.Count) rules but a single -OutputFile was given; " +
                "only the last rule would survive. Use -UseIdAsFilename or -UseDisplayNameAsFilename with " +
                "-OutputFolder instead. No files were written.")
            return
        }

        foreach ($rule in $normalizedRules) {
            try {
                $ruleLabel = if ($rule.DisplayName) { $rule.DisplayName } else { '<unnamed rule>' }

                # ----------------------------------------------------------
                # 2. Blocking gates. A rule that cannot become a custom detection
                #    produces a Blocking diagnostic and NO output object.
                # ----------------------------------------------------------
                $kindInfo = Get-SentinelRuleKind -Kind $rule.Kind
                $blockingDiagnostics = [System.Collections.Generic.List[object]]::new()

                if (-not $kindInfo.Convertible) {
                    $kindData = Get-SentinelRuleKind
                    $record = New-ConversionDiagnostic -Feature $kindData.NonConvertible.Feature `
                        -Capability $kindData.NonConvertible.Capability `
                        -Severity $kindData.NonConvertible.Severity -Action $kindData.NonConvertible.Action `
                        -SourceValue $rule.Kind -TargetValue $null `
                        -Reason ("Rule '$ruleLabel' is a '$($kindInfo.Kind)' rule and cannot be converted to a " +
                        "Defender XDR custom detection. $($kindInfo.Reason)") `
                        -DocReference 'https://learn.microsoft.com/rest/api/securityinsights/alert-rules'
                    $blockingDiagnostics.Add($record)
                    Write-Warning $record.Reason
                }
                elseif ([string]::IsNullOrWhiteSpace($rule.Query)) {
                    $record = New-ConversionDiagnostic -Feature 'Rule data' -Capability 'Sentinel analytics tier' `
                        -Severity 'Blocking' -Action 'Unsupported' -SourceValue $null -TargetValue $null `
                        -Reason ("Rule '$ruleLabel' has no KQL query. A custom detection is defined by its query, " +
                        "so there is nothing to convert. Check whether the source file is a stub or a pointer to " +
                        "content that moved.") `
                        -DocReference 'https://learn.microsoft.com/defender-xdr/custom-detection-rules'
                    $blockingDiagnostics.Add($record)
                    Write-Warning $record.Reason
                }

                if ($blockingDiagnostics.Count -gt 0) {
                    if ($WriteBatchSummary -and $BatchSummaryPath) {
                        $batchResults.Add([PSCustomObject]@{
                            RuleName    = [string]$ruleLabel
                            Guid        = [string]$rule.Id
                            Diagnostics = $blockingDiagnostics.ToArray()
                        })
                    }
                    if ($As -eq 'Object') {
                        [PSCustomObject]@{
                            PSTypeName  = 'SentinelToXDR.CustomDetection'
                            RuleName    = [string]$ruleLabel
                            Id          = [string]$rule.Id
                            Format      = $Format
                            Rule        = $null
                            Diagnostics = $blockingDiagnostics.ToArray()
                            Blocked     = $true
                            SourceRule  = $rule
                        }
                    }
                    continue
                }

                # ----------------------------------------------------------
                # 3. Multiple tactics need a single category ONLY in the legacy
                #    shape. Confirm interactively there, stay quiet for Graph.
                # ----------------------------------------------------------
                if ($Format -eq 'XDRConverter' -and -not $PSBoundParameters.ContainsKey('AlertCategory') -and
                    $rule.Tactics.Count -gt 1) {

                    $autoCategory = $null
                    foreach ($tactic in $rule.Tactics) {
                        if ($tacticToCategory.ContainsKey($tactic)) { $autoCategory = $tacticToCategory[$tactic]; break }
                    }
                    if (-not $autoCategory) { $autoCategory = 'SuspiciousActivity' }

                    $caption = 'Multiple Tactics Detected — Mapping Gap'
                    $message = (
                        "Rule '$ruleLabel' has $($rule.Tactics.Count) tactics: [$($rule.Tactics -join ', ')]. " +
                        "The XDRConverter shape supports only one alertCategory. " +
                        "'$autoCategory' will be used (first mappable tactic). " +
                        "Use -AlertCategory to specify a different one explicitly, or -Format Graph to keep every tactic."
                    )

                    if (-not $Force -and -not $PSCmdlet.ShouldContinue($message, $caption)) {
                        Write-Verbose "Conversion of '$ruleLabel' aborted by user."
                        continue
                    }
                }

                # ----------------------------------------------------------
                # 4. Run the decision engine.
                # ----------------------------------------------------------
                $convertParams = @{ SentinelObject = $rule.RawRule }

                if ($PSBoundParameters.ContainsKey('Enabled'))       { $convertParams['SetEnabled']            = $Enabled }
                if ($PSBoundParameters.ContainsKey('Severity'))      { $convertParams['SetSeverity']           = $Severity }
                if ($PSBoundParameters.ContainsKey('AlertTitle'))    { $convertParams['OverrideAlertTitle']    = $AlertTitle }
                if ($PSBoundParameters.ContainsKey('AlertCategory')) { $convertParams['OverrideAlertCategory'] = $AlertCategory }
                if ($PSBoundParameters.ContainsKey('Guid')) {
                    $convertParams['OverrideGuid'] = $Guid
                } elseif ($rule.Id) {
                    # The normalizer recovers ids the raw rule hides — a GUID inside an ARM
                    # [concat()] name expression, resolved against the template parameters.
                    # Pass it in, or the converter sees no id on the raw object, warns that
                    # it generated one, and every ARM-sourced rule carries a false finding.
                    $convertParams['OverrideGuid'] = $rule.Id
                }

                # Same reason for durations: the normalizer turns a .NET TimeSpan string or
                # a serialized TimeSpan object into ISO 8601. Without passing those through,
                # the converter cannot parse the raw value and quietly schedules the rule
                # hourly instead of every six hours.
                if ($rule.QueryFrequency) { $convertParams['OverrideQueryFrequency'] = $rule.QueryFrequency }
                if ($rule.QueryPeriod)    { $convertParams['OverrideQueryPeriod']    = $rule.QueryPeriod }
                if ($SuggestRemediationActions)                      { $convertParams['SuggestRemediationActions'] = $true }

                $diagnostics = [System.Collections.Generic.List[object]]::new()
                $decision    = $null
                $convertParams['DiagnosticsRef'] = [ref]$diagnostics
                $convertParams['DecisionRef']    = [ref]$decision
                if ($Format -eq 'Graph') { $convertParams['GraphShape'] = $true }

                $legacyObject = ConvertFrom-SentinelToCustomDetection @convertParams

                # The normalized rule carries values the raw shape can hide (a GUID
                # recovered from an ARM [concat()] name, an ISO duration recovered from a
                # serialized TimeSpan). Prefer them when the engine found nothing.
                if ($rule.Id -and -not $PSBoundParameters.ContainsKey('Guid')) {
                    $decision['Guid'] = $rule.Id
                    $legacyObject['guid'] = $rule.Id
                }
                if ($rule.EntityMappings.Count -gt 0) { $decision['EntityMappings'] = $rule.EntityMappings }

                $finalId = [string]$decision['Guid']
                if ($finalId) {
                    if ($seenRuleIds.ContainsKey($finalId)) {
                        $duplicate = New-ConversionDiagnostic -Feature 'Rules management' -Capability 'Manage rules from API' `
                            -Severity 'Warning' -Action 'RequiresReview' -SourceValue $finalId -TargetValue 'DuplicateId' `
                            -Reason ("Rule '$ruleLabel' has id '$finalId', which '$($seenRuleIds[$finalId])' in this batch already uses. " +
                            'Deploying both would create one detection and fail the other with a conflict.')
                        $diagnostics.Add($duplicate)
                        Write-Warning $duplicate.Reason
                    } else {
                        $seenRuleIds[$finalId] = $ruleLabel
                    }
                }

                # ----------------------------------------------------------
                # 5. Render the requested shape.
                # ----------------------------------------------------------
                $ruleObject = if ($Format -eq 'Graph') {
                    ConvertTo-GraphDetectionRule -Decision $decision -DiagnosticSink $diagnostics -RecommendedAction $RecommendedAction
                } else {
                    $legacyObject
                }

                # ----------------------------------------------------------
                # 6. Resolve an output path when a naming switch was used.
                # ----------------------------------------------------------
                $targetFile = $OutputFile
                if ($UseDisplayNameAsFilename -or $UseIdAsFilename) {
                    $folder = if ($OutputFolder) { $OutputFolder } else { [System.IO.Path]::GetTempPath() }
                    # Under -WhatIf nothing may touch the disk, the output folder included.
                    if (-not (Test-Path -LiteralPath $folder) -and $PSCmdlet.ShouldProcess($folder, 'Create output folder')) {
                        New-Item -ItemType Directory -Path $folder -Force | Out-Null
                    }
                    $extension = if ($As -eq 'Json') { 'json' } else { 'yaml' }
                    if ($UseDisplayNameAsFilename) {
                        $safeName = ConvertTo-SafeFileName -Name ([string]$decision['DisplayName']) -Fallback ([string]$decision['Guid'])
                        $targetFile = Join-Path $folder "$safeName.$extension"
                    } else {
                        $targetFile = Join-Path $folder "$($decision['Guid']).$extension"
                    }
                    # Two rules in one batch can resolve to the same file name. Suffix the
                    # later one rather than overwrite the earlier one silently.
                    $candidateTarget = $targetFile
                    $suffix = 1
                    while (-not $claimedTargets.Add($candidateTarget)) {
                        $suffix++
                        $candidateTarget = Join-Path $folder ("{0}-{1}.{2}" -f [System.IO.Path]::GetFileNameWithoutExtension($targetFile), $suffix, $extension)
                    }
                    if ($candidateTarget -ne $targetFile) {
                        Write-Verbose "Output file '$targetFile' was already claimed in this batch; writing '$candidateTarget' instead."
                        $targetFile = $candidateTarget
                    }
                }

                # ----------------------------------------------------------
                # 7. Emit.
                # ----------------------------------------------------------
                if ($As -eq 'Object') {
                    $detection = [PSCustomObject]@{
                        PSTypeName  = 'SentinelToXDR.CustomDetection'
                        RuleName    = [string]$decision['DisplayName']
                        Id          = [string]$decision['Guid']
                        Format      = $Format
                        Rule        = $ruleObject
                        Diagnostics = $diagnostics.ToArray()
                        Blocked     = $false
                        SourceRule  = $rule
                    }
                    if ($targetFile) {
                        Write-SentinelRuleOutput -Content (ConvertTo-DetectionText -Rule $ruleObject -As 'Yaml') -OutputFile $targetFile
                    }
                    $detection
                } else {
                    $text = ConvertTo-DetectionText -Rule $ruleObject -As $As
                    Write-SentinelRuleOutput -Content $text -OutputFile $targetFile
                }

                # ----------------------------------------------------------
                # 8. Companion report and batch accumulation.
                # ----------------------------------------------------------
                if ($WriteReport) {
                    if ($targetFile) {
                        Write-ConversionReport -Diagnostics $diagnostics.ToArray() -BasePath $targetFile
                    } else {
                        Write-Warning '-WriteReport was specified but no output file path is available; skipping report (reports require an output file).'
                    }
                }

                if ($WriteBatchSummary -and $BatchSummaryPath) {
                    $batchResults.Add([PSCustomObject]@{
                        RuleName    = [string]$decision['DisplayName']
                        Guid        = [string]$decision['Guid']
                        Diagnostics = $diagnostics.ToArray()
                    })
                }

            } catch {
                # A rule that throws mid-conversion must still come out the other end.
                # Before this, the catch wrote an error and emitted nothing, so the rule
                # disappeared from -As Object, from Test-XDRMigrationReadiness, from every
                # report and every count - the arithmetic invariant in docs/Validation.md
                # broken with only a non-terminating error to show for it. It is reported
                # as Blocked, carrying the exception, because a rule the converter cannot
                # process is one nobody can deploy until the cause is fixed.
                Write-Error "Error converting Sentinel rule '$($rule.DisplayName)' to an XDR custom detection: $_"
                $failure = New-ConversionDiagnostic -Feature 'Rule conversion' -Capability 'Converter' `
                    -Severity 'Blocking' -Action 'Unsupported' -SourceValue $null -TargetValue 'ConversionFailed' `
                    -Reason ("Rule '$ruleLabel' could not be converted: $($_.Exception.Message) " +
                    "This is a converter failure on this input, not a property of the rule. Report it with the source file.")
                if ($WriteBatchSummary -and $BatchSummaryPath) {
                    $batchResults.Add([PSCustomObject]@{ RuleName = [string]$ruleLabel; Guid = [string]$rule.Id; Diagnostics = @($failure) })
                }
                if ($As -eq 'Object') {
                    [PSCustomObject]@{
                        PSTypeName  = 'SentinelToXDR.CustomDetection'
                        RuleName    = [string]$ruleLabel
                        Id          = [string]$rule.Id
                        Format      = $Format
                        Rule        = $null
                        Diagnostics = @($failure)
                        Blocked     = $true
                        SourceRule  = $rule
                    }
                }
            }
        }
    }

    end {
        if ($WriteBatchSummary -and $BatchSummaryPath) {
            Write-ConversionBatchSummary -Results $batchResults.ToArray() -BasePath $BatchSummaryPath
        }
    }
}
