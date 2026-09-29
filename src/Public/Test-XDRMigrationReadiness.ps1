function Test-XDRMigrationReadiness {
    <#
    .SYNOPSIS
        Assesses which Sentinel analytics rules migrate cleanly to Defender XDR custom detections.

    .DESCRIPTION
        Answers the question the conversion output cannot: of these rules, which ones can I
        deploy as they are, which need a decision first, and which cannot be migrated at all.

        Each rule comes back with one of four verdicts:

          Ready      Converts cleanly. Deploy it.
          Review     Converts and behaves the same, provided a prerequisite holds. Usually
                     that prerequisite is Microsoft Sentinel data being available in the
                     Defender portal, which you check once for the whole estate.
          NeedsWork  Converts, but the detection will not behave the way it did in Sentinel:
                     a changed run frequency, a dropped entity, lost suppression, a
                     near-real-time rule downgraded to a scheduled one. Needs a human
                     decision.
          Blocked    Cannot become a custom detection at all.

        The verdict comes from the conversion's own diagnostics, classified by impact in
        src/Data/MigrationReadiness.psd1. That classification is a judgement call and is
        meant to be edited: if you think a dropped suppression window is a Review rather
        than NeedsWork in your environment, change the data file, not the code.

        Rules are converted as part of the assessment, so this does the same work as
        ConvertTo-XDRCustomDetection. Use -PassThruDetection to keep the converted rule and
        avoid converting twice when you intend to export or deploy afterwards.

    .PARAMETER Path
        File or folder of Sentinel analytics rules to assess.

    .PARAMETER Recurse
        Search subfolders when -Path is a folder.

    .PARAMETER InputObject
        Rules from Get-SentinelAnalyticsRule, or detections already converted with
        ConvertTo-XDRCustomDetection -As Object. Accepts pipeline input.

    .PARAMETER PassThruDetection
        Include the converted detection on each result, so the same objects can be piped
        into Export-XDRCustomDetection or New-XDRCustomDetection without converting again.

    .EXAMPLE
        Test-XDRMigrationReadiness -Path './Analytic Rules' -Recurse

        The estate view: one row per rule with its verdict.

    .EXAMPLE
        Test-XDRMigrationReadiness -Path ./rules -Recurse | Group-Object Verdict

        How much work is this migration?

    .EXAMPLE
        Test-XDRMigrationReadiness -Path ./rules -Recurse |
            Where-Object Verdict -eq 'NeedsWork' |
            Select-Object RuleName -ExpandProperty Headline

        What exactly needs a decision.

    .EXAMPLE
        Test-XDRMigrationReadiness -Path ./rules -Recurse -PassThruDetection |
            Where-Object Verdict -in 'Ready','Review' |
            ForEach-Object Detection |
            New-XDRCustomDetection -Disabled -Force

        Deploy only the rules that migrate cleanly.

    .EXAMPLE
        Test-XDRMigrationReadiness -Path ./rules -Recurse | Export-XDRMigrationReport -Path ./report.html

        The shareable version.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Path')]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Path', Position = 0)]
        [string[]]$Path,

        [Parameter(ParameterSetName = 'Path')]
        [switch]$Recurse,

        [Parameter(Mandatory, ParameterSetName = 'Object', ValueFromPipeline)]
        [PSObject]$InputObject,

        [Parameter()]
        [switch]$PassThruDetection
    )

    begin {
        # Build one readiness row from a converted detection.
        function New-ReadinessResult {
            param([PSObject]$Detection)

            $verdict = Resolve-MigrationVerdict -Diagnostics $Detection.Diagnostics
            $source = $Detection.SourceRule

            $result = [ordered]@{
                PSTypeName    = 'SentinelToXDR.ReadinessResult'
                RuleName      = [string]$Detection.RuleName
                Verdict       = $verdict.Verdict
                Score         = $verdict.Score
                Headline      = $verdict.Headline
                Id            = [string]$Detection.Id
                Kind          = if ($source) { [string]$source.Kind } else { '' }
                DataTier      = ''
                BlockingCount = $verdict.BlockingCount
                HighCount     = $verdict.HighCount
                MediumCount   = $verdict.MediumCount
                LowCount      = $verdict.LowCount
                Description   = $verdict.Description
                Findings      = $verdict.Findings
                SourcePath    = if ($source) { [string]$source.SourcePath } else { '' }
            }

            # The data tier is the single most useful column after the verdict: it says
            # whether the rule can run on native Defender data or needs Sentinel data in
            # the Defender portal.
            $tierFinding = @($Detection.Diagnostics | Where-Object { $_.Feature -eq 'Rule data' } | Select-Object -First 1)
            if ($tierFinding.Count -gt 0) { $result['DataTier'] = [string]$tierFinding[0].TargetValue }

            if ($PassThruDetection) { $result['Detection'] = $Detection }

            [PSCustomObject]$result
        }

        # Ids seen in this assessment. Each rule is converted in its own pipeline below, so
        # the converter's own batch check never sees two of them; the assessment is the
        # batch, so the duplicate is caught here. Two rules with one id deploy as one
        # detection and a 409.
        $seenIds = [System.Collections.Generic.Dictionary[string,string]]::new([System.StringComparer]::OrdinalIgnoreCase)

        function Add-DuplicateIdFinding {
            param([PSObject]$Detection)
            $id = [string]$Detection.Id
            if (-not $id) { return $Detection }
            if ($seenIds.ContainsKey($id)) {
                $already = @($Detection.Diagnostics | Where-Object { $_.TargetValue -eq 'DuplicateId' }).Count -gt 0
                if (-not $already) {
                    $duplicate = New-ConversionDiagnostic -Feature 'Rules management' -Capability 'Manage rules from API' `
                        -Severity 'Warning' -Action 'RequiresReview' -SourceValue $id -TargetValue 'DuplicateId' `
                        -Reason ("Rule '$($Detection.RuleName)' has id '$id', which '$($seenIds[$id])' in this assessment already uses. " +
                        'Deploying both would create one detection and fail the other with a conflict.')
                    $Detection.Diagnostics = @($Detection.Diagnostics) + @($duplicate)
                }
            } else {
                $seenIds[$id] = [string]$Detection.RuleName
            }
            $Detection
        }

        function Test-Candidate {
            param([PSObject]$Candidate)

            # Already converted: assess directly.
            if ($Candidate.PSObject.TypeNames -contains 'SentinelToXDR.CustomDetection') {
                return New-ReadinessResult -Detection (Add-DuplicateIdFinding -Detection $Candidate)
            }

            # A rule (or anything rule-shaped): convert, then assess.
            $converted = @($Candidate | ConvertTo-XDRCustomDetection -As Object -Force -WarningAction SilentlyContinue)
            foreach ($detection in $converted) {
                New-ReadinessResult -Detection (Add-DuplicateIdFinding -Detection $detection)
            }
        }
    }

    process {
        if ($PSCmdlet.ParameterSetName -eq 'Path') {
            $getParams = @{ Path = $Path }
            if ($Recurse) { $getParams['Recurse'] = $true }
            foreach ($rule in (Get-SentinelAnalyticsRule @getParams)) {
                Test-Candidate -Candidate $rule
            }
            return
        }

        Test-Candidate -Candidate $InputObject
    }
}
