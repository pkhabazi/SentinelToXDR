function Export-XDRCustomDetection {
    <#
    .SYNOPSIS
        Writes converted custom detections to YAML and/or JSON files.

    .DESCRIPTION
        Takes the detection objects produced by ConvertTo-XDRCustomDetection -As Object and
        writes them to disk. Both formats can be written in one pass, which is the normal
        case: YAML for the repository (readable, reviewable in a pull request) and JSON for
        the deployment (exactly what POST /security/rules/detectionRules accepts).

        Files are named after the rule id by default, because the id is what the target
        keys on and what makes a re-run idempotent. -NameBy DisplayName produces friendlier
        filenames when the output is meant for humans.

        With -Combine, all detections are written to one JSON array instead of a file per
        rule, which is the easier artifact to hand to a pipeline.

        Blocked rules (a non-convertible kind, or no query) are skipped and counted. They
        carry no rule object, so there is nothing to write; the reason is in their
        diagnostics.

    .PARAMETER Detection
        Detection objects from ConvertTo-XDRCustomDetection -As Object. Accepts pipeline input.

    .PARAMETER Path
        Destination folder. Created if it does not exist.

    .PARAMETER Format
        Which files to write: Yaml, Json, or Both (default).

    .PARAMETER NameBy
        Filename source: Id (default) or DisplayName.

    .PARAMETER Combine
        Write one combined JSON array instead of a file per rule. Requires a JSON format.

    .PARAMETER CombineFileName
        Filename for the combined output. Defaults to 'customDetections.json'.

    .PARAMETER PassThru
        Emit the detection objects so the pipeline can continue (for example into
        New-XDRCustomDetection).

    .PARAMETER Force
        Overwrite existing files without prompting.

    .EXAMPLE
        Get-SentinelAnalyticsRule -Path ./rules |
            ConvertTo-XDRCustomDetection -As Object -Force |
            Export-XDRCustomDetection -Path ./out

        Writes one .yaml and one .json per rule.

    .EXAMPLE
        Get-SentinelAnalyticsRule -Path ./rules |
            ConvertTo-XDRCustomDetection -As Object -Force |
            Export-XDRCustomDetection -Path ./out -Format Json -Combine

        Writes a single customDetections.json array ready for a deployment pipeline.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSObject]$Detection,

        [Parameter(Mandatory, Position = 0)]
        [string]$Path,

        [Parameter()]
        [ValidateSet('Yaml', 'Json', 'Both')]
        [string]$Format = 'Both',

        [Parameter()]
        [ValidateSet('Id', 'DisplayName')]
        [string]$NameBy = 'Id',

        [Parameter()]
        [switch]$Combine,

        [Parameter()]
        [string]$CombineFileName = 'customDetections.json',

        [Parameter()]
        [switch]$PassThru,

        [Parameter()]
        [switch]$Force
    )

    begin {
        if ($Combine -and $Format -eq 'Yaml') {
            throw "-Combine writes a single JSON array; use -Format Json or -Format Both."
        }

        if (-not (Test-Path -LiteralPath $Path)) {
            if ($PSCmdlet.ShouldProcess($Path, 'Create output folder')) {
                New-Item -ItemType Directory -Path $Path -Force | Out-Null
            }
        }

        $combined = [System.Collections.Generic.List[object]]::new()
        $written  = 0
        $skipped  = 0
        # Existing files are counted, not announced one by one: exporting 200 rules into a
        # folder that already has them would otherwise print 400 identical warnings and bury
        # everything else. One summary at the end says the same thing and can be acted on.
        $existing = [System.Collections.Generic.List[string]]::new()
        $usedNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    }

    process {
        if ($null -eq $Detection) { return }

        if ($Detection.PSObject.Properties['Blocked'] -and $Detection.Blocked) {
            Write-Verbose "Skipping blocked rule '$($Detection.RuleName)': it produced no detection to write."
            $skipped++
            if ($PassThru) { $Detection }
            return
        }

        $rule = $Detection.Rule
        if ($null -eq $rule) {
            Write-Warning "Detection for '$($Detection.RuleName)' carries no rule object and was skipped. Convert with -As Object."
            $skipped++
            return
        }

        if ($Combine) {
            $combined.Add($rule)
            $written++
            if ($PassThru) { $Detection }
            return
        }

        # ---- filename ---------------------------------------------------------
        $baseName = if ($NameBy -eq 'DisplayName') {
            ConvertTo-SafeFileName -Name ([string]$Detection.RuleName) -Fallback ([string]$Detection.Id)
        } else {
            [string]$Detection.Id
        }
        if ([string]::IsNullOrWhiteSpace($baseName)) { $baseName = 'detection' }

        # Two rules can share a display name across solutions; do not let the second
        # silently overwrite the first.
        $candidate = $baseName
        $suffix = 2
        while (-not $usedNames.Add($candidate)) {
            $candidate = "$baseName-$suffix"
            $suffix++
        }
        $baseName = $candidate

        $targets = switch ($Format) {
            'Yaml' { @('Yaml') }
            'Json' { @('Json') }
            'Both' { @('Yaml', 'Json') }
        }

        foreach ($target in $targets) {
            $extension = if ($target -eq 'Json') { 'json' } else { 'yaml' }
            $file = Join-Path -Path $Path -ChildPath "$baseName.$extension"

            if ((Test-Path -LiteralPath $file) -and -not $Force) {
                Write-Verbose "File '$file' already exists; skipped."
                $existing.Add($file)
                continue
            }

            if ($PSCmdlet.ShouldProcess($file, "Write $target custom detection")) {
                $text = ConvertTo-DetectionText -Rule $rule -As $target
                Set-Content -LiteralPath $file -Value $text -Encoding utf8NoBOM -NoNewline
                $written++
            }
        }

        if ($PassThru) { $Detection }
    }

    end {
        if ($Combine -and $combined.Count -gt 0) {
            $file = Join-Path -Path $Path -ChildPath $CombineFileName
            if ((Test-Path -LiteralPath $file) -and -not $Force) {
                Write-Warning "File '$file' already exists; use -Force to overwrite. Nothing was written."
            } elseif ($PSCmdlet.ShouldProcess($file, "Write $($combined.Count) custom detection(s)")) {
                $json = $combined.ToArray() | ConvertTo-Json -Depth 20 -AsArray
                Set-Content -LiteralPath $file -Value $json -Encoding utf8NoBOM -NoNewline
            }
        }

        if ($existing.Count -gt 0) {
            $sample = ($existing | Select-Object -First 3 | ForEach-Object { Split-Path $_ -Leaf }) -join ', '
            $more = if ($existing.Count -gt 3) { " and $($existing.Count - 3) more" } else { '' }
            Write-Warning ("$($existing.Count) file(s) already existed in '$Path' and were not overwritten " +
                "($sample$more). Re-run with -Force to overwrite them, or use an empty folder. " +
                "Run with -Verbose to list them all.")
        }

        $summary = "Export-XDRCustomDetection: $written file(s)/rule(s) written to '$Path'"
        if ($skipped -gt 0) { $summary += ", $skipped blocked rule(s) skipped" }
        if ($existing.Count -gt 0) { $summary += ", $($existing.Count) existing file(s) left alone" }
        Write-Verbose $summary
    }
}
