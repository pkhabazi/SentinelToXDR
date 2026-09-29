function Write-ConversionReport {
    <#
    .SYNOPSIS
        Writes a companion conversion report (JSON + Markdown) for a set of diagnostics.

    .DESCRIPTION
        Given a collection of conversion diagnostic records (from New-ConversionDiagnostic)
        and a base path, writes:
          <base>.report.json — the diagnostics serialized as JSON.
          <base>.report.md   — a human-readable table:
                               Feature | Capability | Severity | Action | Source→Target | Reason.

        This is opt-in; callers only invoke it when reporting is requested.

    .PARAMETER Diagnostics
        The diagnostics collection to report on. May be empty.

    .PARAMETER BasePath
        The base path (typically the output YAML path). The .report.json / .report.md
        suffixes are appended after stripping any existing extension.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Diagnostics,

        [Parameter(Mandatory)]
        [string]$BasePath
    )

    # Strip the trailing extension so '<rule>.yaml' becomes '<rule>.report.json' / '.report.md'
    $directory = [System.IO.Path]::GetDirectoryName($BasePath)
    $stem      = [System.IO.Path]::GetFileNameWithoutExtension($BasePath)
    $base      = if ($directory) { Join-Path $directory $stem } else { $stem }

    $jsonPath = "$base.report.json"
    $mdPath   = "$base.report.md"

    # ---- JSON report --------------------------------------------------------
    $json = ConvertTo-Json -InputObject @($Diagnostics) -Depth 5
    if ($PSCmdlet.ShouldProcess($jsonPath, 'Write conversion report (JSON)')) {
        Set-Content -LiteralPath $jsonPath -Value $json -Encoding utf8NoBOM
        Write-Verbose "Report written to: $jsonPath"
    }

    # ---- Markdown report ----------------------------------------------------
    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add('# Conversion report')
    $lines.Add('')
    $lines.Add('| Feature | Capability | Severity | Action | Source→Target | Reason |')
    $lines.Add('| --- | --- | --- | --- | --- | --- |')

    foreach ($d in $Diagnostics) {
        # Escape pipe / newline in free-text cells so the table stays well-formed
        $source     = if ($null -ne $d.SourceValue) { ([string]$d.SourceValue) -replace '\r?\n', ' ' -replace '\|', '\|' } else { '' }
        $target     = if ($null -ne $d.TargetValue) { ([string]$d.TargetValue) -replace '\r?\n', ' ' -replace '\|', '\|' } else { '' }
        $transition = "$source → $target"
        $reason     = ([string]$d.Reason) -replace '\r?\n', ' ' -replace '\|', '\|'
        $cap        = ([string]$d.Capability) -replace '\|', '\|'
        $lines.Add("| $($d.Feature) | $cap | $($d.Severity) | $($d.Action) | $transition | $reason |")
    }

    $markdown = $lines -join [System.Environment]::NewLine
    if ($PSCmdlet.ShouldProcess($mdPath, 'Write conversion report (Markdown)')) {
        Set-Content -LiteralPath $mdPath -Value $markdown -Encoding utf8NoBOM
        Write-Verbose "Report written to: $mdPath"
    }
}
