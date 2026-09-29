<#
.SYNOPSIS
PostToolUse hook: run PSScriptAnalyzer on the file Claude just wrote/edited.

.DESCRIPTION
Advisory only. Reads the hook payload from stdin (JSON), extracts the edited
file path, and - if it is a PowerShell file - runs PSScriptAnalyzer against it.
Findings are written to stderr and the hook exits 2 so they are surfaced back to
Claude for a fix-up. The edit itself has already happened (PostToolUse), so this
never blocks; it only informs. Anything else (non-PS file, analyzer missing,
parse error in the hook) exits 0 silently.
#>

$ErrorActionPreference = 'Stop'

try {
    $raw = [Console]::In.ReadToEnd()
    if ([string]::IsNullOrWhiteSpace($raw)) { exit 0 }

    $payload = $raw | ConvertFrom-Json
    $path = $payload.tool_input.file_path
    if ([string]::IsNullOrWhiteSpace($path)) { exit 0 }

    if ($path -notmatch '\.(ps1|psm1|psd1)$') { exit 0 }
    if (-not (Test-Path -LiteralPath $path)) { exit 0 }

    # .psd1 data/manifest files are plain hashtables - analyzer noise isn't useful there.
    if ($path -match '\.psd1$') { exit 0 }

    if (-not (Get-Module -ListAvailable -Name PSScriptAnalyzer)) { exit 0 }
    Import-Module PSScriptAnalyzer -ErrorAction Stop

    $findings = Invoke-ScriptAnalyzer -Path $path -Severity @('Error', 'Warning') -ErrorAction SilentlyContinue
    if (-not $findings) { exit 0 }

    $name = Split-Path -Leaf $path
    $lines = foreach ($f in $findings) {
        "  [$($f.Severity)] line $($f.Line): $($f.RuleName) - $($f.Message)"
    }

    [Console]::Error.WriteLine("PSScriptAnalyzer found $($findings.Count) issue(s) in ${name}:")
    $lines | ForEach-Object { [Console]::Error.WriteLine($_) }
    [Console]::Error.WriteLine("(advisory - the edit was applied; fix these where they make sense)")
    exit 2
}
catch {
    # Never let a hook failure get in the way of work.
    exit 0
}
