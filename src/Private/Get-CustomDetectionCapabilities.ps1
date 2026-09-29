function Get-CustomDetectionCapabilities {
    <#
    .SYNOPSIS
        Loads the Sentinel→XDR capability matrix from the bundled data file.

    .DESCRIPTION
        Imports src/Data/CustomDetectionCapabilities.psd1 — the data-driven mirror of the
        feature-comparison doc — and returns the full matrix object (Metadata + Capabilities).
        The result is cached on the script scope so repeated conversions don't re-read the file.

        When -Feature and -Capability are supplied the function instead returns the State
        ('Supported' | 'NotSupported' | 'Planned' | 'PublicPreview') of that single capability,
        or $null when no matching row exists. This is the query path converter logic uses to
        decide map / drop / warn behaviour without hard-coding capability states in code.

    .PARAMETER Feature
        The Feature column value to look up (e.g. 'Rule frequency'). Requires -Capability.

    .PARAMETER Capability
        The Capability column value to look up (e.g. 'Link multiple MITRE tactics').

    .EXAMPLE
        Get-CustomDetectionCapabilities

        Returns the full matrix (Metadata + Capabilities array).

    .EXAMPLE
        Get-CustomDetectionCapabilities -Feature 'Alert enrichment' -Capability 'Link multiple MITRE tactics'

        Returns 'Planned'.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Feature,

        [Parameter()]
        [string]$Capability
    )

    # Resolve the data file relative to the module root (works when dot-sourced) and
    # fall back to this script's own location (works when dot-sourced standalone in tests).
    if (-not $script:CustomDetectionCapabilities) {
        $dataRoot = if ($script:ModuleRoot) { $script:ModuleRoot } else { Split-Path -Path $PSScriptRoot -Parent }
        $dataPath = Join-Path -Path $dataRoot -ChildPath 'Data' | Join-Path -ChildPath 'CustomDetectionCapabilities.psd1'
        $script:CustomDetectionCapabilities = Import-PowerShellDataFile -Path $dataPath
    }
    $matrix = $script:CustomDetectionCapabilities

    # Single-capability state lookup
    if ($PSBoundParameters.ContainsKey('Feature') -or $PSBoundParameters.ContainsKey('Capability')) {
        $entry = $matrix.Capabilities | Where-Object {
            $_.Feature -eq $Feature -and $_.Capability -eq $Capability
        } | Select-Object -First 1
        return $(if ($entry) { $entry.State } else { $null })
    }

    return $matrix
}
