function Get-FeatureGapRules {
    <#
    .SYNOPSIS
        Loads the Stage 5 remaining-feature-gap rules from the bundled data file.

    .DESCRIPTION
        Imports src/Data/FeatureGapRules.psd1 — the data source that maps each
        remaining Sentinel source feature (alertDetailsOverride, customDetails,
        eventGroupingSettings, incidentConfiguration, suppression, native
        remediation actions, automation rules) to the compare-doc capability row
        that governs it, plus the native XDR action-type enum. The result is
        cached on the script scope so repeated conversions don't re-read the file.

        Capability STATES (Supported / NotSupported / Planned / ...) are NOT stored
        here; they are read from CustomDetectionCapabilities.psd1 via
        Get-CustomDetectionCapabilities so there is a single source of truth for
        States. This file only records WHICH compare-doc rows the converter must
        look up for each gap.

        Path resolution mirrors Get-CustomDetectionCapabilities / Get-MitreSupportRules:
        relative to the module root when module-imported, falling back to this
        script's own location when dot-sourced standalone in tests.

    .EXAMPLE
        Get-FeatureGapRules

        Returns the full rules object (Metadata + Capabilities + NativeActionTypes).
    #>
    [CmdletBinding()]
    param()

    if (-not $script:FeatureGapRules) {
        $dataRoot = if ($script:ModuleRoot) { $script:ModuleRoot } else { Split-Path -Path $PSScriptRoot -Parent }
        $dataPath = Join-Path -Path $dataRoot -ChildPath 'Data' | Join-Path -ChildPath 'FeatureGapRules.psd1'
        $script:FeatureGapRules = Import-PowerShellDataFile -Path $dataPath
    }

    return $script:FeatureGapRules
}
