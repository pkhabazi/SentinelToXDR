function Get-MitreSupportRules {
    <#
    .SYNOPSIS
        Loads the MITRE tactic/technique mapping rules from the bundled data file.

    .DESCRIPTION
        Imports src/Data/MitreSupportRules.psd1 — the structural rules behind the
        Stage 4 MITRE-completeness behavior (technique validation pattern, the
        subtechnique pattern, the supported-subset policy, and the multi-tactic
        selection strategy) — and returns the full rules object. The result is
        cached on the script scope so repeated conversions don't re-read the file.

        Capability STATES (Planned / Supported / ...) are NOT stored here; they are
        read from CustomDetectionCapabilities.psd1 via Get-CustomDetectionCapabilities
        so there is a single source of truth for States. This file only holds the
        structural constraints; the Capabilities map records WHICH compare-doc rows
        the converter must look up.

        Path resolution mirrors Get-CustomDetectionCapabilities /
        Get-FrequencyLookbackRules: relative to the module root when module-imported,
        falling back to this script's own location when dot-sourced standalone in tests.

    .EXAMPLE
        Get-MitreSupportRules

        Returns the full rules object.
    #>
    [CmdletBinding()]
    param()

    if (-not $script:MitreSupportRules) {
        $dataRoot = if ($script:ModuleRoot) { $script:ModuleRoot } else { Split-Path -Path $PSScriptRoot -Parent }
        $dataPath = Join-Path -Path $dataRoot -ChildPath 'Data' | Join-Path -ChildPath 'MitreSupportRules.psd1'
        $script:MitreSupportRules = Import-PowerShellDataFile -Path $dataPath
    }

    return $script:MitreSupportRules
}
