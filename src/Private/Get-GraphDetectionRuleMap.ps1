function Get-GraphDetectionRuleMap {
    <#
    .SYNOPSIS
        Loads the Graph detectionRule mapping data from the bundled data file.

    .DESCRIPTION
        Imports src/Data/GraphDetectionRule.psd1 — the single source of truth for how a
        Sentinel analytics rule is rendered into the microsoft.graph.security.detectionRule
        shape (entity mapping matrix, severity map, status values, tactic map, automated
        action sets, key order). Cached on the script scope so repeated conversions do not
        re-read the file.

        Path resolution mirrors the other data loaders: relative to the module root when
        module-imported, falling back to this script's own location when dot-sourced
        standalone in tests.

    .EXAMPLE
        (Get-GraphDetectionRuleMap).Severity['High']

        Returns 'high'.
    #>
    [CmdletBinding()]
    param()

    if (-not $script:GraphDetectionRuleMap) {
        $dataRoot = if ($script:ModuleRoot) { $script:ModuleRoot } else { Split-Path -Path $PSScriptRoot -Parent }
        $dataPath = Join-Path -Path $dataRoot -ChildPath 'Data' | Join-Path -ChildPath 'GraphDetectionRule.psd1'
        $script:GraphDetectionRuleMap = Import-PowerShellDataFile -Path $dataPath
    }

    return $script:GraphDetectionRuleMap
}
