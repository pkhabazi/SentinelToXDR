function Get-QueryDependencyRule {
    <#
    .SYNOPSIS
        Loads (and caches) src/Data/QueryDependencyRules.psd1.

    .DESCRIPTION
        Matches the other data loaders in this module: one cached read per session, so the
        converter can stamp the Feature/Capability from data rather than hard-coding them.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    if (-not $script:QueryDependencyRules) {
        $dataRoot = if ($script:ModuleRoot) { $script:ModuleRoot } else { Split-Path -Path $PSScriptRoot -Parent }
        $dataPath = Join-Path -Path $dataRoot -ChildPath 'Data' | Join-Path -ChildPath 'QueryDependencyRules.psd1'
        $script:QueryDependencyRules = Import-PowerShellDataFile -Path $dataPath
    }
    return $script:QueryDependencyRules
}
