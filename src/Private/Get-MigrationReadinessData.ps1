function Get-MigrationReadinessData {
    <#
    .SYNOPSIS
        Loads the migration readiness classification data from the bundled data file.

    .DESCRIPTION
        Imports src/Data/MigrationReadiness.psd1 - the impact classification rules, the
        verdict thresholds, the score weights and the deprecation window - and returns the
        full object, cached on the script scope so repeated assessments do not re-read it.

        This is the loader the other data files have always had. It exists because the
        readiness data now has a second consumer: Resolve-MigrationVerdict classifies
        diagnostics with it, and Export-XDRMigrationReport reads DeprecationWindow from it
        to render the dated estate banner. Two copies of the same inline load would be two
        places to keep in step.

        Path resolution mirrors Get-MitreSupportRules and its siblings: relative to the
        module root when module-imported, falling back to this script's own location when
        dot-sourced standalone in tests.

    .EXAMPLE
        (Get-MigrationReadinessData).DeprecationWindow.Date

        Returns the date the deprecated fallback properties are removed.
    #>
    [CmdletBinding()]
    param()

    if (-not $script:MigrationReadiness) {
        $dataRoot = if ($script:ModuleRoot) { $script:ModuleRoot } else { Split-Path -Path $PSScriptRoot -Parent }
        $dataPath = Join-Path -Path $dataRoot -ChildPath 'Data' | Join-Path -ChildPath 'MigrationReadiness.psd1'
        $script:MigrationReadiness = Import-PowerShellDataFile -Path $dataPath
    }

    return $script:MigrationReadiness
}
