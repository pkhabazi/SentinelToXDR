function Get-FrequencyLookbackRules {
    <#
    .SYNOPSIS
        Loads the frequency & lookback decision rules from the bundled data file.

    .DESCRIPTION
        Imports src/Data/FrequencyLookbackRules.psd1 and returns the full rules object
        (Metadata + Parity + FixedLookbackPerFrequency), cached on the script scope so
        repeated conversions do not re-read the file.

        Parity holds the lookback ceilings for SENTINEL-tier data, as a frequency-ordered
        tier list. FixedLookbackPerFrequency holds the lookback Defender applies to
        DEFENDER-tier data, which is not configurable — the converter reports it so a user
        can see the window their rule will actually evaluate, but never emits it.

        Every value comes from the product documentation verbatim; nothing is derived here.
        An earlier version computed values in this loader, which is how a guessed lookback
        ended up being reported as fact.

        Path resolution mirrors the other data loaders: relative to the module root when
        module-imported, falling back to this script's own location when dot-sourced
        standalone in tests.

    .EXAMPLE
        Get-FrequencyLookbackRules

        Returns the full rules object.
    #>
    [CmdletBinding()]
    param()

    if (-not $script:FrequencyLookbackRules) {
        $dataRoot = if ($script:ModuleRoot) { $script:ModuleRoot } else { Split-Path -Path $PSScriptRoot -Parent }
        $dataPath = Join-Path -Path $dataRoot -ChildPath 'Data' | Join-Path -ChildPath 'FrequencyLookbackRules.psd1'
        $script:FrequencyLookbackRules = Import-PowerShellDataFile -Path $dataPath
    }

    return $script:FrequencyLookbackRules
}
