function Get-SentinelRuleKind {
    <#
    .SYNOPSIS
        Resolves a Sentinel analytics rule kind to its convertibility verdict.

    .DESCRIPTION
        Imports src/Data/SentinelRuleKinds.psd1 and returns the entry for the requested
        kind. Query-backed kinds (Scheduled, NRT) are convertible; Microsoft-managed
        kinds (Fusion, MLBehaviorAnalytics, ThreatIntelligence,
        MicrosoftSecurityIncidentCreation, Anomaly) carry no KQL query and are not.

        An unrecognised kind is returned as non-convertible with a reason naming it, so a
        future Microsoft rule kind fails loudly rather than converting into an
        empty-query detection.

        Called with no -Kind, the full data object is returned (used by tests and by the
        report writer).

    .PARAMETER Kind
        The rule kind to resolve, e.g. 'Scheduled', 'NRT', 'Fusion'. Case-insensitive.
        An empty or missing kind resolves to the data file's DefaultKind.

    .EXAMPLE
        (Get-SentinelRuleKind -Kind 'Fusion').Convertible

        Returns $false.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Kind
    )

    if (-not $script:SentinelRuleKinds) {
        $dataRoot = if ($script:ModuleRoot) { $script:ModuleRoot } else { Split-Path -Path $PSScriptRoot -Parent }
        $dataPath = Join-Path -Path $dataRoot -ChildPath 'Data' | Join-Path -ChildPath 'SentinelRuleKinds.psd1'
        $script:SentinelRuleKinds = Import-PowerShellDataFile -Path $dataPath
    }

    if (-not $PSBoundParameters.ContainsKey('Kind')) {
        return $script:SentinelRuleKinds
    }

    $resolved = if ([string]::IsNullOrWhiteSpace($Kind)) {
        $script:SentinelRuleKinds.DefaultKind
    } else {
        $Kind.Trim()
    }

    $match = $script:SentinelRuleKinds.Kinds | Where-Object { $_.Kind -ieq $resolved } | Select-Object -First 1
    if ($match) {
        return [PSCustomObject]@{
            Kind        = $match.Kind
            Convertible = [bool]$match.Convertible
            Reason      = [string]$match.Reason
            IsKnown     = $true
        }
    }

    return [PSCustomObject]@{
        Kind        = $resolved
        Convertible = $false
        Reason      = ("Unrecognised Sentinel analytics rule kind '$resolved'. Only query-backed kinds " +
                       "(" + (($script:SentinelRuleKinds.Kinds | Where-Object { $_.Convertible }).Kind -join ', ') +
                       ") carry the KQL query and schedule a custom detection is built from. " +
                       "If this is a new Microsoft rule kind, add it to src/Data/SentinelRuleKinds.psd1.")
        IsKnown     = $false
    }
}
