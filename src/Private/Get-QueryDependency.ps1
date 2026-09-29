function Get-QueryDependency {
    <#
    .SYNOPSIS
        Finds KQL constructs that convert cleanly but cannot run in Defender XDR.

    .DESCRIPTION
        The structural checks in this module ask whether a RULE can become a custom
        detection. This one asks whether its QUERY can still run once it gets there.

        A Sentinel query can reach things that exist only in a Log Analytics workspace: a
        watchlist, an ASIM parser, a saved function, another workspace, an externaldata
        URI. Advanced hunting has none of them. The rule around such a query converts
        perfectly — right schedule, right entities, right severity — and the detection
        then fails the moment it runs. Without this check the assessment calls those rules
        Ready or Review, which is the most expensive answer this module can give.

        The scan is a heuristic and deliberately errs toward speaking up. String literals
        are blanked and comments stripped first (the same treatment
        Get-QueryTableClassification and Test-NrtQueryCompatibility apply), so a watchlist
        name inside a quoted string or a commented-out line does not trigger it.

        What settles it for certain is Test-XDRDetectionQuery, which runs the query against
        the tenant. This function is what makes the offline assessment honest in the
        meantime.

        Patterns live in src/Data/QueryDependencyRules.psd1.

    .PARAMETER Query
        The KQL query text.

    .OUTPUTS
        Zero or more objects with Name, Severity, Action, Reason and Match (the construct
        as it appeared, for the diagnostic message).

    .EXAMPLE
        Get-QueryDependency -Query 'SigninLogs | where IPAddress in (_GetWatchlist("bad"))'

        Returns the Watchlist dependency.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Query
    )

    if ([string]::IsNullOrWhiteSpace($Query)) { return }

    if (-not $script:QueryDependencyRules) {
        $dataRoot = if ($script:ModuleRoot) { $script:ModuleRoot } else { Split-Path -Path $PSScriptRoot -Parent }
        $dataPath = Join-Path -Path $dataRoot -ChildPath 'Data' | Join-Path -ChildPath 'QueryDependencyRules.psd1'
        $script:QueryDependencyRules = Import-PowerShellDataFile -Path $dataPath
    }
    $rules = $script:QueryDependencyRules

    # Blank string-literal contents, then strip comments. A watchlist name mentioned in a
    # description string, or a construct in a commented-out line, is not a dependency.
    $scanText = Remove-KqlStringLiteral -Text $Query
    $scanText = [regex]::Replace($scanText, '/\*.*?\*/', ' ', 'Singleline')
    $scanText = [regex]::Replace($scanText, '//[^\r\n]*', ' ')

    foreach ($dependency in $rules.Dependencies) {
        $match = [regex]::Match($scanText, $dependency.Pattern)
        if (-not $match.Success) { continue }

        [PSCustomObject][ordered]@{
            PSTypeName = 'SentinelToXDR.QueryDependency'
            Name       = [string]$dependency.Name
            Severity   = [string]$dependency.Severity
            Action     = [string]$dependency.Action
            Reason     = [string]$dependency.Reason
            Match      = $match.Value.Trim()
            Count      = [regex]::Matches($scanText, $dependency.Pattern).Count
        }
    }
}
