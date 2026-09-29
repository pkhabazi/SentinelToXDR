function ConvertTo-IsoDurationText {
    <#
    .SYNOPSIS
        Renders a TimeSpan (or a number of hours) as a canonical ISO 8601 duration string.

    .DESCRIPTION
        ISO 8601 is the representation the Graph custom-detection API uses for
        schedule.frequency, and the one this module carries internally, because it
        round-trips unambiguously (no m = minute/month clash) and matches the source
        queryFrequency / queryPeriod format.

        Rendering rules:
          - zero or negative      -> '0'  (continuous / NRT)
          - whole days            -> P{n}D    (14 days -> 'P14D')
          - otherwise             -> PT{h}H{m}M, omitting zero components ('PT45M', 'PT6H')

    .PARAMETER Duration
        A TimeSpan to render.

    .PARAMETER TotalHours
        A duration expressed in hours, rendered identically. Convenience for callers that
        already work in hours.

    .EXAMPLE
        ConvertTo-IsoDurationText -Duration ([timespan]::FromMinutes(45))

        Returns 'PT45M'.
    #>
    [CmdletBinding(DefaultParameterSetName = 'TimeSpan')]
    [OutputType([string])]
    param(
        [Parameter(Mandatory, ParameterSetName = 'TimeSpan')]
        [timespan]$Duration,

        [Parameter(Mandatory, ParameterSetName = 'Hours')]
        [double]$TotalHours
    )

    $hours = if ($PSCmdlet.ParameterSetName -eq 'TimeSpan') { $Duration.TotalHours } else { $TotalHours }

    if ($hours -le 0) { return '0' }

    if (($hours % 24.0) -eq 0) {
        return "P$([int]($hours / 24.0))D"
    }

    $wholeHours = [int][Math]::Floor($hours)
    $minutes    = [int][Math]::Round(($hours - $wholeHours) * 60.0)
    if ($minutes -eq 60) { $wholeHours += 1; $minutes = 0 }

    $text = 'PT'
    if ($wholeHours -gt 0) { $text += "${wholeHours}H" }
    if ($minutes -gt 0)    { $text += "${minutes}M" }
    if ($text -eq 'PT')    { $text = 'PT0H' }
    return $text
}
