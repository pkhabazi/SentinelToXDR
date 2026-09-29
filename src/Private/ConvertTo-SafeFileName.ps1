function ConvertTo-SafeFileName {
    <#
    .SYNOPSIS
        Turns a display name into a file name that is readable and safe on every platform.

    .DESCRIPTION
        Keeps letters, digits, spaces and hyphens; drops everything else (brackets, slashes,
        angle brackets, '=', quotes, control codes, bidi overrides); then CamelCases the words
        so '[Entra ID] Devices flapping online/offline' becomes
        'EntraIDDevicesFlappingOnlineOffline' rather than '[EntraID]DevicesFlappingOnline_offline'.
        A leading '=' or '-' is dropped so the name cannot read as a formula or an option.
        Windows reserved device names and an empty result fall back to the id.

        Two exporters used to carry their own copy of this, and they disagreed.

    .PARAMETER Name
        The display name.

    .PARAMETER Fallback
        Used when nothing safe is left, usually the rule id.

    .OUTPUTS
        System.String
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Position = 0)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Name,

        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Fallback = 'detection'
    )

    $text = [string]$Name
    # Anything that is not a letter, digit, space or hyphen becomes a space, so the words
    # around it stay separate ('online/offline' -> 'online offline').
    $text = [regex]::Replace($text, '[^\p{L}\p{N}\s-]', ' ')
    $words = @($text -split '\s+' | Where-Object { $_ } | ForEach-Object {
        $_.Substring(0, 1).ToUpperInvariant() + $_.Substring(1)
    })
    $safe = ($words -join '').Trim('-', '.', ' ')

    if ([string]::IsNullOrWhiteSpace($safe) -or $safe -match '^(?i)(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$') {
        $safe = [string]$Fallback
    }
    if ([string]::IsNullOrWhiteSpace($safe)) { $safe = 'detection' }
    return $safe
}
