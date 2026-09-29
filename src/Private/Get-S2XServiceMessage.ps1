function Get-S2XServiceMessage {
    <#
    .SYNOPSIS
        Pulls the service's own sentence out of a failed request's error text.

    .DESCRIPTION
        Invoke-S2XRestRequest rethrows a failure as one string: the method, the URI, the
        HTTP status, the transport's message and the response body. The part a person
        acts on is the 'message' inside the Graph error body ("Unknown function:
        '_MyOrgDeviceBaseline'"), so every cmdlet that reports a failure wants that
        sentence for a table and the full text for the record.

        When the text carries no JSON error body, the first line is returned instead, so a
        transport failure still shows something rather than an empty cell.

    .PARAMETER Message
        The error text as thrown by Invoke-S2XRestRequest.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Message
    )

    if ([string]::IsNullOrWhiteSpace($Message)) { return '' }

    if ($Message -match '"message"\s*:\s*"((?:[^"\\]|\\.)*)"') {
        # The body is JSON, so the sentence may carry escaped quotes or newlines.
        $raw = $Matches[1]
        try { return [string](ConvertFrom-Json -InputObject "`"$raw`"") } catch { return $raw }
    }

    return ([string]($Message -split "`r?`n")[0]).Trim()
}
