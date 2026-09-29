function ConvertTo-SafeReportText {
    <#
    .SYNOPSIS
        Makes untrusted text safe to place in a CSV cell, a Markdown table cell or an HTML
        text node.

    .DESCRIPTION
        Rule names, reasons and remedies come from community content and from files other
        people wrote. Three things in them break or weaponise a report:

          - a newline inside a Markdown table cell ends the row and lets the rest of the
            text start new rows;
          - a cell beginning with = + - @ or a tab/CR is executed as a formula when the CSV
            is opened in a spreadsheet (CSV injection);
          - Unicode bidirectional overrides (U+202A-U+202E, U+2066-U+2069) and C0 control
            codes reorder or hide the text on screen in every format, including HTML,
            where HtmlEncode leaves them alone.

        One helper, one rule per format, used by every writer. Write-ConversionReport had
        its own newline handling and Export-XDRMigrationReport had none; the two disagreed.

    .PARAMETER Value
        The text. $null becomes ''.

    .PARAMETER Format
        Csv, Markdown or Html.

    .OUTPUTS
        System.String
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Position = 0)]
        [AllowNull()]
        [AllowEmptyString()]
        [object]$Value,

        [Parameter(Mandatory)]
        [ValidateSet('Csv', 'Markdown', 'Html')]
        [string]$Format
    )

    if ($null -eq $Value) { return '' }
    $text = [string]$Value

    # Bidirectional overrides and control codes go in every format. Tabs and newlines are
    # control codes too; they are collapsed to a space rather than deleted so words stay
    # apart.
    $text = $text -replace '[\r\n\t]+', ' '
    $text = [regex]::Replace($text, '[\p{Cc}\u202A-\u202E\u2066-\u2069]', '')

    switch ($Format) {
        'Csv' {
            # A leading formula trigger is neutralised with a quote prefix, which every
            # spreadsheet renders as literal text. Export-Csv adds the field quoting.
            if ($text -match '^[=+\-@]') { $text = "'" + $text }
            return $text
        }
        'Markdown' {
            # Pipes end cells; angle brackets would render as HTML on GitHub.
            $text = $text -replace '\|', '\|'
            $text = $text -replace '<', '&lt;' -replace '>', '&gt;'
            return $text
        }
        'Html' {
            return [System.Net.WebUtility]::HtmlEncode($text)
        }
    }
}
