function Remove-KqlStringLiteral {
    <#
    .SYNOPSIS
        Blanks the CONTENTS of KQL string literals while preserving overall length/structure.

    .DESCRIPTION
        Shared helper used by the heuristic KQL scanners (Get-QueryTableClassification and
        Test-NrtQueryCompatibility). KQL strings can be:
          * double-quoted   "..."
          * single-quoted   '...'
          * verbatim        @"..."  /  @'...'
        Inside a NON-verbatim string a backslash escapes the next character (so \" does not
        end the string). Inside a VERBATIM string there are no escapes; the string ends at
        the first matching quote.

        To keep scanners simple and robust, this function walks the text once and replaces
        every character that lies INSIDE a string literal with a space, leaving the opening
        and closing quote characters in place. A '//' or '/* */' inside a string has its
        contents blanked, so a subsequent comment strip is not fooled by '//' inside a URL
        such as "http://evil.com".

        COMMENTS ARE HANDLED IN THE SAME PASS, and they have to be. Strings and comments
        can each hide the other, so neither can be processed first: blanking strings first
        lets an apostrophe in prose open a phantom string —

            // Setting URI length threshold count, shorter URI's may cause noise

        — which swallowed the entire remainder of the query. That silently changed the data
        tier of 22 rules in the Azure-Sentinel corpus and hid every ASIM and watchlist
        dependency after the comment. Comment CONTENTS are blanked while the '//' and
        '/* */' markers are kept, so a caller that needs to detect a comment still can, and
        the text keeps its length and line structure.

        The returned text has the SAME length as the input and the same non-string content,
        so character offsets are preserved for any downstream matching.

    .PARAMETER Text
        The raw KQL text.

    .OUTPUTS
        [string] the text with string-literal interiors replaced by spaces.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Text
    )

    if ([string]::IsNullOrEmpty($Text)) { return $Text }

    $sb = [System.Text.StringBuilder]::new($Text.Length)
    $i = 0
    $n = $Text.Length

    while ($i -lt $n) {
        $c = $Text[$i]

        # Verbatim string: @"..." or @'...'  (no escape processing inside).
        if ($c -eq '@' -and ($i + 1) -lt $n -and ($Text[$i + 1] -eq '"' -or $Text[$i + 1] -eq "'")) {
            $quote = $Text[$i + 1]
            [void]$sb.Append('@')
            [void]$sb.Append($quote)
            $i += 2
            while ($i -lt $n -and $Text[$i] -ne $quote) {
                [void]$sb.Append(' ')
                $i++
            }
            if ($i -lt $n) {
                [void]$sb.Append($quote)   # closing quote
                $i++
            }
            continue
        }

        # Line comment: // to end of line. The MARKERS are kept so a caller that needs to
        # detect a comment still can; only the contents are blanked. Handling comments in
        # THIS pass is what stops an apostrophe in prose — "shorter URI's may cause noise"
        # — from opening a string that swallows the remainder of the query.
        if ($c -eq '/' -and ($i + 1) -lt $n -and $Text[$i + 1] -eq '/') {
            [void]$sb.Append('//')
            $i += 2
            while ($i -lt $n -and $Text[$i] -ne "`r" -and $Text[$i] -ne "`n") {
                [void]$sb.Append(' ')
                $i++
            }
            continue
        }

        # Block comment: /* ... */, same treatment.
        if ($c -eq '/' -and ($i + 1) -lt $n -and $Text[$i + 1] -eq '*') {
            [void]$sb.Append('/*')
            $i += 2
            while ($i -lt $n -and -not ($Text[$i] -eq '*' -and ($i + 1) -lt $n -and $Text[$i + 1] -eq '/')) {
                # Newlines are preserved so line-based callers still see the same shape.
                if ($Text[$i] -eq "`r" -or $Text[$i] -eq "`n") { [void]$sb.Append($Text[$i]) }
                else { [void]$sb.Append(' ') }
                $i++
            }
            if ($i -lt $n) {
                [void]$sb.Append('*/')
                $i += 2
            }
            continue
        }

        # Regular string: "..." or '...'  (backslash escapes the next char).
        if ($c -eq '"' -or $c -eq "'") {
            $quote = $c
            [void]$sb.Append($quote)
            $i++
            while ($i -lt $n -and $Text[$i] -ne $quote) {
                if ($Text[$i] -eq '\' -and ($i + 1) -lt $n) {
                    # Blank the backslash and the escaped char (stay inside the string).
                    [void]$sb.Append(' ')
                    [void]$sb.Append(' ')
                    $i += 2
                } else {
                    [void]$sb.Append(' ')
                    $i++
                }
            }
            if ($i -lt $n) {
                [void]$sb.Append($quote)   # closing quote
                $i++
            }
            continue
        }

        [void]$sb.Append($c)
        $i++
    }

    return $sb.ToString()
}
