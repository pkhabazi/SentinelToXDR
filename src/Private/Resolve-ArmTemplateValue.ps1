function Resolve-ArmTemplateValue {
    <#
    .SYNOPSIS
        Resolves a simple ARM template expression to a literal string.

    .DESCRIPTION
        Content Hub and portal-exported ARM templates express resource names as template
        expressions, for example:

            [concat(parameters('workspace'),'/Microsoft.SecurityInsights/',parameters('analytic1-id'))]

        The rule GUID is inside that expression, usually as the default value of a template
        parameter. Without resolving it the converter cannot recover a stable rule id and
        generates a fresh GUID on every run, so the same source rule maps to a different
        detection each time it is converted.

        This is deliberately NOT a full ARM expression engine. It handles the subset that
        actually occurs in analytics rule templates:
          - a plain literal (returned unchanged)
          - concat(...) with any number of arguments
          - string literals in single quotes
          - parameters('name')  -> Template.parameters.name.defaultValue
          - variables('name')   -> Template.variables.name
          - nested concat() inside concat()

        Anything it cannot resolve contributes an empty string to the result rather than
        failing, so a partially resolvable name still yields whatever literals it contains
        (which is where the GUID normally lives).

    .PARAMETER Expression
        The raw value from the ARM resource, with or without the enclosing brackets.

    .PARAMETER Template
        The full parsed ARM template object, used to resolve parameters() and variables()
        references. Optional: without it, only literals and concat of literals resolve.

    .EXAMPLE
        Resolve-ArmTemplateValue -Expression "[concat(parameters('ws'),'/Microsoft.SecurityInsights/','8c7b5caf-fd95-460e-baba-6af3f6848cf6')]"

        Returns '/Microsoft.SecurityInsights/8c7b5caf-fd95-460e-baba-6af3f6848cf6' when no
        template is supplied to resolve the workspace parameter.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Expression,

        [Parameter()]
        [AllowNull()]
        [PSObject]$Template
    )

    if ([string]::IsNullOrWhiteSpace($Expression)) { return '' }

    $trimmed = $Expression.Trim()

    # Not an expression at all.
    if ($trimmed[0] -ne '[' -or $trimmed[-1] -ne ']') { return $trimmed }

    $body = $trimmed.Substring(1, $trimmed.Length - 2).Trim()

    # Split a function argument list on top-level commas only (parentheses aware,
    # and ignoring commas inside single-quoted literals).
    function Split-ArmArgument {
        param([string]$Text)
        $parts = [System.Collections.Generic.List[string]]::new()
        $depth = 0
        $inQuote = $false
        $current = [System.Text.StringBuilder]::new()
        foreach ($ch in $Text.ToCharArray()) {
            if ($ch -eq "'") { $inQuote = -not $inQuote; [void]$current.Append($ch); continue }
            if (-not $inQuote) {
                if ($ch -eq '(') { $depth++ }
                elseif ($ch -eq ')') { $depth-- }
                elseif ($ch -eq ',' -and $depth -eq 0) {
                    [void]$parts.Add($current.ToString().Trim())
                    [void]$current.Clear()
                    continue
                }
            }
            [void]$current.Append($ch)
        }
        if ($current.Length -gt 0) { [void]$parts.Add($current.ToString().Trim()) }
        return $parts
    }

    # Resolve one expression fragment to a string ('' when unresolvable).
    function Resolve-ArmFragment {
        param([string]$Fragment)

        $f = $Fragment.Trim()
        if ([string]::IsNullOrWhiteSpace($f)) { return '' }

        # String literal.
        if ($f.Length -ge 2 -and $f[0] -eq "'" -and $f[-1] -eq "'") {
            return $f.Substring(1, $f.Length - 2)
        }

        # concat(...) — recurse over the arguments.
        if ($f -match "(?i)^concat\s*\((.*)\)$") {
            $inner = $Matches[1]
            $sb = [System.Text.StringBuilder]::new()
            foreach ($arg in (Split-ArmArgument -Text $inner)) {
                [void]$sb.Append((Resolve-ArmFragment -Fragment $arg))
            }
            return $sb.ToString()
        }

        # parameters('name') — take the parameter's defaultValue when available.
        if ($f -match "(?i)^parameters\s*\(\s*'([^']+)'\s*\)$") {
            $name = $Matches[1]
            if ($null -ne $Template -and $Template.PSObject.Properties['parameters']) {
                $param = $Template.parameters.PSObject.Properties[$name]
                if ($param -and $param.Value -and $param.Value.PSObject.Properties['defaultValue']) {
                    return [string]$param.Value.defaultValue
                }
            }
            return ''
        }

        # variables('name')
        if ($f -match "(?i)^variables\s*\(\s*'([^']+)'\s*\)$") {
            $name = $Matches[1]
            if ($null -ne $Template -and $Template.PSObject.Properties['variables']) {
                $variable = $Template.variables.PSObject.Properties[$name]
                if ($variable) { return [string]$variable.Value }
            }
            return ''
        }

        # Anything else (resourceId(), guid(), uniqueString(), ...) is not resolvable
        # at conversion time.
        return ''
    }

    return (Resolve-ArmFragment -Fragment $body)
}
