function Test-NrtQueryCompatibility {
    <#
    .SYNOPSIS
        Tests whether a KQL query is compatible with Defender XDR Continuous (NRT) frequency.

    .DESCRIPTION
        A Sentinel NRT (kind=NRT) rule targets a Defender XDR "Continuous (NRT)" custom
        detection, which runs on a single streaming table and supports only a RESTRICTED
        subset of KQL. This function applies a HEURISTIC validator (intentionally not a
        full KQL parser) to decide whether a query may run continuously.

        The restricted set is DATA-DRIVEN from src/Data/NrtQueryRestrictions.psd1 (so a
        change in Microsoft's continuous-query limitations is a data edit, not a code
        change). The authoritative rules — from
        https://learn.microsoft.com/en-us/defender-xdr/custom-detection-rules
        ("Queries you can run continuously") — are that a continuous query:
          * references ONE table only;
          * uses only supported KQL operators;
          * does NOT use joins, unions, or the externaldata operator;
          * does NOT include any comment lines.

        DETECTION HEURISTIC (mirrors Get-QueryTableClassification's tokenization):
          0. Blank the CONTENTS of string literals first via the shared
             Remove-KqlStringLiteral helper (the same string-aware step Stage 1 uses).
             This neutralises '//', '/* */' and operator keywords that occur INSIDE
             string literals — so a URL like "http://evil.com/x" is not read as a
             comment and `has "join"` does not flag the 'join' operator. Genuine
             comments / operators OUTSIDE strings survive and are still flagged.
          1. Capture comments FIRST (before stripping) — continuous queries disallow
             comments, so any // line comment or /* block */ is a violation.
          2. Strip comments, then scan the cleaned text for each disallowed operator
             from the psd1 as a KQL PIPE OPERATOR or standalone token: i.e. the keyword
             appears at a word boundary preceded by a '|' pipe or statement start, OR
             (for join/union/lookup-style operators) as a bare keyword token. To reduce
             false positives the scan requires a word boundary on both sides so column
             names like 'JoinDate' are not matched; with string interiors already
             blanked, operator keywords inside string literals are not matched either.
          3. Scan for disallowed CONSTRUCT substrings (cluster(), workspace(), database()).
          4. Reuse the Stage 1 table extractor (Get-QueryTableClassification) to count
             distinct referenced base tables; >1 table violates the single-table rule.

        Result is a PSCustomObject:
          IsCompatible (bool)         : $true only when no violations were found.
          Violations   (string[])     : distinct violation labels (e.g. 'join',
                                        'externaldata', 'union', 'multiple tables (...)',
                                        'comments').
          ReferencedTables (string[]) : tables seen (from the Stage 1 extractor).

        KNOWN LIMITATIONS:
          - Heuristic, not a parser. String/identifier edge cases may over-flag (safe:
            the rule downgrades to scheduled with a diagnostic) but are designed not to
            silently under-flag the authoritative join/union/externaldata trio.
          - String-literal handling (Remove-KqlStringLiteral) covers the common KQL
            forms ("...", '...', verbatim @"..."/@'...', with backslash escapes in the
            non-verbatim forms). Exotic / malformed string nesting is best-effort.
          - The supported-KQL allow-list is not enumerated positively; this function uses
            a conservative DENY list. An exotic unsupported operator not present in the
            psd1 would pass — extend DisallowedOperators in the data file if discovered.
          - Multi-table detection inherits Get-QueryTableClassification's heuristic limits
            (it reliably handles the common single-table / join / union shapes).

    .PARAMETER Query
        The KQL query text to validate.

    .EXAMPLE
        Test-NrtQueryCompatibility -Query 'DeviceProcessEvents | where FileName == "x" | summarize count() by DeviceId'
        # IsCompatible = $true, Violations = @()

    .EXAMPLE
        Test-NrtQueryCompatibility -Query 'SecurityEvent | join DeviceInfo on DeviceName'
        # IsCompatible = $false, Violations contains 'join' and 'multiple tables (...)'
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Query
    )

    # Resolve + cache the restriction data file (mirrors the other Stage loaders:
    # module root when imported, this script's parent when dot-sourced in tests).
    if (-not $script:NrtQueryRestrictions) {
        $dataRoot = if ($script:ModuleRoot) { $script:ModuleRoot } else { Split-Path -Path $PSScriptRoot -Parent }
        $dataPath = Join-Path -Path $dataRoot -ChildPath 'Data' | Join-Path -ChildPath 'NrtQueryRestrictions.psd1'
        $script:NrtQueryRestrictions = Import-PowerShellDataFile -Path $dataPath
    }
    $rules = $script:NrtQueryRestrictions

    $violations = [System.Collections.Generic.List[string]]::new()
    $seenViol   = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $addViolation = {
        param([string]$label)
        if (-not [string]::IsNullOrWhiteSpace($label) -and $seenViol.Add($label)) {
            $violations.Add($label)
        }
    }

    if ([string]::IsNullOrWhiteSpace($Query)) {
        # An empty/missing query is treated as compatible (nothing disallowed present);
        # the converter handles missing-query concerns elsewhere.
        return [PSCustomObject][ordered]@{
            IsCompatible     = $true
            Violations       = @()
            ReferencedTables = @()
        }
    }

    # Blank the CONTENTS of string literals first (shared KQL-aware helper, also used
    # by Get-QueryTableClassification). This neutralises '//', '/* */' and operator
    # keywords that appear inside strings (e.g. "http://evil.com/x" or has "join") so
    # they are not mistaken for genuine comments or pipe operators. The helper keeps
    # the text length/structure intact, so a GENUINE comment outside any string is
    # still present and still flagged.
    $strBlanked = Remove-KqlStringLiteral -Text $Query

    # 1. Comments — detected on the string-blanked query BEFORE comment-stripping
    #    (continuous mode disallows any genuine comment line/block; '//' inside a
    #    string literal has already been blanked above so it is not flagged).
    if ($rules.CommentsDisallowed) {
        $hasLineComment  = [regex]::IsMatch($strBlanked, '//[^\r\n]*')
        $hasBlockComment = [regex]::IsMatch($strBlanked, '/\*.*?\*/', 'Singleline')
        if ($hasLineComment -or $hasBlockComment) {
            & $addViolation 'comments'
        }
    }

    # Strip comments for the operator scan (so an operator keyword inside a comment
    # is not double-counted as an operator violation). Start from the string-blanked
    # text so operator keywords inside string literals (e.g. has "join") don't match.
    $clean = $strBlanked
    $clean = [regex]::Replace($clean, '/\*.*?\*/', ' ', 'Singleline')
    $clean = [regex]::Replace($clean, '//[^\r\n]*', ' ')

    # 2. Disallowed operators — scan as standalone word-boundary tokens. KQL tabular
    #    operators appear either after a pipe ('| join ...') or as a bare keyword;
    #    a both-sides word boundary avoids matching column names like 'JoinKey'.
    foreach ($entry in $rules.DisallowedOperators) {
        $op = [string]$entry.Operator
        # Escape regex metacharacters (e.g. the hyphen in 'make-graph') and require a
        # word boundary on each side. \b doesn't treat '-' as a boundary, so for
        # hyphenated operators we anchor on whitespace/pipe/start-end instead.
        $escaped = [regex]::Escape($op)
        $pattern = if ($op -match '-') {
            "(?i)(?:^|[\s|;(])$escaped(?=[\s|;)]|$)"
        } else {
            "(?i)\b$escaped\b"
        }
        if ([regex]::IsMatch($clean, $pattern)) {
            & $addViolation ([string]$entry.Label)
        }
    }

    # 3. Disallowed constructs — substring match (function-call forms).
    foreach ($entry in $rules.DisallowedConstructs) {
        $pat = [string]$entry.Pattern
        if ($clean.IndexOf($pat, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
            & $addViolation ([string]$entry.Label)
        }
    }

    # 4. Single-table rule — reuse the Stage 1 extractor to count referenced base
    #    tables. More than one distinct table violates continuous mode.
    $classification = Get-QueryTableClassification -Query $Query
    $referenced = @($classification.ReferencedTables)
    if ($rules.SingleTableOnly -and $referenced.Count -gt 1) {
        & $addViolation ("multiple tables ($($referenced -join ', '))")
    }

    [PSCustomObject][ordered]@{
        IsCompatible     = ($violations.Count -eq 0)
        Violations       = $violations.ToArray()
        ReferencedTables = $referenced
    }
}
