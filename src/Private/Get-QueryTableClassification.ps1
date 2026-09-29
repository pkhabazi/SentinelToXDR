function Get-QueryTableClassification {
    <#
    .SYNOPSIS
        Classifies a KQL query by the data tier of the tables it references.

    .DESCRIPTION
        Extracts the table names referenced by a KQL query and classifies the query
        using the BINARY rule (locked decision #3 in the Edge-Case plan): a table found
        in the Defender XDR catalog (src/Data/DefenderXdrTables.psd1) is a Defender table;
        EVERY other referenced table — including custom, let-defined, or function tables
        not in the catalog — is a Sentinel-tier table. There is NO "Unknown" bucket.

        Returns a PSCustomObject with:
          Classification   : 'SentinelOnly' | 'DefenderOnly' | 'Mixed'
          ReferencedTables : distinct table names extracted from the query
          DefenderTables   : subset present in the Defender XDR catalog
          SentinelTables   : subset NOT in the catalog (the rest)

        Default for a query that references zero recognizable tables (empty, unparseable,
        or comment-only): 'SentinelOnly' with empty table lists. Rationale: under the
        binary "everything not Defender is Sentinel" rule, an empty/unparseable query
        should not claim Defender data, and the safe assumption is Sentinel-tier (which
        keeps the Unified SOC caveat in play).

        TABLE-EXTRACTION HEURISTIC (intentionally not a full KQL parser):
          1. Strip block comments and line comments.
          2. Drop let-bound names: a 'let X = ...;' statement defines X, so X is NOT a
             table; such names are collected and excluded from ReferencedTables.
          3. Collect identifiers that appear:
               - at the very start of a statement (start of query, or after ';'), and
               - immediately after a tabular operator that takes a table: join, union,
                 lookup (incl. their modifier-prefixed forms like 'join kind=inner Table'
                 and union lists 'union A, B, C').
          4. Exclude KQL keywords/operators and let-bound names.

        KNOWN LIMITATIONS:
          - Only the common query shapes are handled reliably (single-table,
            union of tables, join/lookup of two tables, leading 'Table | ...').
          - Tables referenced only inside a let-bound subquery expression (e.g.
            'let x = SomeTable | ...;') are detected when the subquery starts with the
            table, but deeply nested / dynamically built table references may be missed.
          - String literals are not fully tokenized; an identifier that looks like a
            table name inside a string could in rare cases be picked up. This is a
            heuristic by design — misclassification falls back to Sentinel-tier, which
            is the conservative outcome.

    .PARAMETER Query
        The KQL query text to classify.

    .EXAMPLE
        Get-QueryTableClassification -Query 'DeviceProcessEvents | take 10'

        Returns Classification 'DefenderOnly'.

    .EXAMPLE
        Get-QueryTableClassification -Query 'SecurityEvent | join DeviceInfo on DeviceName'

        Returns Classification 'Mixed' (SecurityEvent is Sentinel-tier, DeviceInfo is Defender).
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Query
    )

    # Resolve the catalog relative to the module root (works when module-imported) and
    # fall back to this script's own location (works when dot-sourced standalone in tests).
    if (-not $script:DefenderXdrTables) {
        $dataRoot = if ($script:ModuleRoot) { $script:ModuleRoot } else { Split-Path -Path $PSScriptRoot -Parent }
        $dataPath = Join-Path -Path $dataRoot -ChildPath 'Data' | Join-Path -ChildPath 'DefenderXdrTables.psd1'
        $script:DefenderXdrTables = Import-PowerShellDataFile -Path $dataPath
    }
    $catalog = $script:DefenderXdrTables.Tables

    # Build the empty/default result up front (reused for empty/unparseable queries).
    $emptyResult = [PSCustomObject][ordered]@{
        Classification   = 'SentinelOnly'
        ReferencedTables = @()
        DefenderTables   = @()
        SentinelTables   = @()
    }

    if ([string]::IsNullOrWhiteSpace($Query)) {
        return $emptyResult
    }

    # 1. Blank string-literal contents (shared KQL-aware helper), THEN strip comments.
    #    Blanking strings first means a '//' inside a URL string (e.g. "http://x") is not
    #    mistaken for a line comment, and an identifier inside a string can't be picked up
    #    as a table name. The helper preserves length/structure.
    $clean = Remove-KqlStringLiteral -Text $Query
    $clean = [regex]::Replace($clean, '/\*.*?\*/', ' ', 'Singleline')  # block comments
    $clean = [regex]::Replace($clean, '//[^\r\n]*', ' ')               # line comments

    # KQL keywords / operators that must never be treated as table names.
    $keywords = @(
        'let', 'where', 'project', 'extend', 'summarize', 'order', 'sort', 'top',
        'take', 'limit', 'distinct', 'count', 'mv-expand', 'mvexpand', 'parse',
        'evaluate', 'render', 'print', 'datatable', 'range', 'on', 'kind', 'by',
        'asc', 'desc', 'and', 'or', 'not', 'has', 'contains', 'startswith',
        'endswith', 'matches', 'between', 'in', 'as', 'set', 'declare', 'pattern',
        'invoke', 'getschema', 'sample', 'serialize', 'make-series', 'union',
        'join', 'lookup', 'find', 'search', 'externaldata', 'toscalar', 'materialize',
        'inner', 'outer', 'left', 'right', 'fullouter', 'leftouter', 'rightouter',
        'leftsemi', 'rightsemi', 'leftanti', 'rightanti', 'anti', 'semi',
        'innerunique', 'true', 'false', 'null', 'withsource', 'isfuzzy',
        # Common scalar/function names that can appear as the RHS of a 'let x = ...'
        # scalar assignment; excluded to avoid mistaking them for table references.
        'ago', 'now', 'datetime', 'timespan', 'dynamic', 'toscalar', 'bag_pack',
        'pack', 'pack_array', 'case', 'iff', 'iif', 'strcat', 'tostring', 'tolong',
        'toint', 'todouble', 'todatetime', 'split', 'array_length', 'min_of', 'max_of'
    )
    $keywordSet = [System.Collections.Generic.HashSet[string]]::new(
        [string[]]$keywords, [System.StringComparer]::OrdinalIgnoreCase)

    # 2. Collect let-bound names (these define variables/functions, NOT tables).
    $letNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($m in [regex]::Matches($clean, '(?im)\blet\s+([A-Za-z_][A-Za-z0-9_]*)\s*=')) {
        [void]$letNames.Add($m.Groups[1].Value)
    }

    $identPattern = '[A-Za-z_][A-Za-z0-9_]*'
    $referenced = [System.Collections.Generic.List[string]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    $addTable = {
        param([string]$name)
        if ([string]::IsNullOrWhiteSpace($name)) { return }
        if ($keywordSet.Contains($name)) { return }
        if ($letNames.Contains($name)) { return }
        if ($seen.Add($name)) { $referenced.Add($name) }
    }

    # 3a. Identifier at statement start: start of the query body or just after ';'.
    #     Skip a leading 'let ... ;' run so we land on the first real tabular statement,
    #     but also evaluate every post-';' position for a leading table reference.
    foreach ($m in [regex]::Matches($clean, "(?m)(?:^|;)\s*($identPattern)")) {
        $name = $m.Groups[1].Value
        # A 'let X =' start is a definition, not a table reference — keyword filter drops 'let'.
        & $addTable $name
    }

    # 3a-ii. Leading table of a let-bound subquery: 'let X = SomeTable | ...'.
    #        X itself is excluded (collected in $letNames); SomeTable is a real table.
    foreach ($m in [regex]::Matches($clean, "(?im)\blet\s+$identPattern\s*=\s*($identPattern)")) {
        & $addTable $m.Groups[1].Value
    }

    # 3b. Identifiers following table-taking operators: join / lookup / union.
    #     Handle modifier tokens (kind=..., hints, isfuzzy=...) before the table name,
    #     and union lists (union A, B, C).
    foreach ($m in [regex]::Matches($clean, "(?i)\b(?:join|lookup)\b((?:\s+(?:kind\s*=\s*$identPattern|hint\.\w+\s*=\s*\S+|\`$left|\`$right))*)\s+($identPattern)")) {
        & $addTable $m.Groups[2].Value
    }

    # union [modifiers] T1, T2, ...  — capture the comma-separated table list.
    foreach ($m in [regex]::Matches($clean, "(?i)\bunion\b((?:\s+(?:kind\s*=\s*$identPattern|withsource\s*=\s*$identPattern|isfuzzy\s*=\s*\w+))*)\s+(.+?)(?:\||;|$)")) {
        $list = $m.Groups[2].Value
        foreach ($t in $list -split ',') {
            $name = $t.Trim()
            if ($name -match "^($identPattern)$") { & $addTable $Matches[1] }
        }
    }

    if ($referenced.Count -eq 0) {
        return $emptyResult
    }

    $catalogSet = [System.Collections.Generic.HashSet[string]]::new(
        [string[]]$catalog, [System.StringComparer]::OrdinalIgnoreCase)

    $defenderTables = [System.Collections.Generic.List[string]]::new()
    $sentinelTables = [System.Collections.Generic.List[string]]::new()
    foreach ($t in $referenced) {
        if ($catalogSet.Contains($t)) { $defenderTables.Add($t) }
        else { $sentinelTables.Add($t) }
    }

    $classification =
        if ($defenderTables.Count -gt 0 -and $sentinelTables.Count -gt 0) { 'Mixed' }
        elseif ($defenderTables.Count -gt 0) { 'DefenderOnly' }
        else { 'SentinelOnly' }

    [PSCustomObject][ordered]@{
        Classification   = $classification
        ReferencedTables = $referenced.ToArray()
        DefenderTables   = $defenderTables.ToArray()
        SentinelTables   = $sentinelTables.ToArray()
    }
}
