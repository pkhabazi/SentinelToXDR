function Import-SentinelRuleFile {
    <#
    .SYNOPSIS
        Reads a Sentinel analytics rule file and emits every rule it contains, normalized.

    .DESCRIPTION
        One file can hold one rule or many. This function detects the shape and emits a
        normalized rule object per rule found:

          YAML (.yaml / .yml)
            - a single community rule mapping
            - a sequence of rule mappings

          JSON (.json)
            - a single ARM resource: { type, kind, properties { ... } }
            - a full ARM deployment template: { $schema, resources: [ ... ] }, including
              alertRules nested inside other resources (Content Hub mainTemplate.json puts
              them under a contentTemplate resource). Template parameters are used to
              resolve [concat()] name expressions so the rule GUID is recovered.
            - a REST list response: { value: [ ... ] }
            - a bare array of rule objects (the shape shipped by some solutions)
            - a flat rule object with no envelope

        A file that parses but contains no recognisable analytics rule produces no output
        rather than an empty conversion. Whether that is reported as a warning depends on
        how the file was reached: see -Scanning.

    .PARAMETER Path
        Path to a .yaml, .yml or .json file.

    .PARAMETER Scanning
        Set when the file was found by scanning a folder rather than named by the user.

        A content repository is mostly not analytics rules: workbooks, playbooks, parsers,
        data connectors, DCR templates, table schemas, solution metadata. Warning about each
        one buries the real findings under thousands of lines of noise, and the user did not
        ask about those files in the first place.

        So when scanning, "this is not a rule" is reported through Write-Verbose. When the
        user named the file explicitly, it stays a warning: they asked about that file and
        deserve an answer. Genuine problems (a file that is a rule but fails to parse) warn
        either way.

    .OUTPUTS
        PSCustomObject collection with PSTypeName 'SentinelToXDR.SentinelRule'.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
        [string]$Path,

        [Parameter()]
        [switch]$Scanning
    )

    # "Not a rule file" during a folder scan is expected, not a problem to report.
    $notARule = if ($Scanning) { 'Write-Verbose' } else { 'Write-Warning' }

    $extension = [System.IO.Path]::GetExtension($Path).ToLowerInvariant()
    $content = Get-Content -LiteralPath $Path -Raw

    if ([string]::IsNullOrWhiteSpace($content)) {
        & $notARule "File '$Path' is empty; no rules to read."
        return
    }

    # -- YAML ------------------------------------------------------------------
    if ($extension -in '.yaml', '.yml') {
        $parsed = $null
        try {
            $parsed = ConvertFrom-Yaml -Yaml $content -AllDocuments -ErrorAction Stop
        } catch {
            Write-Warning "File '$Path' is not valid YAML and was skipped: $($_.Exception.Message)"
            return
        }

        foreach ($document in @($parsed)) {
            if ($null -eq $document) { continue }
            # A YAML file can hold a sequence of rules rather than one mapping.
            if ($document -is [System.Collections.IList]) {
                $position = 0
                foreach ($item in $document) {
                    $position++
                    if (Test-SentinelRuleShape -Candidate $item) {
                        ConvertTo-NormalizedSentinelRule -InputObject $item -SourceFormat 'CommunityYaml' -SourcePath $Path
                    } else {
                        # Same reporting as a single-mapping file. This branch used to skip
                        # silently, so an item that was almost a rule left no trace at all.
                        & $notARule ("Item $position in '$Path' is not an analytics rule and was skipped. " +
                            (Get-NotARuleMessage -Path $Path -Candidate $item))
                    }
                }
                continue
            }
            if (Test-SentinelRuleShape -Candidate $document) {
                ConvertTo-NormalizedSentinelRule -InputObject $document -SourceFormat 'CommunityYaml' -SourcePath $Path
            } else {
                & $notARule (Get-NotARuleMessage -Path $Path -Candidate $document)
            }
        }
        return
    }

    # -- JSON ------------------------------------------------------------------
    if ($extension -ne '.json') {
        throw "Unsupported file extension '$extension'. Supported extensions: .yaml, .yml, .json."
    }

    $json = $null
    try {
        $json = $content | ConvertFrom-Json -ErrorAction Stop
    } catch {
        Write-Warning "File '$Path' is not valid JSON and was skipped: $($_.Exception.Message)"
        return
    }

    $emitted = 0

    # Bare array of rules.
    if ($json -is [System.Collections.IList]) {
        foreach ($item in $json) {
            if (Test-SentinelRuleShape -Candidate $item) {
                ConvertTo-NormalizedSentinelRule -InputObject $item -SourceFormat 'ArmResource' -SourcePath $Path
                $emitted++
            }
        }
        if ($emitted -eq 0) { & $notARule "File '$Path' is a JSON array with no recognisable Sentinel analytics rules and was skipped." }
        return
    }

    # REST list response.
    if ($json.PSObject.Properties['value'] -and $json.value -is [System.Collections.IList]) {
        foreach ($item in $json.value) {
            if (Test-SentinelRuleShape -Candidate $item) {
                ConvertTo-NormalizedSentinelRule -InputObject $item -SourceFormat 'LiveApi' -SourcePath $Path
                $emitted++
            }
        }
        if ($emitted -eq 0) { & $notARule "File '$Path' is a REST list response with no recognisable Sentinel analytics rules and was skipped." }
        return
    }

    # ARM deployment template: walk resources[] recursively for alertRules.
    if ($json.PSObject.Properties['resources'] -and $json.resources -is [System.Collections.IList]) {
        $scaffolds = 0
        foreach ($resource in (Find-ArmAlertRuleResource -Resources $json.resources)) {
            # The resource type says "alertRule", but an authoring template declares the
            # same type with every value left as a parameter. Nothing was resolved because
            # nothing had a default; there is no detection here to migrate.
            if (Test-RuleIsArmScaffold -Candidate $resource -Template $json) { $scaffolds++; continue }

            ConvertTo-NormalizedSentinelRule -InputObject $resource -SourceFormat 'ArmTemplate' -SourcePath $Path -Template $json
            $emitted++
        }
        if ($emitted -eq 0 -and $scaffolds -gt 0) {
            & $notARule ("ARM template '$Path' is a blank authoring template, not an analytics rule: its query " +
                'is an unresolved template parameter, so there is no detection logic in the file. Nothing ' +
                'failed to migrate.')
        } elseif ($emitted -eq 0) {
            & $notARule "ARM template '$Path' contains no Microsoft.SecurityInsights alertRules resources and was skipped."
        }
        return
    }

    # Single ARM resource or a flat rule object.
    if (Test-SentinelRuleShape -Candidate $json) {
        $format = if ($json.PSObject.Properties['properties']) { 'ArmResource' } else { 'CommunityYaml' }
        ConvertTo-NormalizedSentinelRule -InputObject $json -SourceFormat $format -SourcePath $Path
        return
    }

    & $notARule (Get-NotARuleMessage -Path $Path -Candidate $json)
}

function Get-NotARuleMessage {
    <#
    .SYNOPSIS
        Explains why a file was not read as an analytics rule.

    .DESCRIPTION
        'No query and no displayName/name' is wrong for a redirect stub — it has a name, and
        saying otherwise sends the reader looking for a parsing problem that is not there.
        A stub gets a message naming the file it points to instead.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter()][AllowNull()][object]$Candidate
    )

    if (Test-RuleIsArmScaffold -Candidate $Candidate) {
        return ("File '$Path' is a blank ARM authoring template, not an analytics rule: its query is " +
            'an unresolved template parameter, so there is no detection logic in the file. Nothing ' +
            'failed to migrate.')
    }

    $target = Get-RulePlaceholderTarget -Candidate $Candidate
    if ($null -ne $target) {
        $where = if ($target) { " The rule moved to: $target" } else { ' The description does not say where it moved.' }
        return ("File '$Path' is a placeholder left behind when the rule moved, not an analytics rule: " +
            "it carries no query and nothing to migrate.$where")
    }

    # This module's own output. Pointing the reader at the folder it just exported to is
    # an easy mistake, and 'no recognisable Sentinel analytics rule' sends the reader to
    # the wrong place for the answer (2026-09-16).
    $memberNames = @()
    if ($Candidate -is [System.Collections.IDictionary]) { $memberNames = @($Candidate.Keys | ForEach-Object { [string]$_ }) }
    elseif ($null -ne $Candidate -and $Candidate.PSObject) { $memberNames = @($Candidate.PSObject.Properties.Name) }
    if (($memberNames -contains 'queryCondition') -or ($memberNames -contains 'detectionAction')) {
        return ("File '$Path' is a Defender XDR custom detection (queryCondition/detectionAction), not a Sentinel " +
            'analytics rule. It looks like output this module produced; point the reader at the Sentinel source rules instead.')
    }

    return "File '$Path' contains no recognisable Sentinel analytics rule (no query and no displayName/name) and was skipped."
}

function Get-RulePlaceholderTarget {
    <#
    .SYNOPSIS
        Returns the destination of a redirect stub, or $null when the candidate is a rule.

    .DESCRIPTION
        Content repositories leave a stub behind when a rule moves: an id, a name and a
        kind, no query, and a description saying where the rule went. Azure-Sentinel has 312
        of them. They are not analytics rules that failed to migrate — there was never a
        detection in the file — so counting them as Blocked overstates how much of an estate
        cannot move.

        Returns the destination when one can be found, an empty string when the file is a
        stub with no destination given, and $null when this is a real rule. A candidate that
        HAS a query is never a placeholder, so a genuine rule whose description happens to
        mention a content migration is never discarded.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        [AllowNull()]
        [object]$Candidate
    )

    if ($null -eq $Candidate) { return $null }

    $read = {
        param($Source, [string]$Name)
        if ($null -eq $Source) { return $null }
        if ($Source -is [System.Collections.IDictionary]) {
            foreach ($key in $Source.Keys) { if ([string]$key -ieq $Name) { return $Source[$key] } }
            return $null
        }
        $property = $Source.PSObject.Properties | Where-Object { $_.Name -ieq $Name } | Select-Object -First 1
        if ($property) { return $property.Value }
        return $null
    }

    $properties = & $read $Candidate 'properties'

    # A query means it is a rule, whatever the description says.
    if ($null -ne (& $read $Candidate 'query')) { return $null }
    if ($null -ne $properties -and $null -ne (& $read $properties 'query')) { return $null }

    $description = & $read $Candidate 'description'
    if ($null -eq $description -and $null -ne $properties) { $description = & $read $properties 'description' }
    if ($description -isnot [string] -or [string]::IsNullOrWhiteSpace($description)) { return $null }

    $isPlaceholder = $false
    foreach ($marker in @((Get-SentinelRuleKind).PlaceholderMarkers)) {
        if ($marker -and $description -like "*$marker*") { $isPlaceholder = $true; break }
    }
    if (-not $isPlaceholder) { return $null }

    $match = [regex]::Match($description, 'https?://\S+?(?=[\s''"]|$)')
    if ($match.Success) { return $match.Value }
    return ''
}

function Test-RuleIsArmScaffold {
    <#
    .SYNOPSIS
        True when the candidate is a blank ARM authoring template rather than a rule.

    .DESCRIPTION
        A content repository ships templates for people to fill in — Azure-Sentinel has one
        at Tools/ARM-Templates/AnalyticsRules/ScheduledRule/ScheduledRule.json. Structurally
        it is indistinguishable from a rule: it declares a kind, a displayName, a query, a
        queryFrequency. Every one of those values is an ARM parameter reference with NO
        default, so what survives template resolution is the literal text
        "[parameters('query')]".

        That matters because the query is the decisive test for "is this a rule". A scaffold
        passes it, gets read as a rule with a query that is not KQL, and then vanishes
        during conversion — no verdict, no diagnostic, no line in the report. Found by
        counting: 5,162 rules read from the corpus, 5,161 converted.

        The guard keys on the QUERY specifically. A real rule can legitimately carry an
        unresolved parameter in a peripheral field — a threshold, a workspace name — and
        must not be discarded for it. A rule whose query is a parameter reference has no
        detection logic in it at all; there is nothing to migrate, and nothing failed to.

        -Template matters more than it looks. Content Hub mainTemplate.json routinely writes
        the query as "[parameters('query')]" WITH a default value holding the real KQL, and
        that is a perfectly good rule. Only a parameter that resolves to nothing is a
        scaffold, so the expression is resolved against the template first and the guard is
        applied to the RESULT. Testing the raw text instead would silently discard a large
        share of Content Hub content — a far worse bug than the one being fixed.

    .PARAMETER Candidate
        The rule or ARM resource to test.

    .PARAMETER Template
        The full ARM template, when there is one, so parameters() can be resolved before the
        query is judged.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter()]
        [AllowNull()]
        [object]$Candidate,

        [Parameter()]
        [AllowNull()]
        [PSObject]$Template
    )

    if ($null -eq $Candidate) { return $false }

    $read = {
        param($Source, [string]$Name)
        if ($null -eq $Source) { return $null }
        if ($Source -is [System.Collections.IDictionary]) {
            foreach ($key in $Source.Keys) { if ([string]$key -ieq $Name) { return $Source[$key] } }
            return $null
        }
        $property = $Source.PSObject.Properties | Where-Object { $_.Name -ieq $Name } | Select-Object -First 1
        if ($property) { return $property.Value }
        return $null
    }

    $query = & $read $Candidate 'query'
    if ($null -eq $query) {
        $properties = & $read $Candidate 'properties'
        if ($null -ne $properties) { $query = & $read $properties 'query' }
    }

    if ($query -isnot [string]) { return $false }

    # Not an ARM expression at all: an ordinary rule with an ordinary query.
    if ($query -notmatch "^\s*\[.*\]\s*$") { return $false }

    # Resolve it. A parameter WITH a default yields the real KQL and this is a rule; a
    # parameter with no default resolves to itself or to nothing, and that is a scaffold.
    $resolved = Resolve-ArmTemplateValue -Expression $query -Template $Template

    if ([string]::IsNullOrWhiteSpace($resolved)) { return $true }
    return ($resolved -match "^\s*\[\s*(parameters|variables)\s*\(.+\)\s*\]\s*$")
}

function Find-ArmAlertRuleResource {
    <#
    .SYNOPSIS
        Recursively collects Microsoft.SecurityInsights alertRules resources from an ARM
        template's resources array.

    .DESCRIPTION
        Content Hub mainTemplate.json files nest analytics rules several levels deep, under
        a contentTemplate resource whose own 'resources' array holds the alertRule. A flat
        scan of the top-level resources array misses every one of them.

        Matches both resource types Microsoft uses for analytics rules:
          Microsoft.SecurityInsights/alertRules
          Microsoft.OperationalInsights/workspaces/providers/alertRules
    #>
    [CmdletBinding()]
    [OutputType([PSObject])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Resources
    )

    foreach ($resource in $Resources) {
        if ($null -eq $resource) { continue }

        $type = [string]$resource.type
        if ($type -match '(?i)alertRules$') {
            $resource
        }

        # Nested resources (contentTemplate wrappers, child resources).
        if ($resource.PSObject.Properties['resources'] -and $resource.resources -is [System.Collections.IList]) {
            Find-ArmAlertRuleResource -Resources $resource.resources
        }
        # Content Hub wraps the real template under properties.mainTemplate.resources.
        if ($resource.PSObject.Properties['properties'] -and
            $resource.properties.PSObject.Properties['mainTemplate'] -and
            $resource.properties.mainTemplate.PSObject.Properties['resources'] -and
            $resource.properties.mainTemplate.resources -is [System.Collections.IList]) {
            Find-ArmAlertRuleResource -Resources $resource.properties.mainTemplate.resources
        }
        # A nested deployment (Microsoft.Resources/deployments) carries its own template
        # under properties.template.resources - the standard ARM way to nest, and the one
        # this walker did not follow until 2026-09-16. A templateLink points at a template
        # that is not in the file, so there is nothing to read; say so rather than skip.
        if ($resource.PSObject.Properties['properties'] -and $type -match '(?i)Microsoft\.Resources/deployments$') {
            if ($resource.properties.PSObject.Properties['template'] -and
                $resource.properties.template.PSObject.Properties['resources'] -and
                $resource.properties.template.resources -is [System.Collections.IList]) {
                Find-ArmAlertRuleResource -Resources $resource.properties.template.resources
            }
            elseif ($resource.properties.PSObject.Properties['templateLink']) {
                $link = $resource.properties.templateLink
                $uri = if ($link.PSObject.Properties['uri']) { [string]$link.uri } elseif ($link.PSObject.Properties['relativePath']) { [string]$link.relativePath } else { '' }
                Write-Warning ("Nested deployment '$([string]$resource.name)' references an external template" +
                    $(if ($uri) { " ($uri)" } else { '' }) + '. Its rules are not in this file and were not read.')
            }
        }
    }
}

function Test-SentinelRuleShape {
    <#
    .SYNOPSIS
        Returns $true when an object looks like a Sentinel analytics rule.

    .DESCRIPTION
        An object is an analytics rule when it has a KQL query, OR declares a kind this
        module recognises as a Sentinel rule kind, OR carries a field only analytics rules
        have (query frequency, trigger, tactics, entity mappings).

        The kind and field checks matter for opposite reasons. Rules of a non-convertible
        kind (Fusion, ThreatIntelligence and friends) have no query but must still be
        reported, so they are accepted here and rejected later with a Blocking diagnostic
        that explains why. Meanwhile a Content Hub solution folder is full of YAML and JSON
        that has a name but is not a rule at all: data connector definitions, DCR
        templates, table schemas, solution metadata. Accepting those would flood an
        assessment with hundreds of fictitious "blocked rules" and make the report useless.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter()]
        [AllowNull()]
        [object]$Candidate
    )

    if ($null -eq $Candidate) { return $false }
    if ($Candidate -is [string] -or $Candidate -is [System.ValueType]) { return $false }

    # Collect member names from the root and from .properties (ARM nests everything there).
    $names = @()
    $getValue = {
        param($Source, [string]$Name)
        if ($null -eq $Source) { return $null }
        if ($Source -is [System.Collections.IDictionary]) {
            foreach ($key in $Source.Keys) { if ([string]$key -ieq $Name) { return $Source[$key] } }
            return $null
        }
        $property = $Source.PSObject.Properties | Where-Object { $_.Name -ieq $Name } | Select-Object -First 1
        if ($property) { return $property.Value }
        return $null
    }

    if ($Candidate -is [System.Collections.IDictionary]) {
        $names = @($Candidate.Keys | ForEach-Object { [string]$_ })
    } else {
        $names = @($Candidate.PSObject.Properties.Name)
    }
    $properties = & $getValue $Candidate 'properties'
    if ($null -ne $properties) {
        if ($properties -is [System.Collections.IDictionary]) {
            $names += @($properties.Keys | ForEach-Object { [string]$_ })
        } elseif ($properties.PSObject) {
            $names += @($properties.PSObject.Properties.Name)
        }
    }

    function Test-HasMember {
        param([string[]]$Names, [string]$Wanted)
        foreach ($name in $Names) { if ($name -ieq $Wanted) { return $true } }
        return $false
    }

    # 1. A query is decisive — unless the query is itself an unresolved ARM parameter, in
    #    which case this is a blank authoring template and there is no detection in it.
    if (Test-HasMember -Names $names -Wanted 'query') {
        if (Test-RuleIsArmScaffold -Candidate $Candidate) { return $false }
        return $true
    }

    # 1b. No query, and a description that says the rule moved: this is a redirect stub, not
    #     a rule. Content repositories leave them behind — 312 in Azure-Sentinel alone. They
    #     declare a kind, so check 2 below would accept them and the converter would then
    #     report each one as a Blocked rule that "has no KQL query", which is true and
    #     useless: nothing failed to migrate, there was never a detection here. Checked
    #     before the kind so the kind cannot rescue them, and only when there is no query so
    #     a real rule mentioning a migration in its description is never discarded.
    if ($null -ne (Get-RulePlaceholderTarget -Candidate $Candidate)) { return $false }

    # 2. A recognised Sentinel rule kind is decisive, including the non-convertible ones.
    $kindValue = & $getValue $Candidate 'kind'
    if ($null -eq $kindValue -and $null -ne $properties) { $kindValue = & $getValue $properties 'kind' }
    if ($kindValue -is [string] -and -not [string]::IsNullOrWhiteSpace($kindValue)) {
        if ((Get-SentinelRuleKind -Kind $kindValue).IsKnown) { return $true }
    }

    # 3. A field only an analytics rule carries.
    foreach ($marker in @('queryFrequency', 'queryPeriod', 'triggerOperator', 'triggerThreshold',
                          'tactics', 'entityMappings', 'relevantTechniques', 'alertRuleTemplateName')) {
        if (Test-HasMember -Names $names -Wanted $marker) { return $true }
    }

    return $false
}
