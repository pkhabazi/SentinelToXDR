function ConvertFrom-SentinelToCustomDetection {
    <#
    .SYNOPSIS
        Converts a normalized Sentinel analytics rule object to an XDR custom detection YAML hashtable.

    .DESCRIPTION
        Performs the field mapping from a Microsoft Sentinel Scheduled (or NRT) analytics rule
        to the XDR custom detection YAML schema. Handles both the community / content-hub YAML
        format and the ARM template JSON format (the latter has properties nested under a
        'properties' sub-object which this function normalizes automatically).

        Mapping gaps are reported via Write-Warning. Callers should surface any interactive
        confirmations (e.g. multiple-tactic selection) before invoking this function, using
        the OverrideAlertCategory parameter to pass the confirmed choice.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSObject]$SentinelObject,

        [Parameter()]
        [bool]$SetEnabled,

        [Parameter()]
        [ValidateSet('Informational', 'Low', 'Medium', 'High')]
        [string]$SetSeverity,

        [Parameter()]
        [ValidateSet(
            'CredentialAccess', 'DefenseEvasion', 'Discovery', 'Execution', 'Exfiltration',
            'Impact', 'InitialAccess', 'LateralMovement', 'Persistence', 'PrivilegeEscalation',
            'Collection', 'CommandAndControl', 'SuspiciousActivity'
        )]
        [string]$OverrideAlertCategory,

        [Parameter()]
        [string]$OverrideAlertTitle,

        [Parameter()]
        [string]$OverrideGuid,

        # The normalizer resolves durations the raw rule expresses in shapes this function
        # cannot parse: a .NET TimeSpan string ('06:00:00') or a serialized TimeSpan OBJECT
        # with Ticks members, which some solutions ship. Reading the raw value in that case
        # yields an unparseable string and a silent fall back to the shortest frequency —
        # so the caller passes the normalized value in.
        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$OverrideQueryFrequency,

        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$OverrideQueryPeriod,

        # Opt-in: surface the Feature F native-remediation-actions enrichment
        # opportunity diagnostic. Off by default (it is a per-batch enrichment
        # note, not a per-rule finding, so it would otherwise be pure noise).
        [Parameter()]
        [switch]$SuggestRemediationActions,

        # Optional [ref] to a list the caller passes in. Structured conversion
        # diagnostics are appended to it. Kept out of the returned ordered hashtable
        # so the serialized YAML is unchanged.
        [Parameter()]
        [ref]$DiagnosticsRef,

        # Set when the caller renders the GRAPH shape. Several diagnostics below describe
        # limitations of the legacy flat shape rather than of the target, and stating them
        # for a Graph conversion is simply wrong:
        #
        #   * Multi-tactic drops. The Graph model carries a tactics collection, so nothing
        #     is dropped to fit one category. Resolve-GraphTactic reports what really
        #     happened.
        #   * Entity mapping. The legacy map treats File, MailMessage, AzureResource and
        #     friends as having no XDR equivalent, which the Graph entity model disproves.
        #     Resolve-GraphEntityMapping maps them.
        #
        # Suppressed here rather than filtered later, so a false finding never reaches a
        # report in the first place.
        [Parameter()]
        [switch]$GraphShape,

        # Optional [ref] receiving every value this function RESOLVED (guid, severity,
        # frequency in both representations, final title/description, tactics,
        # techniques, custom details, table classification). The Graph renderer builds
        # its output from these, so the two output shapes share one decision engine
        # instead of each re-deriving frequency, MITRE and capability gating.
        [Parameter()]
        [ref]$DecisionRef
    )

    # -------------------------------------------------------------------------
    # Diagnostics sink. Every refactored Write-Warning site builds a structured
    # record here AND still emits the original Write-Warning text (back-compat).
    # The doc anchor base is shared across records.
    # -------------------------------------------------------------------------
    $docBase = 'Feature comparison- Microsoft Sentinel analytics rules and Microsoft Defender custom detections.md'
    $diagnostics = [System.Collections.Generic.List[object]]::new()

    # Build a diagnostic, emit its Reason as a Write-Warning (verbatim), and record it.
    function Add-Diagnostic {
        param(
            [string]$Feature,
            [string]$Capability,
            [string]$Severity,
            [string]$Action,
            [object]$SourceValue = $null,
            [object]$TargetValue = $null,
            [string]$Reason,
            [string]$DocReference = $docBase
        )
        $record = New-ConversionDiagnostic -Feature $Feature -Capability $Capability `
            -Severity $Severity -Action $Action -SourceValue $SourceValue `
            -TargetValue $TargetValue -Reason $Reason -DocReference $DocReference
        $diagnostics.Add($record)
        Write-Warning $record.Reason
    }

    # -------------------------------------------------------------------------
    # Helper: does this object have this member, and what is its value?
    #
    # Community YAML parses to a Hashtable and ARM JSON to a PSCustomObject. On a
    # Hashtable, $obj.PSObject.Properties['name'] returns NOTHING for a key —
    # PSObject exposes Count/Keys/Values, not the entries. Any presence check
    # written that way silently answers "absent" for every YAML rule, which is
    # how the whole feature-gap sweep (suppression, event grouping, incident
    # configuration, custom details, dynamic alert details) came to be skipped
    # for exactly the input format most community content ships in.
    #
    # Member lookup is case-insensitive, matching PowerShell property access.
    # -------------------------------------------------------------------------
    function Test-HasMember {
        param([object]$Source, [string]$Name)
        if ($null -eq $Source) { return $false }
        if ($Source -is [System.Collections.IDictionary]) {
            foreach ($key in $Source.Keys) { if ([string]$key -ieq $Name) { return $true } }
            return $false
        }
        return [bool]($Source.PSObject.Properties | Where-Object { $_.Name -ieq $Name })
    }

    function Get-MemberValue {
        param([object]$Source, [string]$Name)
        if ($null -eq $Source) { return $null }
        if ($Source -is [System.Collections.IDictionary]) {
            foreach ($key in $Source.Keys) { if ([string]$key -ieq $Name) { return $Source[$key] } }
            return $null
        }
        $property = $Source.PSObject.Properties | Where-Object { $_.Name -ieq $Name } | Select-Object -First 1
        if ($property) { return $property.Value }
        return $null
    }

    # -------------------------------------------------------------------------
    # Helper: parse an ISO 8601 duration or community shorthand into total hours
    # -------------------------------------------------------------------------
    function ConvertFrom-IsoDuration {
        param([string]$Duration)

        if ([string]::IsNullOrWhiteSpace($Duration)) { return $null }

        # Community shorthand: 30m, 1h, 6h, 1d, 1w (case-insensitive)
        if ($Duration -match '^(\d+(?:\.\d+)?)\s*(m|h|d|w)$') {
            $value = [double]$Matches[1]
            $multiplier = switch ($Matches[2].ToLower()) {
                'm' { 1.0 / 60.0 }
                'h' { 1.0 }
                'd' { 24.0 }
                'w' { 168.0 }
                default { 1.0 }
            }
            return $value * $multiplier
        }

        # ISO 8601: P[nW][nD][T[nH][nM][nS]]
        if ($Duration -match '^P(?:(\d+)W)?(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?$') {
            $weeks   = if ($Matches[1]) { [double]$Matches[1] } else { 0 }
            $days    = if ($Matches[2]) { [double]$Matches[2] } else { 0 }
            $hours   = if ($Matches[3]) { [double]$Matches[3] } else { 0 }
            $minutes = if ($Matches[4]) { [double]$Matches[4] } else { 0 }
            $seconds = if ($Matches[5]) { [double]$Matches[5] } else { 0 }
            return ($weeks * 168.0) + ($days * 24.0) + $hours + ($minutes / 60.0) + ($seconds / 3600.0)
        }

        return $null
    }

    # -------------------------------------------------------------------------
    # Helper: round total hours to the nearest valid XDR schedule bucket.
    #
    # DATA-DRIVEN: the candidate buckets are derived from the psd1 — the non-'0'
    # keys of FixedLookbackPerFrequency (e.g. '1H','3H','12H','24H'), parsed to
    # hours via their leading number. The rounding boundary between two adjacent
    # buckets is their arithmetic mean (midpoint); a source frequency is assigned
    # to the LOWER bucket while it is strictly below the midpoint, and to the upper
    # bucket at/above it — i.e. ties go UP. This reproduces the previous hardcoded
    # midpoints exactly (1/3 -> 2.0, 3/12 -> 7.5, 12/24 -> 18.0) while making the
    # bucket set a pure data edit. Adding e.g. a '6H' default frequency to the psd1
    # automatically inserts a new bucket (and its midpoints) with no code change.
    #
    #   -Buckets : ordered double[] of bucket hour-values (ascending), from data.
    #   -Labels  : parallel string[] of the bucket enum labels ('1H', ...).
    # Sets WasRounded.Value = $true unless the source equals the chosen bucket.
    # -------------------------------------------------------------------------
    function ConvertTo-XdrFrequency {
        param(
            [double]$TotalHours,
            [double[]]$Buckets,
            [string[]]$Labels,
            [ref]$WasRounded
        )

        # Walk ascending: stay in bucket i while below the midpoint to bucket i+1.
        $index = $Buckets.Count - 1
        for ($i = 0; $i -lt $Buckets.Count - 1; $i++) {
            $midpoint = ($Buckets[$i] + $Buckets[$i + 1]) / 2.0
            if ($TotalHours -lt $midpoint) { $index = $i; break }
        }

        $WasRounded.Value = $TotalHours -ne $Buckets[$index]
        return $Labels[$index]
    }

    # -------------------------------------------------------------------------
    # Helper: render a number of total hours as a canonical ISO 8601 duration.
    # Used for the FLEXIBLE (SentinelOnly) frequency + lookback representation.
    # See the "FIELD-NAME / REPRESENTATION ASSUMPTIONS" block below.
    #   - Whole days  -> P{n}D     (e.g. 14d -> 'P14D')
    #   - Sub-day     -> PT{h}H[{m}M]  (e.g. 0.75h -> 'PT45M', 6h -> 'PT6H')
    # -------------------------------------------------------------------------
    function ConvertTo-IsoDuration {
        param([double]$TotalHours)

        # '0' means NRT/continuous (no window). This is only legitimately reached for
        # the lookback of an NRT rule. Callers on the SCHEDULED frequency path guard
        # against zero/non-positive source frequencies BEFORE calling this helper, so
        # a scheduled rule never silently coerces to a continuous '0' here.
        if ($TotalHours -le 0) { return '0' }

        # Exact whole-day values render as P{n}D for readability/round-tripping.
        if (($TotalHours % 24.0) -eq 0) {
            return "P$([int]($TotalHours / 24.0))D"
        }

        $wholeHours = [int][Math]::Floor($TotalHours)
        $minutes    = [int][Math]::Round(($TotalHours - $wholeHours) * 60.0)
        if ($minutes -eq 60) { $wholeHours += 1; $minutes = 0 }

        $time = 'PT'
        if ($wholeHours -gt 0) { $time += "${wholeHours}H" }
        if ($minutes -gt 0)    { $time += "${minutes}M" }
        if ($time -eq 'PT')    { $time = 'PT0H' }
        return $time
    }

    # -------------------------------------------------------------------------
    # Normalize: ARM template format has properties nested under '.properties'
    # -------------------------------------------------------------------------
    $isArmFormat = (Test-HasMember -Source $SentinelObject -Name 'properties') -and
                   ($SentinelObject.type -eq 'Microsoft.SecurityInsights/alertRules' -or
                    $null -ne $SentinelObject.kind)
    $props = if ($isArmFormat) { $SentinelObject.properties } else { $SentinelObject }

    # -------------------------------------------------------------------------
    # Kind (Scheduled vs NRT)
    # -------------------------------------------------------------------------
    $kindValue = if ($SentinelObject.kind) { [string]$SentinelObject.kind }
                 elseif ($props.kind) { [string]$props.kind }
                 else { 'Scheduled' }
    $isNrt = $kindValue -ieq 'NRT'

    # -------------------------------------------------------------------------
    # Display name  (community YAML: 'name'; ARM: 'properties.displayName')
    # -------------------------------------------------------------------------
    $displayName = if ($props.displayName) { [string]$props.displayName }
                   elseif ($SentinelObject.name) { [string]$SentinelObject.name }
                   else { '' }

    # A name is untrusted input: community content, or a file someone else wrote. Control
    # codes and Unicode bidirectional overrides (U+202A-U+202E, U+2066-U+2069) survive
    # every step of the conversion and end up in the portal, in filenames and in every
    # report, where an override reorders the visible text. Strip them and say so; a name
    # that reads differently from its source is worth a finding, not a silent fix.
    $unsafeNamePattern = '[\p{Cc}\u202A-\u202E\u2066-\u2069]'
    if ($displayName -match $unsafeNamePattern) {
        $codePoints = @([regex]::Matches($displayName, $unsafeNamePattern) |
            ForEach-Object { 'U+{0:X4}' -f [int][char]$_.Value } | Select-Object -Unique)
        # Tabs and newlines become a space so words stay apart; every other control code
        # and every override is deleted; runs of spaces collapse.
        $cleaned = (([regex]::Replace(($displayName -replace '[\t\r\n]', ' '), $unsafeNamePattern, '')) -replace '\s+', ' ').Trim()
        Add-Diagnostic -Feature 'Rules management' -Capability 'Manage rules from API' `
            -Severity 'Warning' -Action 'Constrained' -SourceValue $displayName -TargetValue 'DisplayNameSanitised' `
            -Reason ("Rule name contained $($codePoints -join ', ') (control or bidirectional-override characters). " +
            "They were removed; the detection is named '$cleaned'.")
        $displayName = $cleaned
    }
    # An empty name is resolved after the GUID below, so the placeholder can carry the id.
    $displayNameMissing = [string]::IsNullOrWhiteSpace($displayName)

    # -------------------------------------------------------------------------
    # GUID  (community YAML: 'id'; ARM resource: 'name' when GUID-shaped)
    # -------------------------------------------------------------------------
    $uuidPattern = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
    $sourceGuid = if ($PSBoundParameters.ContainsKey('OverrideGuid') -and $OverrideGuid) {
        $OverrideGuid
    } elseif ($SentinelObject.id -and [string]$SentinelObject.id -match $uuidPattern) {
        [string]$SentinelObject.id
    } elseif ($SentinelObject.name -and [string]$SentinelObject.name -match $uuidPattern) {
        [string]$SentinelObject.name
    } else {
        $newGuid = [System.Guid]::NewGuid().ToString()
        Add-Diagnostic -Feature 'Rules management' -Capability 'Manage rules from API' `
            -Severity 'Warning' -Action 'RequiresReview' -SourceValue $null -TargetValue $newGuid `
            -Reason "No UUID found in Sentinel rule '$displayName'. A new GUID has been generated: $newGuid. Use -Guid to specify one explicitly."
        $newGuid
    }

    if ($displayNameMissing) {
        # displayName is required by the schema (minLength 1), so an empty one is refused
        # before anything else is looked at. The placeholder is derived from the id, which
        # is transparent and reversible, and the finding says exactly what happened.
        $displayName = "Unnamed rule $sourceGuid"
        Add-Diagnostic -Feature 'Rules management' -Capability 'Manage rules from API' `
            -Severity 'Warning' -Action 'RequiresReview' -SourceValue $null -TargetValue 'DisplayNameMissing' `
            -Reason ("The rule has no display name. displayName is mandatory on a custom detection, so it was named " +
            "'$displayName' after its id. Give the source rule a real name before deploying.")
    }

    # -------------------------------------------------------------------------
    # Description
    # -------------------------------------------------------------------------
    $description = if ($props.description) { [string]$props.description }
                   elseif ($SentinelObject.description) { [string]$SentinelObject.description }
                   else { '' }

    # -------------------------------------------------------------------------
    # Severity
    # -------------------------------------------------------------------------
    $sentinelSeverity = if ($props.severity) { [string]$props.severity }
                        elseif ($SentinelObject.severity) { [string]$SentinelObject.severity }
                        else { 'Medium' }
    $severity = if ($PSBoundParameters.ContainsKey('SetSeverity')) { $SetSeverity } else { $sentinelSeverity }

    # -------------------------------------------------------------------------
    # isEnabled  (ARM: 'enabled'; community YAML: 'status')
    # -------------------------------------------------------------------------
    $rawEnabled = if ($null -ne $props.enabled) { $props.enabled }
                  elseif ($null -ne $SentinelObject.enabled) { $SentinelObject.enabled }
                  else { $null }
    $sentinelEnabled = if ($null -ne $rawEnabled) { [bool]$rawEnabled }
                       else {
                           $status = if ($SentinelObject.status) { [string]$SentinelObject.status } else { 'Available' }
                           $status -ine 'Deprecated'
                       }
    $isEnabled = if ($PSBoundParameters.ContainsKey('SetEnabled')) { $SetEnabled } else { $sentinelEnabled }

    # -------------------------------------------------------------------------
    # KQL query
    # -------------------------------------------------------------------------
    $queryText = if ($props.query) { [string]$props.query }
                 elseif ($SentinelObject.query) { [string]$SentinelObject.query }
                 else { '' }

    # -------------------------------------------------------------------------
    # Classify the query by the data tier of its tables (Stage 1). Binary rule:
    # tables in the Defender XDR catalog are Defender; everything else is Sentinel.
    # The classification is surfaced as a precise diagnostic (replacing the old
    # universal "may reference Sentinel-specific tables" warning) and attached to
    # its TargetValue so Stage 2 (frequency/lookback) can consume it. The serialized
    # YAML output is unchanged here — no frequency logic changes in this stage.
    # -------------------------------------------------------------------------
    $tableClassification = Get-QueryTableClassification -Query $queryText
    $unifiedSocCaveat = ("These Sentinel-tier tables are available in XDR only when Microsoft " +
        "Sentinel Unified SOC (the Defender portal integration) is enabled. If Unified SOC is " +
        "not enabled, review and adapt the query before deploying to XDR.")

    switch ($tableClassification.Classification) {
        'DefenderOnly' {
            Add-Diagnostic -Feature 'Rule data' -Capability 'Defender XDR data' `
                -Severity 'Info' -Action 'Mapped' `
                -SourceValue ($tableClassification.ReferencedTables -join ', ') `
                -TargetValue $tableClassification.Classification `
                -Reason ("The KQL query in rule '$displayName' references only native Defender XDR " +
                "tables [$($tableClassification.DefenderTables -join ', ')]. No Sentinel-tier data is required.")
        }
        'Mixed' {
            Add-Diagnostic -Feature 'Rule data' -Capability 'Sentinel analytics tier' `
                -Severity 'Warning' -Action 'RequiresReview' `
                -SourceValue ($tableClassification.ReferencedTables -join ', ') `
                -TargetValue $tableClassification.Classification `
                -Reason ("The KQL query in rule '$displayName' references both Defender XDR tables " +
                "[$($tableClassification.DefenderTables -join ', ')] and Sentinel-tier tables " +
                "[$($tableClassification.SentinelTables -join ', ')]. $unifiedSocCaveat " +
                "This Mixed classification will constrain frequency/lookback options.")
        }
        default {
            # SentinelOnly (including the empty/unparseable default).
            $tableList = if ($tableClassification.SentinelTables.Count -gt 0) {
                "[$($tableClassification.SentinelTables -join ', ')]"
            } else { '(no tables detected)' }
            Add-Diagnostic -Feature 'Rule data' -Capability 'Sentinel analytics tier' `
                -Severity 'Warning' -Action 'RequiresReview' `
                -SourceValue ($tableClassification.ReferencedTables -join ', ') `
                -TargetValue $tableClassification.Classification `
                -Reason ("The KQL query in rule '$displayName' uses only Sentinel-tier tables " +
                "$tableList. $unifiedSocCaveat")
        }
    }

    # -------------------------------------------------------------------------
    # Workspace-only query dependencies — the false-green check.
    #
    # Table classification asks WHICH tables the query reads. This asks whether
    # the query can run at all: a watchlist, an ASIM parser, a saved function or
    # a cross-workspace reference exists only in the Log Analytics workspace, and
    # advanced hunting has no equivalent. The rule around such a query converts
    # perfectly and the detection then fails on its first run, which is the most
    # expensive answer this module can give. Warn instead.
    #
    # Heuristic, and biased toward speaking up. Test-XDRDetectionQuery settles it.
    # -------------------------------------------------------------------------
    $dependencyRules = Get-QueryDependencyRule
    foreach ($dependency in (Get-QueryDependency -Query $queryText)) {
        $occurrence = if ($dependency.Count -gt 1) { " ($($dependency.Count) occurrences)" } else { '' }
        Add-Diagnostic -Feature $dependencyRules.Feature -Capability $dependencyRules.Capability `
            -Severity $dependency.Severity -Action $dependency.Action `
            -SourceValue $dependency.Match -TargetValue $dependency.Name `
            -Reason ("The KQL query in rule '$displayName' $($dependency.Reason)" +
            " Detected from '$($dependency.Match)'$occurrence. Test-XDRDetectionQuery confirms " +
            "this against a live tenant.") `
            -DocReference 'https://learn.microsoft.com/defender-xdr/advanced-hunting-schema-tables'
    }

    # =========================================================================
    # Query frequency + lookback (Stage 2 — the keystone gap)
    # =========================================================================
    #
    # FIELD-NAME / REPRESENTATION ASSUMPTIONS  (CONFIRM against the real
    # Graph custom-detection API / XDRConverter schema before deploying):
    #
    #   * Flexible-frequency REPRESENTATION = ISO 8601 duration strings
    #     (e.g. 'PT45M', 'PT6H', 'P14D'). Chosen over shorthand ('45m','6h','14d')
    #     because ISO 8601 round-trips unambiguously (no m=minute/month clash) and
    #     matches the source queryFrequency/queryPeriod format. The legacy
    #     CONSTRAINED path still emits the enum strings ('0','1H','3H','12H','24H').
    #
    #   * OUTPUT FIELD NAMES:
    #       - 'frequency'      = scheduled value. CONSTRAINED rules keep the legacy
    #                            enum; FLEXIBLE rules carry an ISO 8601 string.
    #       - 'lookbackPeriod' = NEW lookback field (ISO 8601 / '0'). This name is
    #                            an ASSUMPTION — the downstream deploy target may
    #                            call it 'period', 'lookback', or 'lookbackPeriod'.
    #                            If it differs, change the key here + in
    #                            $defaultSortOrder + CustomDetection.schema.json.
    #
    # Behavior is driven by the Stage 1 table classification computed ONCE above
    # ($tableClassification) — no re-classification here:
    #   SentinelOnly      -> FLEXIBLE  : carry source freq + period, clamp to parity.
    #   DefenderOnly/Mixed -> CONSTRAINED: round freq to legacy enum, default lookback.
    #   NRT (kind=NRT)    -> Stage 3 decisioning: continuous '0' ONLY when the query
    #                        is NRT-compatible (Test-NrtQueryCompatibility); otherwise
    #                        downgraded to the shortest scheduled frequency + diagnosed.
    #
    # Tunables (parity limits, default set, default-lookback map) live in
    # src/Data/FrequencyLookbackRules.psd1 — edit data, not code, when MS shifts.
    # -------------------------------------------------------------------------
    $flRules     = Get-FrequencyLookbackRules
    $parity      = $flRules.Parity
    $defaultLook = $flRules.FixedLookbackPerFrequency

    # Resolve the maximum lookback allowed for a given frequency on Sentinel-tier
    # data. The tiers are ordered by frequency; the first whose upper bound the
    # frequency falls under wins, and a bound of 0 means "no upper bound".
    function Get-LookbackTier {
        param([double]$FrequencyHours)
        foreach ($tier in $parity.Tiers) {
            $bound = [double]$tier.MaxFrequencyHoursExclusive
            if ($bound -le 0 -or $FrequencyHours -lt $bound) { return $tier }
        }
        return $parity.Tiers[-1]
    }
    $isConstrained = $tableClassification.Classification -in @('DefenderOnly', 'Mixed')

    # Derive the constrained scheduled-rounding buckets from the psd1 (single source
    # of truth): every default-frequency label except the NRT '0', parsed to hours
    # via its leading number ('1H'=1, '3H'=3, '12H'=12, '24H'=24), ascending. Adding
    # or removing a default frequency in the psd1 reshapes the buckets with no code
    # change. The smallest non-zero bucket is also the zero/invalid-frequency fallback.
    $scheduledLabels = @($defaultLook.Keys | Where-Object { $_ -ne '0' })
    $bucketPairs = foreach ($label in $scheduledLabels) {
        if ($label -match '^(\d+(?:\.\d+)?)\s*[Hh]?$') {
            [PSCustomObject]@{ Label = $label; Hours = [double]$Matches[1] }
        }
    }
    $bucketPairs   = @($bucketPairs | Sort-Object Hours)
    $bucketHours   = @($bucketPairs.Hours)
    $bucketLabels  = @($bucketPairs.Label)
    $shortestFreq  = $bucketLabels[0]   # smallest / most-frequent scheduled bucket

    $queryFrequencyStr = if ($PSBoundParameters.ContainsKey('OverrideQueryFrequency') -and $OverrideQueryFrequency) {
                             $OverrideQueryFrequency
                         } elseif ($props.queryFrequency) { [string]$props.queryFrequency }
                         elseif ($SentinelObject.queryFrequency) { [string]$SentinelObject.queryFrequency }
                         else { '' }
    $queryPeriodStr = if ($PSBoundParameters.ContainsKey('OverrideQueryPeriod') -and $OverrideQueryPeriod) {
                          $OverrideQueryPeriod
                      } elseif ($props.queryPeriod) { [string]$props.queryPeriod }
                      elseif ($SentinelObject.queryPeriod) { [string]$SentinelObject.queryPeriod }
                      else { '' }

    $xdrFrequency = '1H'
    $xdrLookback  = $null

    if ($isNrt) {
        # ---- NRT / continuous decisioning (Stage 3).
        # A Sentinel NRT rule maps to a Defender XDR "Continuous (NRT)" custom
        # detection, which runs on a single streaming table and supports only a
        # restricted subset of KQL (no join/union/externaldata, single table, no
        # comments). Validate the query; only emit continuous ('0') when it is
        # actually NRT-compatible. Otherwise DOWNGRADE to the shortest scheduled
        # frequency + matched default lookback and diagnose WHY (which constructs).
        $nrtDocRef = "$docBase | https://learn.microsoft.com/en-us/defender-xdr/custom-detection-rules#queries-you-can-run-continuously"
        $nrtCheck  = Test-NrtQueryCompatibility -Query $queryText

        if ($nrtCheck.IsCompatible) {
            $xdrFrequency = '0'
            $xdrLookback  = $defaultLook['0']
            Add-Diagnostic -Feature 'Rule frequency' -Capability 'Near-real-time (NRT) rules on Sentinel data' `
                -Severity 'Info' -Action 'Mapped' -SourceValue 'NRT' -TargetValue '0' `
                -Reason ("Rule '$displayName' is a near-real-time (NRT) rule and its query is compatible " +
                "with Defender XDR Continuous (NRT) frequency (single table, no join/union/externaldata, " +
                "no comments). Emitting continuous frequency '0'.") `
                -DocReference $nrtDocRef
        }
        else {
            # Not continuous-compatible: fall back to the shortest scheduled bucket.
            $xdrFrequency = $shortestFreq
            $xdrLookback  = $defaultLook[$xdrFrequency]
            $violationList = ($nrtCheck.Violations -join ', ')
            Add-Diagnostic -Feature 'Rule frequency' -Capability 'Near-real-time (NRT) rules on Sentinel data' `
                -Severity 'Warning' -Action 'Constrained' -SourceValue 'NRT (frequency 0)' -TargetValue $xdrFrequency `
                -Reason ("Rule '$displayName' is a near-real-time (NRT) rule, but its query uses construct(s) " +
                "not allowed in Defender XDR Continuous (NRT) detections: [$violationList]. " +
                "Continuous queries must reference a single table and may not use joins, unions, the " +
                "externaldata operator, or comments. The rule was DOWNGRADED from continuous to the shortest " +
                "supported scheduled frequency '$xdrFrequency' (lookback '$xdrLookback'). Rewrite the query to " +
                "remove the listed construct(s) to restore continuous (NRT) behavior.") `
                -DocReference $nrtDocRef

            # If the rule additionally references Sentinel-tier / Mixed data, note that
            # NRT eligibility also depends on the data tier (the KQL gate above is the
            # primary decision; this is an informational aid, not a separate gate).
            if ($tableClassification.Classification -eq 'Mixed') {
                Add-Diagnostic -Feature 'Rule frequency' -Capability 'Near-real-time (NRT) rules on Sentinel data' `
                    -Severity 'Info' -Action 'RequiresReview' `
                    -SourceValue $tableClassification.Classification -TargetValue $xdrFrequency `
                    -Reason ("Rule '$displayName' also has a Mixed data classification " +
                    "[$($tableClassification.ReferencedTables -join ', ')]; continuous (NRT) frequency requires the " +
                    "query to target a single supported streaming table. Review the data tier alongside the KQL fix.") `
                    -DocReference $nrtDocRef
            }
        }
    }
    elseif ($isConstrained) {
        # ---- CONSTRAINED path (DefenderOnly / Mixed).
        #
        # Custom frequency and a configurable lookback are available ONLY when the
        # detection reads Microsoft Sentinel data exclusively. One Defender table in
        # the query is enough to lose both, which is why Mixed is constrained here
        # rather than treated as a Sentinel rule that happens to touch Defender data.
        #
        # For a Mixed rule that constraint is worth explaining, because it is
        # actionable: the rule could keep its schedule if the Defender table were
        # removed or the query split in two. Name the tables that caused it.
        $supportedList = ('0 (NRT), ' + ($bucketLabels -join ', '))
        $mixedTierNote = if ($tableClassification.Classification -eq 'Mixed') {
            (" Custom frequency is available only to detections that read Microsoft Sentinel " +
             "data exclusively. This query also reads Defender table(s) " +
             "[$($tableClassification.DefenderTables -join ', ')], which forfeits it for the whole rule. " +
             "Splitting the Defender table into its own detection would let the Sentinel part keep its " +
             "original schedule.")
        } else { '' }
        if (-not [string]::IsNullOrWhiteSpace($queryFrequencyStr)) {
            $totalHours = ConvertFrom-IsoDuration -Duration $queryFrequencyStr
            if ($null -ne $totalHours -and $totalHours -gt 0) {
                $wasRounded = $false
                $xdrFrequency = ConvertTo-XdrFrequency -TotalHours $totalHours `
                    -Buckets $bucketHours -Labels $bucketLabels -WasRounded ([ref]$wasRounded)
                if ($wasRounded) {
                    Add-Diagnostic -Feature 'Rule frequency' -Capability 'Support flexible and high frequency for Sentinel data' `
                        -Severity 'Warning' -Action 'Rounded' -SourceValue $queryFrequencyStr -TargetValue $xdrFrequency `
                        -Reason ("Query frequency '$queryFrequencyStr' (~$([Math]::Round($totalHours, 2))h) " +
                        "was rounded to '$xdrFrequency' — the nearest supported XDR frequency. " +
                        "Supported values are: $supportedList.$mixedTierNote")
                }
            } elseif ($null -ne $totalHours) {
                # A genuine ZERO / non-positive SCHEDULED frequency must NOT silently
                # become NRT/continuous ('0'). Fall back to the shortest constrained
                # default frequency and diagnose the fallback. (NRT rules take the
                # kind=NRT branch above and still emit '0'.)
                $xdrFrequency = $shortestFreq
                Add-Diagnostic -Feature 'Rule frequency' -Capability 'Support flexible and high frequency for Sentinel data' `
                    -Severity 'Warning' -Action 'Constrained' -SourceValue $queryFrequencyStr -TargetValue $xdrFrequency `
                    -Reason ("Query frequency '$queryFrequencyStr' is zero/non-positive but the rule is " +
                    "scheduled (not NRT). A zero scheduled frequency would silently become a continuous " +
                    "detection, so it was constrained to the shortest supported frequency '$xdrFrequency'. " +
                    "Supported values are: $supportedList.")
            } else {
                $xdrFrequency = $shortestFreq
                Add-Diagnostic -Feature 'Rule frequency' -Capability 'Support flexible and high frequency for Sentinel data' `
                    -Severity 'Warning' -Action 'RequiresReview' -SourceValue $queryFrequencyStr -TargetValue $xdrFrequency `
                    -Reason "Unable to parse query frequency '$queryFrequencyStr'. Defaulting to '$xdrFrequency'."
            }
        } else {
            $xdrFrequency = $shortestFreq
            Add-Diagnostic -Feature 'Rule frequency' -Capability 'Support flexible and high frequency for Sentinel data' `
                -Severity 'Warning' -Action 'RequiresReview' -SourceValue $null -TargetValue $xdrFrequency `
                -Reason "No queryFrequency found in rule '$displayName'. Defaulting to '$xdrFrequency'."
        }

        # Defender-tier data applies a FIXED lookback derived from the frequency;
        # it is not a field the API accepts and the converter does not emit one.
        # What matters to the user is whether that fixed window is smaller than
        # the window their rule asked for, because then the detection genuinely
        # sees less data than the Sentinel rule did.
        $xdrLookback = $defaultLook[$xdrFrequency]
        if (-not [string]::IsNullOrWhiteSpace($queryPeriodStr)) {
            $sourcePeriodHours = ConvertFrom-IsoDuration -Duration $queryPeriodStr
            $fixedPeriodHours  = ConvertFrom-IsoDuration -Duration $xdrLookback

            if ($null -ne $sourcePeriodHours -and $null -ne $fixedPeriodHours -and
                $sourcePeriodHours -gt $fixedPeriodHours) {
                Add-Diagnostic -Feature 'Rule lookback' -Capability 'Lookback support' `
                    -Severity 'Warning' -Action 'Constrained' -SourceValue $queryPeriodStr -TargetValue $xdrLookback `
                    -Reason ("Rule '$displayName' looks back '$queryPeriodStr' " +
                    "(~$([Math]::Round($sourcePeriodHours, 2))h), but it references Defender XDR data " +
                    "($($tableClassification.Classification)), where the lookback is FIXED at '$xdrLookback' for a " +
                    "'$xdrFrequency' frequency and cannot be configured. The detection will evaluate a shorter " +
                    "window than the Sentinel rule did. Choose a less frequent schedule for a longer fixed " +
                    "window (hourly 4h, 3H 12h, 12H 48h, 24H 30d), or narrow the query.$mixedTierNote")
            } else {
                Add-Diagnostic -Feature 'Rule lookback' -Capability 'Lookback support' `
                    -Severity 'Info' -Action 'Mapped' -SourceValue $queryPeriodStr -TargetValue $xdrLookback `
                    -Reason ("Rule '$displayName' references Defender XDR data " +
                    "($($tableClassification.Classification)), where the lookback is fixed at '$xdrLookback' for a " +
                    "'$xdrFrequency' frequency. The source lookback '$queryPeriodStr' fits inside that window, so " +
                    "no data is lost.")
            }
        }
    }
    else {
        # ---- FLEXIBLE path (SentinelOnly): carry source freq + period, clamp to parity.
        $freqHours = $null
        if (-not [string]::IsNullOrWhiteSpace($queryFrequencyStr)) {
            $freqHours = ConvertFrom-IsoDuration -Duration $queryFrequencyStr
            if ($null -ne $freqHours -and $freqHours -gt 0) {
                $xdrFrequency = ConvertTo-IsoDuration -TotalHours $freqHours
                Add-Diagnostic -Feature 'Rule frequency' -Capability 'Support flexible and high frequency for Sentinel data' `
                    -Severity 'Info' -Action 'Mapped' -SourceValue $queryFrequencyStr -TargetValue $xdrFrequency `
                    -Reason ("Query frequency '$queryFrequencyStr' (~$([Math]::Round($freqHours, 2))h) is carried " +
                    "as a flexible frequency '$xdrFrequency' (Sentinel-tier data supports custom frequency).")
            } elseif ($null -ne $freqHours) {
                # Zero / non-positive SCHEDULED frequency: do NOT let ConvertTo-IsoDuration
                # silently coerce it to '0' (NRT/continuous). Fall back to the shortest
                # constrained default frequency and diagnose. (NRT rules take the kind=NRT
                # branch above and still emit '0'.)
                $freqHours = $bucketHours[0]
                $xdrFrequency = ConvertTo-IsoDuration -TotalHours $freqHours

                Add-Diagnostic -Feature 'Rule frequency' -Capability 'Support flexible and high frequency for Sentinel data' `
                    -Severity 'Warning' -Action 'Constrained' -SourceValue $queryFrequencyStr -TargetValue $xdrFrequency `
                    -Reason ("Query frequency '$queryFrequencyStr' is zero/non-positive but the rule is " +
                    "scheduled (not NRT). A zero scheduled frequency would silently become a continuous " +
                    "detection, so it was constrained to the shortest supported frequency '$xdrFrequency'.")
            } else {
                $freqHours = 1.0
                $xdrFrequency = ConvertTo-IsoDuration -TotalHours $freqHours

                Add-Diagnostic -Feature 'Rule frequency' -Capability 'Support flexible and high frequency for Sentinel data' `
                    -Severity 'Warning' -Action 'RequiresReview' -SourceValue $queryFrequencyStr -TargetValue $xdrFrequency `
                    -Reason "Unable to parse query frequency '$queryFrequencyStr'. Defaulting to '$xdrFrequency'."
            }
        } else {
            $freqHours = 1.0
            $xdrFrequency = ConvertTo-IsoDuration -TotalHours $freqHours

            Add-Diagnostic -Feature 'Rule frequency' -Capability 'Support flexible and high frequency for Sentinel data' `
                -Severity 'Warning' -Action 'RequiresReview' -SourceValue $null -TargetValue $xdrFrequency `
                -Reason "No queryFrequency found in rule '$displayName'. Defaulting to '$xdrFrequency'."
        }

        # Sentinel-tier data allows a custom lookback, bounded by how often the rule
        # runs: the more frequent the schedule, the shorter the reach.
        $tier = Get-LookbackTier -FrequencyHours $freqHours
        $maxLookbackHours = [double]$tier.MaxLookbackHours
        $limitText = [string]$tier.Label

        # Both bounds come from FrequencyLookbackRules.psd1 Parity. The upper one is
        # also expressed by the tiers; the lower one (five minutes) was recorded as data
        # and never read, so a PT1M lookback was reported as 'carried' - an unverified
        # claim. It is enforced here, as data.
        $minLookbackHours = [double]$flRules.Parity.MinLookbackMinutes / 60.0

        if (-not [string]::IsNullOrWhiteSpace($queryPeriodStr)) {
            $periodHours = ConvertFrom-IsoDuration -Duration $queryPeriodStr
            if ($null -ne $periodHours) {
                if ($periodHours -gt 0 -and $periodHours -lt $minLookbackHours) {
                    $xdrLookback = ConvertTo-IsoDuration -TotalHours $minLookbackHours
                    Add-Diagnostic -Feature 'Rule lookback' -Capability 'Lookback support' `
                        -Severity 'Warning' -Action 'Constrained' -SourceValue $queryPeriodStr -TargetValue $xdrLookback `
                        -Reason ("Query lookback '$queryPeriodStr' is shorter than the $($flRules.Parity.MinLookbackMinutes)-minute " +
                        "minimum a custom detection supports and was raised to '$xdrLookback'.")
                }
                elseif ($periodHours -gt $maxLookbackHours) {
                    $xdrLookback = ConvertTo-IsoDuration -TotalHours $maxLookbackHours
                    Add-Diagnostic -Feature 'Rule lookback' -Capability 'Lookback support' `
                        -Severity 'Warning' -Action 'Constrained' -SourceValue $queryPeriodStr -TargetValue $xdrLookback `
                        -Reason ("Query lookback '$queryPeriodStr' (~$([Math]::Round($periodHours, 2))h) exceeds the " +
                        "parity limit of $limitText for frequency '$xdrFrequency' and was clamped to '$xdrLookback'.")
                } else {
                    $xdrLookback = ConvertTo-IsoDuration -TotalHours $periodHours
                    Add-Diagnostic -Feature 'Rule lookback' -Capability 'Lookback support' `
                        -Severity 'Info' -Action 'Mapped' -SourceValue $queryPeriodStr -TargetValue $xdrLookback `
                        -Reason ("Query lookback '$queryPeriodStr' is carried as '$xdrLookback' " +
                        "(within the $limitText parity limit for frequency '$xdrFrequency').")
                }
            } else {
                $xdrLookback = $xdrFrequency
                Add-Diagnostic -Feature 'Rule lookback' -Capability 'Lookback support' `
                    -Severity 'Warning' -Action 'RequiresReview' -SourceValue $queryPeriodStr -TargetValue $xdrLookback `
                    -Reason "Unable to parse query lookback '$queryPeriodStr'. Defaulting lookback to the frequency '$xdrLookback'."
            }
        } else {
            # No source period: default the lookback to the frequency window.
            $xdrLookback = $xdrFrequency
        }
    }

    # =========================================================================
    # MITRE completeness (Stage 4)
    # =========================================================================
    # Behavior here is DATA-DRIVEN and BUILD-FOR-CHANGE:
    #   * Structural rules (technique regex, subtechnique regex, subset policy,
    #     tactic selection strategy) live in src/Data/MitreSupportRules.psd1.
    #   * Capability STATES (Planned / Supported / ...) are read at runtime from
    #     CustomDetectionCapabilities.psd1 via Get-CustomDetectionCapabilities, so
    #     a Microsoft Planned -> Supported flip is a pure DATA edit — this code
    #     reads the State and branches accordingly (see the gates below).
    # -------------------------------------------------------------------------
    $mitreRules = Get-MitreSupportRules
    $mitreDocBase = "$docBase#compare-analytics-rules-and-custom-detections-features"

    # Live capability States (single source of truth = CustomDetectionCapabilities.psd1).
    $multiTacticCap   = $mitreRules.Capabilities.MultipleTactics
    $fullTechCap      = $mitreRules.Capabilities.FullTechniques
    $attackPageCap    = $mitreRules.Capabilities.AttackPageReflection
    $multiTacticState = Get-CustomDetectionCapabilities -Feature $multiTacticCap.Feature -Capability $multiTacticCap.Capability
    $fullTechState    = Get-CustomDetectionCapabilities -Feature $fullTechCap.Feature    -Capability $fullTechCap.Capability
    $attackPageState  = Get-CustomDetectionCapabilities -Feature $attackPageCap.Feature  -Capability $attackPageCap.Capability

    # -------------------------------------------------------------------------
    # Tactics → alertCategory
    # -------------------------------------------------------------------------
    $tacticToCategory = @{
        'Collection'              = 'Collection'
        'CommandAndControl'       = 'CommandAndControl'
        'CredentialAccess'        = 'CredentialAccess'
        'DefenseEvasion'          = 'DefenseEvasion'
        'Discovery'               = 'Discovery'
        'Execution'               = 'Execution'
        'Exfiltration'            = 'Exfiltration'
        'Impact'                  = 'Impact'
        'InitialAccess'           = 'InitialAccess'
        'LateralMovement'         = 'LateralMovement'
        'Persistence'             = 'Persistence'
        'PrivilegeEscalation'     = 'PrivilegeEscalation'
        # Sentinel-only tactics mapped to the closest XDR category
        'PreAttack'               = 'SuspiciousActivity'
        'Reconnaissance'          = 'SuspiciousActivity'
        'ResourceDevelopment'     = 'SuspiciousActivity'
        'ImpairProcessControl'    = 'SuspiciousActivity'
        'InhibitResponseFunction' = 'SuspiciousActivity'
    }

    $tactics = @(if ($props.tactics) { $props.tactics }
                 elseif ($SentinelObject.tactics) { $SentinelObject.tactics }
                 else { @() })

    $alertCategory = 'SuspiciousActivity'
    if ($PSBoundParameters.ContainsKey('OverrideAlertCategory')) {
        $alertCategory = $OverrideAlertCategory
    } elseif ($tactics.Count -gt 0) {
        # Pick the first tactic that maps to a valid XDR category (selection
        # strategy from the data file; today only 'FirstMappable' is implemented).
        # NOTE: chosen-VALUE behavior is intentionally preserved from Stage 0–3.
        $chosenCategory = $null
        $chosenTactic   = $null
        foreach ($tactic in $tactics) {
            if ($tacticToCategory.ContainsKey($tactic)) {
                $chosenCategory = $tacticToCategory[$tactic]
                $chosenTactic   = $tactic
                break
            }
        }
        $alertCategory = if ($chosenCategory) { $chosenCategory } else { 'SuspiciousActivity' }

        if ($tactics.Count -gt 1 -and -not $GraphShape) {
            # -----------------------------------------------------------------
            # MULTIPLE TACTICS — precise drop accounting (Stage 4).
            # Legacy shape only: see the -GraphShape parameter.
            #
            # BUILD-FOR-CHANGE: gate on the live 'Link multiple MITRE tactics'
            # State. While it is NOT 'Supported' (today: Planned) a custom
            # detection holds exactly ONE alertCategory, so we keep the chosen
            # tactic and DROP the rest — recorded as a STRUCTURED diagnostic with
            # the full source list, the explicit dropped list, and an N-of-M
            # count. When Microsoft flips the State to 'Supported', this branch
            # carries ALL mapped tactics instead (data flip, no logic rewrite).
            # -----------------------------------------------------------------
            if ($multiTacticState -eq 'Supported') {
                # The PLATFORM can now link multiple tactics, but this legacy output
                # shape still carries exactly one alertCategory, so the tactics are
                # still dropped — by us, not by XDR. Say that, rather than claiming
                # they were carried: a diagnostic that overstates what migrated is
                # the one failure this module exists to prevent.
                #
                # This cannot be fixed inside this shape, and that is not a gap left
                # open: the legacy format is consumed by XDRConverter, which reads a
                # single alertCategory string. Inventing an array here would produce
                # output that tool cannot parse — trading a documented, diagnosed
                # limitation for a silent incompatibility.
                #
                # The fix already exists and is one parameter away: -Format Graph
                # emits alertTemplate.tactics[] and carries every mapped tactic with
                # its techniques. The diagnostic below says so.
                $droppedTactics = @($tactics | Where-Object { $_ -ne $chosenTactic })
                $keptLabel = if ($chosenTactic) { "'$chosenTactic' (alertCategory '$alertCategory')" }
                             else { "'$alertCategory' (no tactic mapped; defaulted)" }
                Add-Diagnostic -Feature $multiTacticCap.Feature -Capability $multiTacticCap.Capability `
                    -Severity 'Warning' -Action 'Dropped' -SourceValue ($tactics -join ', ') -TargetValue $alertCategory `
                    -Reason ("Rule '$displayName' has $($tactics.Count) MITRE tactics: [$($tactics -join ', ')]. " +
                    "XDR now supports linking multiple tactics ('$($multiTacticCap.Capability)' is " +
                    "$multiTacticState), but this output shape carries only one alertCategory, so " +
                    "$($droppedTactics.Count) of $($tactics.Count) tactic(s) were NOT migrated. " +
                    "Kept $keptLabel; dropped [$($droppedTactics -join ', ')]. Use -Format Graph, or " +
                    "-AlertCategory to choose a different one.") `
                    -DocReference $mitreDocBase
            }
            else {
                # Current state (Planned): one alertCategory only. Record exactly
                # which tactic was kept and which were dropped, with a count.
                $droppedTactics = @($tactics | Where-Object { $_ -ne $chosenTactic })
                $keptLabel = if ($chosenTactic) { "'$chosenTactic' (alertCategory '$alertCategory')" }
                             else { "'$alertCategory' (no tactic mapped; defaulted)" }
                Add-Diagnostic -Feature $multiTacticCap.Feature -Capability $multiTacticCap.Capability `
                    -Severity 'Warning' -Action 'Dropped' -SourceValue ($tactics -join ', ') -TargetValue $alertCategory `
                    -Reason ("Rule '$displayName' has $($tactics.Count) MITRE tactics: [$($tactics -join ', ')]. " +
                    "XDR custom detections support only one alertCategory ('Link multiple MITRE tactics' is " +
                    "$multiTacticState), so $($droppedTactics.Count) of $($tactics.Count) tactic(s) were NOT migrated. " +
                    "Kept $keptLabel; dropped [$($droppedTactics -join ', ')]. Use -AlertCategory to choose a different one.") `
                    -DocReference $mitreDocBase
            }
        }

        # Warn about tactics that had no direct XDR equivalent
        $sentinelOnlyTactics = $tactics | Where-Object {
            $tacticToCategory.ContainsKey($_) -and $tacticToCategory[$_] -eq 'SuspiciousActivity' -and $_ -ne 'SuspiciousActivity'
        }
        $unknownTactics = $tactics | Where-Object { -not $tacticToCategory.ContainsKey($_) }

        if ($sentinelOnlyTactics -and -not $GraphShape) {
            Add-Diagnostic -Feature $multiTacticCap.Feature -Capability $multiTacticCap.Capability `
                -Severity 'Warning' -Action 'Mapped' -SourceValue ($sentinelOnlyTactics -join ', ') -TargetValue 'SuspiciousActivity' `
                -Reason ("Tactics [$($sentinelOnlyTactics -join ', ')] are not natively supported " +
                "in XDR and have been mapped to 'SuspiciousActivity'.") `
                -DocReference $mitreDocBase
        }
        if ($unknownTactics -and -not $GraphShape) {
            Add-Diagnostic -Feature $multiTacticCap.Feature -Capability $multiTacticCap.Capability `
                -Severity 'Warning' -Action 'Dropped' -SourceValue ($unknownTactics -join ', ') -TargetValue $null `
                -Reason ("Unknown tactic(s) [$($unknownTactics -join ', ')] cannot be mapped. Ignoring.") `
                -DocReference $mitreDocBase
        }
    } elseif (-not $GraphShape) {
        Add-Diagnostic -Feature $multiTacticCap.Feature -Capability $multiTacticCap.Capability `
            -Severity 'Warning' -Action 'RequiresReview' -SourceValue $null -TargetValue 'SuspiciousActivity' `
            -Reason "Rule '$displayName' has no tactics defined. Defaulting alertCategory to 'SuspiciousActivity'. Use -AlertCategory to override." `
            -DocReference $mitreDocBase
    }

    # -------------------------------------------------------------------------
    # MITRE techniques & subtechniques (Stage 4)
    # (community YAML: 'relevantTechniques'; ARM JSON: 'techniques')
    #
    # Pipeline: collect -> dedup (preserve order) -> validate format -> classify
    # parent vs subtechnique -> apply the SUBSET POLICY (data-driven, gated on the
    # live 'Support full list of MITRE techniques and subtechniques' State) ->
    # account (counts of kept / dropped / subtechniques) in diagnostics.
    #
    # DECISION (see MitreSupportRules.psd1): SubsetPolicy = 'PassThroughFlag'.
    # The exact supported technique/subtechnique subset is NOT documented, so we
    # do NOT silently drop VALID IDs. We pass valid techniques through and emit a
    # RequiresReview diagnostic (listing + counting subtechniques) for the user to
    # verify against the live product. INVALID IDs are always dropped + counted.
    # -------------------------------------------------------------------------
    $rawTechniques = @(
        if ($props.techniques) { $props.techniques }
        elseif ($SentinelObject.relevantTechniques) { $SentinelObject.relevantTechniques }
        elseif ($props.relevantTechniques) { $props.relevantTechniques }
        else { @() }
    )

    $techniquePattern    = $mitreRules.TechniquePattern
    $subtechniquePattern = $mitreRules.SubtechniquePattern

    # Dedup, preserving first-seen order (case-insensitive on the trimmed value).
    $seenTech    = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $dedupedTech = [System.Collections.Generic.List[string]]::new()
    foreach ($t in $rawTechniques) {
        $tv = ([string]$t).Trim()
        if ([string]::IsNullOrWhiteSpace($tv)) { continue }
        if ($seenTech.Add($tv)) { $dedupedTech.Add($tv) }
    }

    # Validate format; separate parent techniques (T1234) from subtechniques (T1234.001).
    $validTechniques  = [System.Collections.Generic.List[string]]::new()
    $parentTechniques = [System.Collections.Generic.List[string]]::new()
    $subTechniques    = [System.Collections.Generic.List[string]]::new()
    $invalidTechniques = [System.Collections.Generic.List[string]]::new()
    foreach ($t in $dedupedTech) {
        if ($t -match $techniquePattern) {
            $validTechniques.Add($t)
            if ($t -match $subtechniquePattern) { $subTechniques.Add($t) }
            else { $parentTechniques.Add($t) }
        } else {
            $invalidTechniques.Add($t)
        }
    }

    # Invalid entries are DROPPED (excluded from output) + named + counted.
    if ($invalidTechniques.Count -gt 0) {
        Add-Diagnostic -Feature $fullTechCap.Feature -Capability $fullTechCap.Capability `
            -Severity 'Warning' -Action 'Dropped' `
            -SourceValue ($invalidTechniques -join ', ') -TargetValue $null `
            -Reason ("Rule '$displayName' has $($invalidTechniques.Count) MITRE technique ID(s) that are not " +
            "valid ATT&CK identifiers (expected 'T####' or 'T####.###'): [$($invalidTechniques -join ', ')]. " +
            "They were dropped and excluded from mitreTechniques.") `
            -DocReference $mitreDocBase
    }

    # Apply the supported-subset policy (data-driven; gated on the live State).
    $mitreTechniques = @($validTechniques)
    if ($validTechniques.Count -gt 0) {
        if ($fullTechState -eq 'Supported') {
            # Full support shipped: carry everything, just confirm.
            Add-Diagnostic -Feature $fullTechCap.Feature -Capability $fullTechCap.Capability `
                -Severity 'Info' -Action 'Mapped' `
                -SourceValue ($validTechniques -join ', ') -TargetValue ($mitreTechniques -join ', ') `
                -Reason ("Rule '$displayName': all $($validTechniques.Count) valid MITRE technique(s) carried " +
                "($($parentTechniques.Count) parent, $($subTechniques.Count) subtechnique(s)). Full " +
                "technique/subtechnique support is $fullTechState.") `
                -DocReference $mitreDocBase
        }
        elseif ($mitreRules.SubsetPolicy -eq 'ParentOnly') {
            # CONFIRMED constraint: target rejects subtechniques. Drop them + count.
            $mitreTechniques = @($parentTechniques)
            if ($subTechniques.Count -gt 0) {
                Add-Diagnostic -Feature $fullTechCap.Feature -Capability $fullTechCap.Capability `
                    -Severity 'Warning' -Action 'Dropped' `
                    -SourceValue ($subTechniques -join ', ') -TargetValue ($mitreTechniques -join ', ') `
                    -Reason ("Rule '$displayName': $($subTechniques.Count) of $($validTechniques.Count) MITRE " +
                    "ID(s) are subtechniques [$($subTechniques -join ', ')]. The target supports parent " +
                    "techniques only ('$($fullTechCap.Capability)' is $fullTechState), so subtechniques were " +
                    "dropped; $($parentTechniques.Count) parent technique(s) carried.") `
                    -DocReference $mitreDocBase
            }
        }
        elseif ($mitreRules.SubsetPolicy -eq 'Capped' -and [int]$mitreRules.MaxTechniqueCount -gt 0 `
                -and $validTechniques.Count -gt [int]$mitreRules.MaxTechniqueCount) {
            # CONFIRMED cap: keep the first N (order preserved), drop + count the rest.
            $cap = [int]$mitreRules.MaxTechniqueCount
            $mitreTechniques = @($validTechniques[0..($cap - 1)])
            $cappedOut = @($validTechniques[$cap..($validTechniques.Count - 1)])
            Add-Diagnostic -Feature $fullTechCap.Feature -Capability $fullTechCap.Capability `
                -Severity 'Warning' -Action 'Dropped' `
                -SourceValue ($validTechniques -join ', ') -TargetValue ($mitreTechniques -join ', ') `
                -Reason ("Rule '$displayName' has $($validTechniques.Count) valid MITRE technique(s) but the " +
                "target accepts at most $cap ('$($fullTechCap.Capability)' is $fullTechState). " +
                "$($cappedOut.Count) technique(s) over the cap were dropped: [$($cappedOut -join ', ')].") `
                -DocReference $mitreDocBase
        }
        else {
            # DEFAULT (PassThroughFlag): pass all valid techniques through, but FLAG
            # for review since full support is Planned and the exact subset is
            # undocumented. List + count subtechniques separately so the user can
            # verify them against the live product. Do NOT drop valid IDs here.
            $subNote = if ($subTechniques.Count -gt 0) {
                "Of these, $($subTechniques.Count) is/are subtechniques [$($subTechniques -join ', ')] " +
                "(verify the live product accepts subtechniques). "
            } else { '' }
            Add-Diagnostic -Feature $fullTechCap.Feature -Capability $fullTechCap.Capability `
                -Severity 'Warning' -Action 'RequiresReview' `
                -SourceValue ($validTechniques -join ', ') -TargetValue ($mitreTechniques -join ', ') `
                -Reason ("Rule '$displayName': full MITRE technique/subtechnique support in custom detections is " +
                "$fullTechState. $($validTechniques.Count) valid technique(s) [$($validTechniques -join ', ')] " +
                "were carried through unchanged ($($parentTechniques.Count) parent, $($subTechniques.Count) " +
                "subtechnique(s)). ${subNote}Confirm every ID is accepted by the live custom-detection product.") `
                -DocReference $mitreDocBase
        }
    }

    # Low-noise reflection diagnostic: custom detections do not yet reflect on the
    # MITRE ATT&CK coverage page (Planned) — coverage visibility differs from
    # Sentinel. Emit once per conversion when ANY tactics OR techniques are present.
    if (($tactics.Count -gt 0 -or $validTechniques.Count -gt 0) -and $attackPageState -ne 'Supported') {
        Add-Diagnostic -Feature $attackPageCap.Feature -Capability $attackPageCap.Capability `
            -Severity 'Info' -Action 'RequiresReview' `
            -SourceValue ("tactics: $($tactics.Count), techniques: $($validTechniques.Count)") -TargetValue $null `
            -Reason ("Rule '$displayName' carries MITRE metadata, but custom detections do not yet reflect on the " +
            "MITRE ATT&CK coverage page ('$($attackPageCap.Capability)' is $attackPageState). ATT&CK coverage " +
            "visibility will differ from Microsoft Sentinel until this ships.") `
            -DocReference $mitreDocBase
    }

    # -------------------------------------------------------------------------
    # Alert title  (Sentinel has no separate alertTitle field)
    # -------------------------------------------------------------------------
    # Determine whether a dynamic alertDisplayNameFormat will be applied by the
    # Stage 5 sweep below. If so (and no explicit -AlertTitle override is given),
    # the Stage 5 dynamic-title diagnostic supersedes the default-title one, so
    # we suppress the default-title diagnostic here to avoid a misleading double
    # diagnostic. Precedence: explicit -AlertTitle > dynamic format > rule name.
    $willApplyDynamicTitle = $false
    if (-not ($PSBoundParameters.ContainsKey('OverrideAlertTitle') -and $OverrideAlertTitle)) {
        $adoEarly = Get-MemberValue -Source $props -Name 'alertDetailsOverride'
        if ($null -eq $adoEarly) { $adoEarly = Get-MemberValue -Source $SentinelObject -Name 'alertDetailsOverride' }
        $adoEarlyTitle = Get-MemberValue -Source $adoEarly -Name 'alertDisplayNameFormat'
        if ($null -ne $adoEarly -and -not [string]::IsNullOrWhiteSpace([string]$adoEarlyTitle)) {
            $titleDescCapEarly = (Get-FeatureGapRules).Capabilities.DynamicTitleDescription
            if ((Get-CustomDetectionCapabilities -Feature $titleDescCapEarly.Feature -Capability $titleDescCapEarly.Capability) -eq 'Supported') {
                $willApplyDynamicTitle = $true
            }
        }
    }

    $alertTitle = if ($PSBoundParameters.ContainsKey('OverrideAlertTitle') -and $OverrideAlertTitle) {
        $OverrideAlertTitle
    } elseif ($willApplyDynamicTitle) {
        # Placeholder; the Stage 5 sweep below overrides $alertTitle with the
        # dynamic format and emits the single Mapped diagnostic for it.
        $displayName
    } else {
        Add-Diagnostic -Feature 'Alert enrichment' -Capability 'Define alert title and description dynamically - Integrate query results in runtime' `
            -Severity 'Info' -Action 'Mapped' -SourceValue $null -TargetValue $displayName `
            -Reason ("Sentinel analytics rules do not have a dedicated alert title. " +
            "Using the rule name '$displayName' as alertTitle. Use -AlertTitle to override.")
        $displayName
    }

    # -------------------------------------------------------------------------
    # Trigger threshold / operator  (no XDR equivalent)
    # -------------------------------------------------------------------------
    $rawThreshold = if ($null -ne $props.triggerThreshold) { $props.triggerThreshold }
                    elseif ($null -ne $SentinelObject.triggerThreshold) { $SentinelObject.triggerThreshold }
                    else { $null }
    # Never a hard [int] cast. An ARM parameter with no default arrives as the literal
    # string "[parameters('threshold')]"; the normalizer already warns about it and leaves
    # its own copy null - but this function reads the RAW rule, and on 2026-09-16 the cast
    # here threw and the rule vanished from the output (read 4, assessed 2) directly after
    # a warning that said 'everything else about the rule converts normally'. The threshold
    # has no XDR equivalent and is dropped anyway, so an unreadable one costs a diagnostic,
    # not the rule.
    $triggerThreshold = 0
    $thresholdUnreadable = $false
    if ($null -ne $rawThreshold) {
        $parsedThreshold = 0
        if ([int]::TryParse([string]$rawThreshold, [ref]$parsedThreshold)) { $triggerThreshold = $parsedThreshold }
        else { $thresholdUnreadable = $true }
    }

    $triggerOperator = if ($props.triggerOperator) { [string]$props.triggerOperator }
                       elseif ($SentinelObject.triggerOperator) { [string]$SentinelObject.triggerOperator }
                       else { 'gt' }

    # Normalize to shorthand for the warning message
    $normalizedOperator = switch ($triggerOperator) {
        'GreaterThan' { 'gt' }
        'LessThan'    { 'lt' }
        'Equal'       { 'eq' }
        'NotEqual'    { 'ne' }
        default       { $triggerOperator }
    }
    if ($thresholdUnreadable) {
        Add-Diagnostic -Feature 'Control alerts and events grouping' -Capability 'Choose between all events under one alert and one alert per event' `
            -Severity 'Warning' -Action 'Unsupported' -SourceValue "$normalizedOperator $rawThreshold" -TargetValue $null `
            -Reason ("Sentinel trigger threshold '$rawThreshold' is not a number - usually an ARM template parameter " +
            "with no default value - so the trigger condition could not be read. It has no XDR equivalent in any case: " +
            "XDR custom detections trigger on every row returned by the query.")
    }
    elseif ($normalizedOperator -ne 'gt' -or $triggerThreshold -ne 0) {
        Add-Diagnostic -Feature 'Control alerts and events grouping' -Capability 'Choose between all events under one alert and one alert per event' `
            -Severity 'Warning' -Action 'Unsupported' -SourceValue "$normalizedOperator $triggerThreshold" -TargetValue $null `
            -Reason ("Sentinel trigger condition '$normalizedOperator $triggerThreshold' is not supported in XDR. " +
            "XDR custom detections trigger on every row returned by the query.")
    }

    # -------------------------------------------------------------------------
    # Entity mappings → impactedEntities
    # Sentinel 'Host' → XDR 'Machine', 'Account' → 'User'; columnName → entityIdentifier
    # -------------------------------------------------------------------------
    $entityTypeMap = @{
        'Host'          = 'Machine'
        'Account'       = 'User'
        'IP'            = 'IP'
        'URL'           = 'URL'
        'Process'       = 'Process'
        'Mailbox'       = 'Mailbox'
        'RegistryKey'   = 'RegistryKey'
        'RegistryValue' = 'RegistryValue'
        'FileHash'      = 'FileHash'
        # No XDR equivalent — will be skipped with a warning
        'File'               = $null
        'MailMessage'        = $null
        'AzureResource'      = $null
        'CloudApplication'   = $null
        'DNS'               = $null
        'IoTDevice'         = $null
        'SecurityGroup'     = $null
        'SubmissionMail'    = $null
        'MailCluster'       = $null
        'Malware'           = $null
    }

    $sentinelEntityMappings = @(
        if ($props.entityMappings) { $props.entityMappings }
        elseif ($SentinelObject.entityMappings) { $SentinelObject.entityMappings }
        else { @() }
    )

    $impactedEntities = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($entityMapping in $sentinelEntityMappings) {
        $sentinelType = [string]$entityMapping.entityType
        if (-not $entityTypeMap.ContainsKey($sentinelType)) {
            if (-not $GraphShape) {
                Add-Diagnostic -Feature 'Alert enrichment' -Capability 'Flexible entity mapping over Sentinel data' `
                    -Severity 'Warning' -Action 'Dropped' -SourceValue $sentinelType -TargetValue $null `
                    -Reason "Unknown Sentinel entity type '$sentinelType'. Skipping."
            }
            continue
        }
        $xdrEntityType = $entityTypeMap[$sentinelType]
        if ($null -eq $xdrEntityType) {
            if (-not $GraphShape) {
                Add-Diagnostic -Feature 'Alert enrichment' -Capability 'Flexible entity mapping over Sentinel data' `
                    -Severity 'Warning' -Action 'Dropped' -SourceValue $sentinelType -TargetValue $null `
                    -Reason ("Sentinel entity type '$sentinelType' has no equivalent in XDR custom " +
                    "detections and will be skipped. Review impactedEntities in the output manually.")
            }
            continue
        }

        # Each fieldMapping entry becomes a separate impactedEntity row in XDR.
        # XDR entityIdentifier = query column name (Sentinel 'columnName').
        foreach ($fieldMapping in $entityMapping.fieldMappings) {
            $impactedEntities.Add(@{
                entityType       = $xdrEntityType
                entityIdentifier = [string]$fieldMapping.columnName
            })
        }
    }

    # =========================================================================
    # Remaining feature gaps (Stage 5 — matrix-driven drop + diagnose)
    # =========================================================================
    # Every Sentinel source feature below was previously DROPPED SILENTLY. Here
    # each one is gated on its compare-doc capability State (read at runtime via
    # Get-CustomDetectionCapabilities) and acted on:
    #   Supported    -> MAP into output (or surface) + Info/Mapped diagnostic.
    #   NotSupported -> DROP + Warning/Unsupported diagnostic (field NOT emitted).
    #   Planned      -> RequiresReview/Info diagnostic (not migrated yet).
    #
    # BUILD-FOR-CHANGE: the State drives the Action/Severity. A future flip
    # (e.g. 'Customize alert grouping logic' NotSupported -> Supported) changes
    # behavior via the data edit in CustomDetectionCapabilities.psd1; the row
    # references live in FeatureGapRules.psd1. The Feature/Capability strings on
    # every diagnostic below match a real matrix row (a guard test asserts this).
    #
    # OUTPUT FIELD-NAME ASSUMPTIONS (CONFIRM against the real Graph custom-
    # detection API / XDRConverter schema before deploying):
    #   * customDetails  -> NEW additive output field: a map of name -> KQL column,
    #     carried verbatim from the Sentinel customDetails map. The downstream
    #     field name may differ (e.g. 'customDetails' vs 'alertCustomDetails');
    #     if so, change the key here + in CustomDetection.schema.json + the sort
    #     order together.
    #   * Dynamic alert title/description: Sentinel expresses these as FORMAT
    #     STRINGS with {{Column}} placeholders. The output schema has only plain
    #     'alertTitle'/'alertDescription' strings, so the format string is carried
    #     INTO those fields (a Mapped+RequiresReview diagnostic flags that the
    #     placeholder syntax must be confirmed against the live product, which may
    #     use a different token form).
    # -------------------------------------------------------------------------
    $gapRules      = Get-FeatureGapRules
    $gapCaps       = $gapRules.Capabilities
    $gapDocBase    = "$docBase#compare-analytics-rules-and-custom-detections-features"

    # Helper: resolve a source property from the normalized $props or the raw object.
    function Get-SourceProp {
        param([string]$Name)
        $value = Get-MemberValue -Source $props -Name $Name
        if ($null -ne $value) { return $value }
        $value = Get-MemberValue -Source $SentinelObject -Name $Name
        if ($null -ne $value) { return $value }
        return $null
    }

    # Holds the NEW customDetails output field (only emitted when supported + present).
    $customDetailsOut = $null

    # ---- A. alertDetailsOverride (dynamic alert title/description) -----------
    $alertDetailsOverride = Get-SourceProp -Name 'alertDetailsOverride'
    if ($null -ne $alertDetailsOverride) {
        $titleDescCap   = $gapCaps.DynamicTitleDescription
        $allPropsCap    = $gapCaps.DynamicAllProperties
        $titleDescState = Get-CustomDetectionCapabilities -Feature $titleDescCap.Feature -Capability $titleDescCap.Capability
        $allPropsState  = Get-CustomDetectionCapabilities -Feature $allPropsCap.Feature  -Capability $allPropsCap.Capability

        $displayNameFormat = [string](Get-MemberValue -Source $alertDetailsOverride -Name 'alertDisplayNameFormat')
        $descriptionFormat = [string](Get-MemberValue -Source $alertDetailsOverride -Name 'alertDescriptionFormat')

        # Dynamic title/description IS supported -> map the format strings.
        if ($titleDescState -eq 'Supported') {
            if (-not [string]::IsNullOrWhiteSpace($displayNameFormat)) {
                if ($PSBoundParameters.ContainsKey('OverrideAlertTitle') -and $OverrideAlertTitle) {
                    # Do NOT overwrite an explicit -AlertTitle override.
                    Add-Diagnostic -Feature $titleDescCap.Feature -Capability $titleDescCap.Capability `
                        -Severity 'Info' -Action 'RequiresReview' -SourceValue $displayNameFormat -TargetValue $OverrideAlertTitle `
                        -Reason ("Rule '$displayName' defines a dynamic alert title format '$displayNameFormat'. " +
                        "An explicit -AlertTitle override ('$OverrideAlertTitle') was supplied, so the dynamic format was NOT applied. " +
                        "Remove -AlertTitle to carry the dynamic title instead.") `
                        -DocReference $gapDocBase
                } else {
                    $alertTitle = $displayNameFormat
                    Add-Diagnostic -Feature $titleDescCap.Feature -Capability $titleDescCap.Capability `
                        -Severity 'Warning' -Action 'Mapped' -SourceValue $displayNameFormat -TargetValue $alertTitle `
                        -Reason ("Rule '$displayName' defines a dynamic alert title format '$displayNameFormat'. " +
                        "Dynamic title is supported in custom detections; it was carried into alertTitle. " +
                        "CONFIRM the placeholder syntax (Sentinel uses {{Column}}) matches the live custom-detection product.") `
                        -DocReference $gapDocBase
                }
            }
            if (-not [string]::IsNullOrWhiteSpace($descriptionFormat)) {
                $description = $descriptionFormat
                Add-Diagnostic -Feature $titleDescCap.Feature -Capability $titleDescCap.Capability `
                    -Severity 'Warning' -Action 'Mapped' -SourceValue $descriptionFormat -TargetValue $description `
                    -Reason ("Rule '$displayName' defines a dynamic alert description format '$descriptionFormat'. " +
                    "Dynamic description is supported in custom detections; it was carried into alertDescription. " +
                    "CONFIRM the placeholder syntax (Sentinel uses {{Column}}) matches the live custom-detection product.") `
                    -DocReference $gapDocBase
            }
        }

        # The OTHER sub-properties (dynamic severity/tactics columns,
        # alertDynamicProperties) fall under "all properties dynamic" = Planned.
        $otherDynamic = [System.Collections.Generic.List[string]]::new()
        foreach ($subProp in @('alertSeverityColumnName', 'alertTacticsColumnName', 'alertDynamicProperties')) {
            if ($null -ne (Get-MemberValue -Source $alertDetailsOverride -Name $subProp)) {
                $otherDynamic.Add($subProp)
            }
        }
        if ($otherDynamic.Count -gt 0 -and $allPropsState -ne 'Supported') {
            Add-Diagnostic -Feature $allPropsCap.Feature -Capability $allPropsCap.Capability `
                -Severity 'Warning' -Action 'RequiresReview' -SourceValue ($otherDynamic -join ', ') -TargetValue $null `
                -Reason ("Rule '$displayName' defines $($otherDynamic.Count) dynamic alert property override(s) " +
                "[$($otherDynamic -join ', ')] beyond title/description. Defining ALL alert properties dynamically is " +
                "'$($allPropsCap.Capability)' = $allPropsState in custom detections, so these were NOT migrated. " +
                "Review and reconfigure manually if/when the capability ships.") `
                -DocReference $gapDocBase
        }
    }

    # ---- B. customDetails (enrich alerts with custom details) ----------------
    $customDetails = Get-SourceProp -Name 'customDetails'
    if ($null -ne $customDetails) {
        # Community YAML parses into a Hashtable and ARM JSON into a PSCustomObject, and
        # only the second answers to PSObject.Properties. On a Hashtable that call returns
        # the adapter members — IsReadOnly, Keys, Values, Count — so the old check built a
        # map of those instead of the custom details, and community rules lost this gap
        # silently. Same shape of bug as the one fixed in v2.1.0 for the other Stage 6
        # checks; this branch was missed.
        #
        # And a scalar or an array is neither. A string answers to PSObject.Properties
        # with 'Length', so 'customDetails: SomeColumn' used to emit {"Length":"10"} as a
        # custom detail on a rule graded Ready (found 2026-09-16). Only a name-to-column
        # map is a custom details block; anything else is reported and dropped.
        $cdMap = [ordered]@{}
        $cdMalformed = $false
        if ($customDetails -is [System.Collections.IDictionary]) {
            foreach ($key in $customDetails.Keys) { $cdMap[[string]$key] = [string]$customDetails[$key] }
        } elseif ($customDetails -is [System.Management.Automation.PSCustomObject]) {
            foreach ($p in $customDetails.PSObject.Properties) { $cdMap[$p.Name] = [string]$p.Value }
        } else {
            $cdMalformed = $true
        }
        $cdCount = $cdMap.Keys.Count
        if ($cdMalformed) {
            $shown = [string]($customDetails | ConvertTo-Json -Compress -Depth 3 -ErrorAction SilentlyContinue)
            if ($shown.Length -gt 80) { $shown = $shown.Substring(0, 80) + '...' }
            Add-Diagnostic -Feature 'Alert enrichment' -Capability 'Enrich alerts with custom details' `
                -Severity 'Warning' -Action 'Dropped' -SourceValue $shown -TargetValue $null `
                -Reason ("customDetails must be a map of detail name to query column, but this rule carries " +
                "$($customDetails.GetType().Name) $shown. Nothing was carried, and nothing was invented in its place.")
        }
    }
    if ($null -ne $customDetails -and $cdCount -gt 0) {
        $cdCap   = $gapCaps.CustomDetails
        $cdState = Get-CustomDetectionCapabilities -Feature $cdCap.Feature -Capability $cdCap.Capability

        if ($cdState -eq 'Supported') {
            # Supported -> MAP into the new additive output field, flag for review
            # since the exact downstream representation/field name is an assumption.
            $customDetailsOut = $cdMap
            Add-Diagnostic -Feature $cdCap.Feature -Capability $cdCap.Capability `
                -Severity 'Warning' -Action 'Mapped' -SourceValue (($cdMap.Keys) -join ', ') -TargetValue (($cdMap.Keys) -join ', ') `
                -Reason ("Rule '$displayName' defines $cdCount custom detail(s) [$(($cdMap.Keys) -join ', ')]. " +
                "Custom details are supported in custom detections; they were carried into the 'customDetails' output field " +
                "(name -> KQL column). CONFIRM the downstream field name/representation against the live custom-detection product.") `
                -DocReference $gapDocBase
        } else {
            Add-Diagnostic -Feature $cdCap.Feature -Capability $cdCap.Capability `
                -Severity 'Warning' -Action 'RequiresReview' -SourceValue (($cdMap.Keys) -join ', ') -TargetValue $null `
                -Reason ("Rule '$displayName' defines $cdCount custom detail(s) [$(($cdMap.Keys) -join ', ')]. " +
                "'$($cdCap.Capability)' is $cdState, so they were recorded for review but not migrated.") `
                -DocReference $gapDocBase
        }
    }

    # ---- C. eventGroupingSettings (alert grouping) ---------------------------
    $eventGrouping = Get-SourceProp -Name 'eventGroupingSettings'
    if ($null -ne $eventGrouping) {
        $aggKind = [string](Get-MemberValue -Source $eventGrouping -Name 'aggregationKind')
        if ([string]::IsNullOrWhiteSpace($aggKind)) { $aggKind = '(unspecified)' }
        $egCap   = $gapCaps.EventsPerAlert
        $egState = Get-CustomDetectionCapabilities -Feature $egCap.Feature -Capability $egCap.Capability
        if ($egState -eq 'Supported') {
            Add-Diagnostic -Feature $egCap.Feature -Capability $egCap.Capability `
                -Severity 'Info' -Action 'Mapped' -SourceValue $aggKind -TargetValue $aggKind `
                -Reason ("Rule '$displayName' sets event grouping aggregationKind '$aggKind'. " +
                "'$($egCap.Capability)' is now $egState — review the mapping.") `
                -DocReference $gapDocBase
        } else {
            Add-Diagnostic -Feature $egCap.Feature -Capability $egCap.Capability `
                -Severity 'Warning' -Action 'Unsupported' -SourceValue $aggKind -TargetValue $null `
                -Reason ("Rule '$displayName' sets event grouping aggregationKind '$aggKind'. Choosing between " +
                "all events under one alert and one alert per event is '$($egCap.Capability)' = $egState in custom " +
                "detections (the SIEM/XDR correlation engine handles grouping). This setting was DROPPED.") `
                -DocReference $gapDocBase
        }
    }

    # ---- D. incidentConfiguration (alerts-without-incidents + grouping) ------
    $incidentConfig = Get-SourceProp -Name 'incidentConfiguration'
    if ($null -ne $incidentConfig) {
        # D1. createIncident=false -> alerts without incidents.
        $createIncidentRaw = Get-MemberValue -Source $incidentConfig -Name 'createIncident'
        if ($null -ne $createIncidentRaw) {
            $createIncident = [bool]$createIncidentRaw
            if (-not $createIncident) {
                $awCap   = $gapCaps.AlertsWithoutIncidents
                $awState = Get-CustomDetectionCapabilities -Feature $awCap.Feature -Capability $awCap.Capability
                if ($awState -eq 'Supported') {
                    Add-Diagnostic -Feature $awCap.Feature -Capability $awCap.Capability `
                        -Severity 'Info' -Action 'Mapped' -SourceValue 'createIncident: false' -TargetValue 'createIncident: false' `
                        -Reason ("Rule '$displayName' creates alerts without incidents. '$($awCap.Capability)' is now $awState.") `
                        -DocReference $gapDocBase
                } else {
                    Add-Diagnostic -Feature $awCap.Feature -Capability $awCap.Capability `
                        -Severity 'Warning' -Action 'Unsupported' -SourceValue 'createIncident: false' -TargetValue $null `
                        -Reason ("Rule '$displayName' is configured to create alerts WITHOUT incidents (createIncident: false). " +
                        "'$($awCap.Capability)' is $awState in custom detections — XDR creates incidents via the correlation " +
                        "engine. This setting was DROPPED; the detection's alerts will be correlated into incidents.") `
                        -DocReference $gapDocBase
                }
            }
        }

        # D2. groupingConfiguration (incident grouping / reopen) -> grouping logic.
        if ($null -ne (Get-MemberValue -Source $incidentConfig -Name 'groupingConfiguration')) {
            $cgCap   = $gapCaps.CustomizeGrouping
            $cgState = Get-CustomDetectionCapabilities -Feature $cgCap.Feature -Capability $cgCap.Capability
            if ($cgState -eq 'Supported') {
                Add-Diagnostic -Feature $cgCap.Feature -Capability $cgCap.Capability `
                    -Severity 'Info' -Action 'Mapped' -SourceValue 'groupingConfiguration' -TargetValue 'groupingConfiguration' `
                    -Reason ("Rule '$displayName' defines incident grouping configuration. '$($cgCap.Capability)' is now $cgState.") `
                    -DocReference $gapDocBase
            } else {
                Add-Diagnostic -Feature $cgCap.Feature -Capability $cgCap.Capability `
                    -Severity 'Warning' -Action 'Unsupported' -SourceValue 'groupingConfiguration' -TargetValue $null `
                    -Reason ("Rule '$displayName' defines incident grouping configuration (incident grouping/reopen). " +
                    "Customizing alert grouping logic is '$($cgCap.Capability)' = $cgState in custom detections (the " +
                    "correlation engine controls grouping). This configuration was DROPPED.") `
                    -DocReference $gapDocBase
            }
        }
    }

    # ---- E. Alert suppression ------------------------------------------------
    # Sentinel scheduled rules carry suppressionEnabled / suppressionDuration.
    $suppressionEnabledRaw = Get-SourceProp -Name 'suppressionEnabled'
    $suppressionDuration   = Get-SourceProp -Name 'suppressionDuration'
    $hasSuppression = ($null -ne $suppressionEnabledRaw -and [bool]$suppressionEnabledRaw) -or
                      ($null -ne $suppressionDuration)
    if ($hasSuppression) {
        $supCap   = $gapCaps.AlertSuppression
        $supState = Get-CustomDetectionCapabilities -Feature $supCap.Feature -Capability $supCap.Capability
        $window   = if ($null -ne $suppressionDuration) { [string]$suppressionDuration } else { '(enabled, unspecified window)' }
        if ($supState -eq 'Supported') {
            Add-Diagnostic -Feature $supCap.Feature -Capability $supCap.Capability `
                -Severity 'Info' -Action 'Mapped' -SourceValue $window -TargetValue $window `
                -Reason ("Rule '$displayName' defines alert suppression (window '$window'). '$($supCap.Capability)' is now $supState.") `
                -DocReference $gapDocBase
        } else {
            Add-Diagnostic -Feature $supCap.Feature -Capability $supCap.Capability `
                -Severity 'Warning' -Action 'Unsupported' -SourceValue $window -TargetValue $null `
                -Reason ("Rule '$displayName' defines alert suppression after the rule runs (window '$window'). " +
                "'$($supCap.Capability)' is $supState in custom detections. The suppression window was DROPPED.") `
                -DocReference $gapDocBase
        }
    }

    # ---- F. Native Defender XDR remediation actions (enrichment opportunity) -
    # Sentinel analytics rules have no native XDR remediation actions, so there
    # is nothing to map FROM the source. This is a per-batch enrichment note, not
    # a per-rule finding, so it is OPT-IN: only emitted when the caller passes
    # -SuggestRemediationActions. When set (and the capability is Supported in XDR)
    # we emit ONE low-noise Info diagnostic noting the opportunity. We do NOT
    # fabricate any actions in the output.
    $actionsCap   = $gapCaps.NativeRemediationActions
    $actionsState = Get-CustomDetectionCapabilities -Feature $actionsCap.Feature -Capability $actionsCap.Capability
    if ($SuggestRemediationActions -and $actionsState -eq 'Supported') {
        Add-Diagnostic -Feature $actionsCap.Feature -Capability $actionsCap.Capability `
            -Severity 'Info' -Action 'RequiresReview' -SourceValue $null -TargetValue $null `
            -Reason ("Custom detections support native Defender XDR remediation actions " +
            "[$($gapRules.NativeActionTypes -join ', ')] that Sentinel analytics rules do not. None were added " +
            "automatically (the source has none to map). Consider configuring an 'actions' entry on rule '$displayName' " +
            "post-migration if automated response is desired.") `
            -DocReference $gapDocBase
    }

    # ---- G. Sentinel automation rules (incident / alert trigger) -------------
    # The rule YAML itself rarely references automation, but incidentConfiguration
    # / playbook wiring implies downstream automation rules. Emit ONE low-noise
    # RequiresReview/Planned diagnostic when an incidentConfiguration is present
    # (the strongest in-rule signal of incident-trigger automation).
    if ($null -ne $incidentConfig) {
        $autoIncCap   = $gapCaps.AutomationIncidentTrigger
        $autoAlertCap = $gapCaps.AutomationAlertTrigger
        $autoIncState   = Get-CustomDetectionCapabilities -Feature $autoIncCap.Feature   -Capability $autoIncCap.Capability
        $autoAlertState = Get-CustomDetectionCapabilities -Feature $autoAlertCap.Feature -Capability $autoAlertCap.Capability
        if ($autoIncState -ne 'Supported' -or $autoAlertState -ne 'Supported') {
            Add-Diagnostic -Feature $autoIncCap.Feature -Capability $autoIncCap.Capability `
                -Severity 'Info' -Action 'RequiresReview' -SourceValue 'incidentConfiguration' -TargetValue $null `
                -Reason ("Rule '$displayName' has an incident configuration that may be tied to Sentinel automation rules. " +
                "Sentinel automation rules with incident trigger ($autoIncState) and alert trigger ($autoAlertState) are not " +
                "yet fully available for custom detections — review any downstream automation/playbooks that depend on this rule.") `
                -DocReference $gapDocBase
        }
    }

    # -------------------------------------------------------------------------
    # Build ordered output hashtable (XDR YAML schema field order)
    # -------------------------------------------------------------------------
    $defaultSortOrder = @(
        'guid', 'isEnabled', 'ruleName', 'alertTitle', 'alertCategory',
        'alertDescription', 'frequency', 'lookbackPeriod', 'alertSeverity',
        'alertRecommendedAction', 'mitreTechniques', 'customDetails',
        'impactedEntities', 'actions', 'queryText'
    )

    $yamlObj = @{
        guid             = $sourceGuid
        ruleName         = $displayName
        isEnabled        = $isEnabled
        alertTitle       = $alertTitle
        frequency        = $xdrFrequency
        alertSeverity    = $severity
        alertDescription = $description
        alertCategory    = $alertCategory
        queryText        = $queryText
    }

    if (-not [string]::IsNullOrWhiteSpace($xdrLookback)) {
        $yamlObj['lookbackPeriod'] = $xdrLookback
    }

    # Stage 5: carry the mapped customDetails (only set when the capability is
    # Supported AND the source had custom details).
    if ($null -ne $customDetailsOut -and $customDetailsOut.Keys.Count -gt 0) {
        $yamlObj['customDetails'] = $customDetailsOut
    }

    if ($mitreTechniques.Count -gt 0) {
        $yamlObj['mitreTechniques'] = $mitreTechniques
    }
    if ($impactedEntities.Count -gt 0) {
        $yamlObj['impactedEntities'] = $impactedEntities
    }

    $orderedResult = [ordered]@{}
    foreach ($key in $defaultSortOrder) {
        if ($yamlObj.ContainsKey($key)) {
            $orderedResult[$key] = $yamlObj[$key]
        }
    }

    # Hand the structured diagnostics back via the caller-supplied [ref] list so the
    # serialized YAML (the ordered hashtable) is unchanged.
    if ($PSBoundParameters.ContainsKey('DiagnosticsRef') -and $null -ne $DiagnosticsRef) {
        $DiagnosticsRef.Value = $diagnostics
    }

    # Hand the resolved decisions back for the Graph renderer. The legacy shape carries
    # the frequency ENUM ('1H'); the Graph schedule.frequency is an ISO 8601 duration, so
    # both representations are exposed here rather than re-derived downstream. This is a
    # pure read-out of values already computed above; nothing is decided here.
    if ($PSBoundParameters.ContainsKey('DecisionRef') -and $null -ne $DecisionRef) {
        $frequencyIso = if ($xdrFrequency -eq '0') {
            '0'
        } elseif ($xdrFrequency -match '^(\d+(?:\.\d+)?)\s*[Hh]$') {
            # Legacy enum bucket ('1H', '3H', '12H', '24H') -> ISO 8601.
            ConvertTo-IsoDurationText -TotalHours ([double]$Matches[1])
        } else {
            # Flexible path already produced an ISO 8601 duration.
            $xdrFrequency
        }

        $DecisionRef.Value = [ordered]@{
            Guid                = $sourceGuid
            DisplayName         = $displayName
            AlertTitle          = $alertTitle
            Description         = $description
            Severity            = $severity
            IsEnabled           = $isEnabled
            QueryText           = $queryText
            FrequencyEnum       = $xdrFrequency
            FrequencyIso        = $frequencyIso
            LookbackPeriod      = $xdrLookback
            IsNrt               = $isNrt
            Classification      = $tableClassification
            Tactics             = $tactics
            AlertCategory       = $alertCategory
            Techniques          = @($validTechniques)
            ParentTechniques    = @($parentTechniques)
            SubTechniques       = @($subTechniques)
            CustomDetails       = $customDetailsOut
            EntityMappings      = $sentinelEntityMappings
            RecommendedAction   = $null
        }
    }

    return $orderedResult
}

