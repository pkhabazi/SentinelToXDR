function ConvertTo-NormalizedSentinelRule {
    <#
    .SYNOPSIS
        Normalizes any supported Sentinel analytics rule shape into one flat rule object.

    .DESCRIPTION
        Every downstream stage (classification, frequency, MITRE, entity mapping, rendering)
        consumes this one object, so the rest of the module never has to know which of the
        four source shapes a rule arrived in:

          1. Community / content-hub YAML  — flat, 'name' + 'relevantTechniques', frequency
             in shorthand ('10m', '1h').
          2. ARM resource                  — 'kind' + everything under '.properties',
             'displayName' + 'techniques', ISO 8601 durations.
          3. ARM deployment template       — the above, nested inside 'resources[]' with the
             GUID hidden in a [concat()] name expression.
          4. Live Sentinel REST response   — same as (2) plus resource 'id'/'name' and
             read-only fields.

        Property lookup is CASE-INSENSITIVE and checks both the '.properties' sub-object and
        the root, because real-world exports mix casing (the SAP solution ships PascalCase
        'DisplayName'/'Query'/'QueryFrequency' at the root).

    .PARAMETER InputObject
        The parsed rule object (from ConvertFrom-Yaml, ConvertFrom-Json or a REST response).

    .PARAMETER SourceFormat
        Where the rule came from: CommunityYaml | ArmResource | ArmTemplate | LiveApi | Object.

    .PARAMETER SourcePath
        File path or resource id the rule came from. Carried through for reporting.

    .PARAMETER Template
        The enclosing ARM template, when the rule was found inside one. Used to resolve
        parameters() references in the resource name so the rule GUID survives.

    .OUTPUTS
        PSCustomObject with PSTypeName 'SentinelToXDR.SentinelRule'.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [PSObject]$InputObject,

        [Parameter()]
        [ValidateSet('CommunityYaml', 'ArmResource', 'ArmTemplate', 'LiveApi', 'Object')]
        [string]$SourceFormat = 'Object',

        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$SourcePath,

        [Parameter()]
        [AllowNull()]
        [PSObject]$Template
    )

    $uuidPattern = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'

    # A YAML mapping parsed by powershell-yaml is a Hashtable, JSON gives a PSCustomObject,
    # and REST responses give either. Normalize member access across all of them.
    function Get-Member2 {
        param([object]$Source, [string]$Name)
        if ($null -eq $Source) { return $null }
        if ($Source -is [System.Collections.IDictionary]) {
            foreach ($key in $Source.Keys) {
                if ([string]$key -ieq $Name) { return $Source[$key] }
            }
            return $null
        }
        $prop = $Source.PSObject.Properties | Where-Object { $_.Name -ieq $Name } | Select-Object -First 1
        if ($prop) { return $prop.Value }
        return $null
    }

    # ARM nests everything under .properties; community YAML is flat. Look in both,
    # properties first.
    $props = Get-Member2 -Source $InputObject -Name 'properties'
    function Get-RuleValue {
        param([string[]]$Names)
        foreach ($name in $Names) {
            if ($null -ne $props) {
                $value = Get-Member2 -Source $props -Name $name
                if ($null -ne $value -and $value -ne '') { return $value }
            }
            $value = Get-Member2 -Source $InputObject -Name $name
            if ($null -ne $value -and $value -ne '') { return $value }
        }
        return $null
    }

    # Durations arrive in four shapes across the corpus: ISO 8601 ('PT6H'), community
    # shorthand ('10m'), a .NET TimeSpan string ('06:00:00'), and a serialized TimeSpan
    # OBJECT with Ticks/TotalHours members (the SAP solution ships these). Normalize the
    # last two to ISO 8601 here so every downstream stage sees only ISO or shorthand.
    function ConvertTo-DurationText {
        param([object]$Value)

        # $null in, $null out: callers distinguish "absent" from "present but empty",
        # and the suppression check keys off presence.
        if ($null -eq $Value) { return $null }
        if ($Value -is [timespan]) { return (ConvertTo-IsoDurationText -Duration $Value) }

        if ($Value -isnot [string]) {
            $ticks = Get-Member2 -Source $Value -Name 'Ticks'
            if ($null -ne $ticks) {
                return (ConvertTo-IsoDurationText -Duration ([timespan]::FromTicks([long]$ticks)))
            }
            $totalHours = Get-Member2 -Source $Value -Name 'TotalHours'
            if ($null -ne $totalHours) {
                return (ConvertTo-IsoDurationText -Duration ([timespan]::FromHours([double]$totalHours)))
            }
            return [string]$Value
        }

        $text = $Value.Trim()
        # .NET TimeSpan string, e.g. '06:00:00' or '1.00:00:00'.
        if ($text -match '^\d+(\.\d+)?:\d{2}(:\d{2})?') {
            $parsed = [timespan]::Zero
            if ([timespan]::TryParse($text, [ref]$parsed)) {
                return (ConvertTo-IsoDurationText -Duration $parsed)
            }
        }
        return $text
    }

    # ---- Kind -------------------------------------------------------------------
    $kindRaw = Get-RuleValue -Names @('kind')
    $kind = if ($kindRaw) { [string]$kindRaw } else { (Get-SentinelRuleKind).DefaultKind }

    # ---- Display name -----------------------------------------------------------
    # ARM uses properties.displayName; community YAML uses the root 'name'. The ARM
    # resource 'name' is the resource path, never the display name, so it is only used
    # as a fallback when it is not a resource-shaped string.
    $displayName = [string](Get-RuleValue -Names @('displayName'))
    if ([string]::IsNullOrWhiteSpace($displayName)) {
        $rootName = [string](Get-Member2 -Source $InputObject -Name 'name')

        # A slash alone does not make it a resource path. Real community rules are called
        # things like 'Devices flapping online/offline' and 'IPS/IDS disabled', and
        # rejecting every name with a slash silently left 94 rules in the Azure-Sentinel
        # corpus with no name at all — unnamed rows in a migration report nobody can act
        # on. What actually marks a resource path is the provider namespace, either in the
        # name itself or on an ARM-shaped object's 'type'.
        $armType = [string](Get-Member2 -Source $InputObject -Name 'type')
        $isResourcePath = $rootName -match 'Microsoft\.SecurityInsights' -or
                          ($rootName -match '/' -and $armType -match 'Microsoft\.SecurityInsights')

        # Nor does a leading bracket. '[Entra ID] Privileged Role Assigned to User' is a
        # naming convention, not a template expression. An ARM expression wraps the WHOLE
        # string and calls a function: [concat(parameters('workspace'),'/...')].
        $isArmExpression = $rootName -match '^\[.+\]$' -and $rootName -match '\('

        if (-not [string]::IsNullOrWhiteSpace($rootName) -and
            -not $isArmExpression -and -not $isResourcePath -and $rootName -notmatch "^$uuidPattern$") {
            $displayName = $rootName
        }
    }

    # ---- Rule id ----------------------------------------------------------------
    # Order: community 'id' -> ARM resource name (resolved through the template when it
    # is an expression) -> the ARM resource id path -> alertRuleTemplateName.
    $ruleId = $null
    foreach ($candidateName in @('id', 'name', 'alertRuleTemplateName')) {
        $candidate = [string](Get-Member2 -Source $InputObject -Name $candidateName)
        if ([string]::IsNullOrWhiteSpace($candidate)) {
            $candidate = [string](Get-RuleValue -Names @($candidateName))
        }
        if ([string]::IsNullOrWhiteSpace($candidate)) { continue }

        # Resolve [concat(...)] style names against the enclosing template.
        if ($candidate -match '^\[') {
            $candidate = Resolve-ArmTemplateValue -Expression $candidate -Template $Template
        }
        if ($candidate -match $uuidPattern) {
            $ruleId = $Matches[0]
            break
        }
    }

    # ---- Enabled ----------------------------------------------------------------
    $enabledRaw = Get-RuleValue -Names @('enabled')
    $isEnabled = if ($null -ne $enabledRaw) {
        [bool]$enabledRaw
    } else {
        # Community YAML has no 'enabled'; it has a lifecycle 'status' where only
        # 'Deprecated' means the rule should not be turned on.
        $status = [string](Get-RuleValue -Names @('status'))
        if ([string]::IsNullOrWhiteSpace($status)) { $true } else { $status -ine 'Deprecated' }
    }

    # ---- Collections ------------------------------------------------------------
    $tactics = @()
    $tacticsRaw = Get-RuleValue -Names @('tactics')
    if ($null -ne $tacticsRaw) { $tactics = @($tacticsRaw | ForEach-Object { [string]$_ }) }

    $techniques = @()
    $techniquesRaw = Get-RuleValue -Names @('techniques', 'relevantTechniques')
    if ($null -ne $techniquesRaw) { $techniques = @($techniquesRaw | ForEach-Object { [string]$_ }) }

    $entityMappings = @()
    $entityMappingsRaw = Get-RuleValue -Names @('entityMappings')
    if ($null -ne $entityMappingsRaw) { $entityMappings = @($entityMappingsRaw) }

    # An ARM template can reference a parameter that carries no default, in which case
    # Resolve-ArmTemplateValue leaves the expression as written: "[parameters('x')]". A hard
    # [int] cast on that throws, and because this runs while the rule is being normalized it
    # takes the WHOLE RULE with it — the rule vanishes from the output with no verdict, no
    # diagnostic, and no entry in the report. That is silent data loss of the exact kind
    # this module exists to prevent, and it is invisible in a small sample: one rule in the
    # 5,162-rule Azure-Sentinel corpus trips it.
    #
    # The threshold is never fatal to a conversion — a non-default trigger threshold has no
    # XDR equivalent and is dropped with a diagnostic downstream regardless. So an
    # unreadable one must not cost the rule; it is reported and left null.
    $triggerThresholdRaw = Get-RuleValue -Names @('triggerThreshold')
    $triggerThreshold = $null
    if ($null -ne $triggerThresholdRaw) {
        $parsed = 0
        if ([int]::TryParse([string]$triggerThresholdRaw, [ref]$parsed)) {
            $triggerThreshold = $parsed
        } else {
            Write-Warning ("Rule '$displayName': triggerThreshold is '$triggerThresholdRaw', which is not a " +
                'number. This is usually an ARM template parameter with no default value. The threshold ' +
                'was not read; everything else about the rule converts normally.')
        }
    }

    [PSCustomObject]@{
        PSTypeName            = 'SentinelToXDR.SentinelRule'
        Id                    = $ruleId
        DisplayName           = $displayName
        Description           = [string](Get-RuleValue -Names @('description'))
        Kind                  = $kind
        Severity              = [string](Get-RuleValue -Names @('severity'))
        Enabled               = $isEnabled
        Query                 = [string](Get-RuleValue -Names @('query'))
        QueryFrequency        = ConvertTo-DurationText -Value (Get-RuleValue -Names @('queryFrequency'))
        QueryPeriod           = ConvertTo-DurationText -Value (Get-RuleValue -Names @('queryPeriod'))
        TriggerOperator       = [string](Get-RuleValue -Names @('triggerOperator'))
        TriggerThreshold      = $triggerThreshold
        Tactics               = $tactics
        Techniques            = $techniques
        EntityMappings        = $entityMappings
        CustomDetails         = Get-RuleValue -Names @('customDetails')
        AlertDetailsOverride  = Get-RuleValue -Names @('alertDetailsOverride')
        EventGroupingSettings = Get-RuleValue -Names @('eventGroupingSettings')
        IncidentConfiguration = Get-RuleValue -Names @('incidentConfiguration')
        SuppressionEnabled    = Get-RuleValue -Names @('suppressionEnabled')
        SuppressionDuration   = ConvertTo-DurationText -Value (Get-RuleValue -Names @('suppressionDuration'))
        RequiredDataConnectors = Get-RuleValue -Names @('requiredDataConnectors')
        SourceFormat          = $SourceFormat
        SourcePath            = $SourcePath
        RawRule               = $InputObject
    }
}
