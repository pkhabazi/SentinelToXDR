function ConvertTo-DetectionPatchBody {
    <#
    .SYNOPSIS
        Reduces a detection rule to the properties PATCH will actually accept.

    .DESCRIPTION
        POST and PATCH do not take the same body, and the difference is not cosmetic.

        POST /security/rules/detectionRules creates the rule and takes the whole object,
        id included. PATCH /security/rules/detectionRules/{id} addresses the rule by id in
        the URI and documents a CLOSED set of updatable properties: description,
        detectionAction, displayName, queryCondition, schedule, status. Everything else is
        server-owned — id, createdBy, createdDateTime, lastModifiedBy, lastModifiedDateTime,
        @odata.type — and echoing one of those back is rejected.

        That matters more than it first appears. The object we PATCH is almost always one we
        either just built for a POST or just read back off the wire, so it carries exactly
        the properties PATCH refuses. The failure lands on the SECOND run of a migration —
        the update path, the one that makes a re-run safe — while the first run looked
        perfect. Filtering here is what keeps those two runs equivalent.

        The updatable list is data, not code: it lives in
        src/Data/GraphDetectionRule.psd1 under UpdatableProperties, so a Graph model change
        is a data edit. Filtering is allow-list rather than deny-list on purpose — a
        property Microsoft adds to the resource but not to the updatable set would otherwise
        start failing deployments the moment it appeared in a response.

    .PARAMETER Rule
        The detection rule to reduce. Accepts an ordered hashtable (as the converter
        produces) or a PSCustomObject (as ConvertFrom-Json produces).

    .OUTPUTS
        An ordered hashtable holding only the updatable properties present on the input,
        in the order the updatable list defines.

    .EXAMPLE
        ConvertTo-DetectionPatchBody -Rule $graphRule

        Returns the same rule without id or any service-owned property.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory)]
        [object]$Rule
    )

    $updatable = (Get-GraphDetectionRuleMap).UpdatableProperties
    $body = [ordered]@{}

    # Read the input uniformly, whichever shape it arrived in.
    $read = if ($Rule -is [System.Collections.IDictionary]) {
        { param([string]$Name) if ($Rule.Contains($Name)) { $Rule[$Name] } else { $null } }
    } else {
        {
            param([string]$Name)
            $property = $Rule.PSObject.Properties | Where-Object { $_.Name -ieq $Name } | Select-Object -First 1
            if ($property) { $property.Value } else { $null }
        }
    }

    # Deprecated properties NESTED inside an updatable one, keyed by the updatable property
    # they live under. UpdatableProperties filters the top level; this filters one level in.
    #
    # That distinction is not academic. 'schedule' is updatable, and a schedule read back
    # from the service carries its own deprecated 'period' - which the service sets to
    # 'Custom' for an ISO 8601 frequency it has no enum value for. PATCHing that straight
    # back gets:
    #
    #   Schedule.Period 'Custom' is not in a recognized format. Valid formats are
    #   0, 1H, 3H, 12H, 24H.
    #
    # So the service rejects a value it produced itself. Found on 2026-08-24 by the round
    # trip, on the update leg - the same leg, and the same class of bug, as the top-level
    # id echo fixed just before it. A create-only test never sees either.
    $map = Get-GraphDetectionRuleMap
    $nestedDeprecated = @{}
    foreach ($deprecated in $map.DeprecatedProperties) {
        $parts = @([string]$deprecated.Path -split '\.')
        if ($parts.Count -ne 2) { continue }
        # DeprecatedProperties names the RESOURCE type ('ruleSchedule.period'); the body
        # names the PROPERTY ('schedule'). Match on the leaf and let the caller's own
        # property names decide where it applies.
        if (-not $nestedDeprecated.ContainsKey($parts[1])) { $nestedDeprecated[$parts[1]] = $true }
    }

    # Remove deprecated and service-owned keys from a nested object, without mutating what
    # the caller handed us.
    $stripNested = {
        param([object]$Value)
        if ($Value -is [System.Collections.IDictionary]) {
            $clean = [ordered]@{}
            foreach ($key in $Value.Keys) {
                if ($nestedDeprecated.ContainsKey([string]$key)) { continue }
                $clean[[string]$key] = $Value[$key]
            }
            return $clean
        }
        if ($Value -is [System.Management.Automation.PSCustomObject]) {
            $clean = [ordered]@{}
            foreach ($property in $Value.PSObject.Properties) {
                if ($nestedDeprecated.ContainsKey($property.Name)) { continue }
                $clean[$property.Name] = $property.Value
            }
            return $clean
        }
        return $Value
    }

    foreach ($name in $updatable) {
        $value = & $read $name
        # A property that is absent is not the same as one set to null: only carry what the
        # caller actually supplied, so a PATCH never blanks a field it was not asked to.
        if ($null -ne $value) { $body[$name] = & $stripNested $value }
    }

    if ($body.Count -eq 0) {
        Write-Verbose ("The rule carried none of the updatable properties ($($updatable -join ', ')). " +
            'The resulting PATCH would be a no-op.')
    }

    return $body
}
