function Resolve-GraphEntityMapping {
    <#
    .SYNOPSIS
        Converts Sentinel entityMappings into a Graph entityMappingConfiguration.

    .DESCRIPTION
        Sentinel describes an entity as a type plus a list of field mappings:

            entityMappings:
              - entityType: Account
                fieldMappings:
                  - identifier: FullName
                    columnName: TargetUserName
                  - identifier: Sid
                    columnName: TargetUserSid

        Graph describes the same thing as one typed object per entity kind, with one
        property per ROLE, each holding a query column name:

            entityMappings:
              accounts:
                - nameColumn: TargetUserName
                  sidColumn:  TargetUserSid

        So the Sentinel 'identifier' is exactly what selects the Graph column property.
        All field mappings for one Sentinel entity collapse into a SINGLE Graph entry,
        because the roles are properties of one entity rather than separate rows.

        The mapping table lives in src/Data/GraphDetectionRule.psd1. An identifier that
        maps to $null has no target column and is dropped with a diagnostic that names it,
        rather than being silently discarded. An entity TYPE with no Graph collection
        (IoTDevice, Malware, SubmissionMail) is dropped whole, also named.

        FileHash is special: Sentinel models a hash as its own entity with an Algorithm
        column and a Value column, while Graph models hashes as columns on the file
        entity (sha1Column / sha256Column). When the algorithm is not a literal this
        function cannot know which column applies and defaults to SHA-256 with a
        RequiresReview diagnostic.

        Producing a mapping is not the same as producing an ACCEPTABLE one. The service
        validates each mapping against a set of sufficient identifier combinations per
        entity type - an Account needs a strong identifier (SID, UPN, Entra object ID)
        while a Host is satisfied by a name alone - and refuses one that carries only
        weak identifiers. That rule appears in neither the Graph reference (which lists
        every column and marks none required) nor the product documentation; it was found
        by deploying. Because this function maps identifiers one at a time, sufficiency
        can only be judged on the finished entity, which is what the check before the
        collapse does. See EntityIdentifierRequirements in
        src/Data/GraphDetectionRule.psd1, which is still incomplete - an untested
        combination is treated as unknown and never reported.

    .PARAMETER EntityMappings
        The raw Sentinel entityMappings collection.

    .PARAMETER RuleName
        Rule display name, used in diagnostic text.

    .PARAMETER DiagnosticSink
        A List[object] the function appends conversion diagnostics to.

    .OUTPUTS
        An ordered hashtable shaped as a Graph entityMappingConfiguration, or $null when
        nothing could be mapped.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]$EntityMappings,

        [Parameter()]
        [string]$RuleName = '',

        [Parameter()]
        [AllowNull()]
        [object]$DiagnosticSink
    )

    $map = Get-GraphDetectionRuleMap
    $entityMap = $map.EntityMappings
    $docRef = 'https://learn.microsoft.com/graph/api/resources/security-entitymappingconfiguration?view=graph-rest-beta'

    function Add-EntityDiagnostic {
        param([string]$Severity, [string]$Action, [object]$SourceValue, [object]$TargetValue, [string]$Reason)
        if ($null -eq $DiagnosticSink) { return }
        $record = New-ConversionDiagnostic -Feature 'Alert enrichment' `
            -Capability 'Flexible entity mapping over Sentinel data' `
            -Severity $Severity -Action $Action -SourceValue $SourceValue `
            -TargetValue $TargetValue -Reason $Reason -DocReference $docRef
        $DiagnosticSink.Add($record)
        Write-Warning $record.Reason
    }

    if ($null -eq $EntityMappings -or $EntityMappings.Count -eq 0) { return $null }

    $result = [ordered]@{}
    $mappedCount = 0

    foreach ($entity in $EntityMappings) {
        if ($null -eq $entity) { continue }

        $entityType = [string]$entity.entityType
        if ([string]::IsNullOrWhiteSpace($entityType)) { continue }

        # Unknown to the mapping table entirely.
        # Action 'Unsupported' means the whole entity is lost; 'Dropped' is reserved for a
        # partial loss where the entity still attaches but with fewer columns. The
        # readiness assessment weighs those differently, so the distinction has to be real.
        if (-not $entityMap.ContainsKey($entityType)) {
            Add-EntityDiagnostic -Severity 'Warning' -Action 'Unsupported' -SourceValue $entityType -TargetValue $null `
                -Reason ("Rule '$RuleName' maps a Sentinel entity type '$entityType' that is not in the " +
                "Graph entity mapping table. The entity was dropped. If Microsoft added this entity type, " +
                "add it to src/Data/GraphDetectionRule.psd1.")
            continue
        }

        $definition = $entityMap[$entityType]
        $collection = $definition.Collection

        # Known type, but no Graph collection accepts it.
        if ([string]::IsNullOrWhiteSpace($collection)) {
            Add-EntityDiagnostic -Severity 'Warning' -Action 'Unsupported' -SourceValue $entityType -TargetValue $null `
                -Reason ("Rule '$RuleName' maps Sentinel entity type '$entityType', which has no equivalent " +
                "entity in Defender XDR custom detections. The entity was dropped; the columns it referenced " +
                "are still available in the query output and can be carried as custom details instead.")
            continue
        }

        $fieldMappings = @($entity.fieldMappings)
        if ($fieldMappings.Count -eq 0) {
            Add-EntityDiagnostic -Severity 'Warning' -Action 'Unsupported' -SourceValue $entityType -TargetValue $null `
                -Reason ("Rule '$RuleName' maps entity type '$entityType' with no fieldMappings, so there is no column " +
                'to identify it by. The entity was dropped.')
            continue
        }

        # All field mappings for one Sentinel entity collapse into ONE Graph entry.
        $graphEntity = [ordered]@{}
        $droppedIdentifiers = [System.Collections.Generic.List[string]]::new()
        $hashAlgorithmColumn = $null

        foreach ($fieldMapping in $fieldMappings) {
            $identifier = [string]$fieldMapping.identifier
            $columnName = [string]$fieldMapping.columnName
            if ([string]::IsNullOrWhiteSpace($columnName)) {
                # An identifier with no column names nothing. Recorded with the other
                # dropped identifiers below rather than skipped in silence.
                $droppedIdentifiers.Add("$(if ($identifier) { $identifier } else { '(no identifier)' }) (empty columnName)")
                continue
            }

            # FileHash: the Algorithm field names the column holding the algorithm, which
            # tells us nothing at conversion time. Remember it for the diagnostic below.
            if ($entityType -eq 'FileHash' -and $identifier -ieq 'Algorithm') {
                $hashAlgorithmColumn = $columnName
                continue
            }

            if (-not $definition.Identifiers.ContainsKey($identifier)) {
                $droppedIdentifiers.Add("$identifier (unknown)")
                continue
            }

            $targetProperty = $definition.Identifiers[$identifier]
            if ([string]::IsNullOrWhiteSpace($targetProperty)) {
                $droppedIdentifiers.Add($identifier)
                continue
            }

            # First writer wins: Sentinel allows two identifiers to target the same Graph
            # column (Name and FullName both feed nameColumn); keep the first and report
            # the collision rather than silently overwriting.
            if ($graphEntity.Contains($targetProperty)) {
                if ($graphEntity[$targetProperty] -ne $columnName) {
                    Add-EntityDiagnostic -Severity 'Info' -Action 'Dropped' -SourceValue "$identifier -> $columnName" -TargetValue $graphEntity[$targetProperty] `
                        -Reason ("Rule '$RuleName' maps two Sentinel identifiers onto the same Graph column " +
                        "'$targetProperty' for entity '$entityType'. Kept '$($graphEntity[$targetProperty])'; " +
                        "dropped '$columnName' (from identifier '$identifier').")
                }
                continue
            }

            $graphEntity[$targetProperty] = $columnName
        }

        if ($entityType -eq 'FileHash' -and $graphEntity.Count -gt 0) {
            $default = $map.HashAlgorithmColumns.Default
            Add-EntityDiagnostic -Severity 'Warning' -Action 'RequiresReview' -SourceValue $hashAlgorithmColumn -TargetValue $default `
                -Reason ("Rule '$RuleName' maps a FileHash entity. Defender XDR carries hashes as typed columns " +
                "on the file entity (sha1Column / sha256Column) rather than as an algorithm/value pair, and the " +
                "algorithm here comes from query column '$hashAlgorithmColumn' rather than a literal. The hash " +
                "was mapped to '$default'. Confirm the query emits SHA-256, or edit the output if it emits SHA-1.")
        }

        if ($droppedIdentifiers.Count -gt 0) {
            Add-EntityDiagnostic -Severity 'Warning' -Action 'Dropped' -SourceValue ($droppedIdentifiers -join ', ') -TargetValue $null `
                -Reason ("Rule '$RuleName' entity '$entityType': $($droppedIdentifiers.Count) field mapping(s) " +
                "[$($droppedIdentifiers -join ', ')] have no matching column on the Graph '$collection' entity " +
                "and were dropped. The other field mappings for this entity were carried.")
        }

        if ($graphEntity.Count -eq 0) { continue }

        # Constraint 5. The service validates each entity mapping against a set of
        # sufficient identifier COMBINATIONS per entity type and refuses one that carries
        # only weak identifiers - accounts on a name alone is refused, hosts on a name
        # alone is accepted, and accounts on a name PLUS a domain is accepted. Stated in
        # neither the Graph reference nor the product documentation; found by deploying.
        # This loop maps identifiers to columns one at a time and has no notion of a
        # combination, which is why the check happens here, on the finished entity.
        #
        # The three-way outcome is the point. Superset of a sufficient combination:
        # accept. Exactly a confirmed-weak set: report, the deployment will fail.
        # Anything else: UNKNOWN, and unknown says nothing - the confirmed table comes
        # from probing a live tenant and is deliberately incomplete.
        $confirmed = $map.EntityIdentifierRequirements.Confirmed
        if ($confirmed.ContainsKey($collection)) {
            $spec = $confirmed[$collection]
            $emitted = @($graphEntity.Keys)

            # Each entry is one combination, written as columns joined by ' + '.
            $splitCombination = { param([string]$Combination)
                @($Combination -split '\+' | ForEach-Object { $_.Trim() } |
                    Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
            }

            $hasSufficient = $false
            foreach ($combination in @($spec.Sufficient)) {
                $required = & $splitCombination $combination
                if ($required.Count -eq 0) { continue }
                $missing = @($required | Where-Object { $_ -notin $emitted })
                if ($missing.Count -eq 0) { $hasSufficient = $true; break }
            }

            # Every emitted column has to be one this entity type is CONFIRMED to be
            # refused on. One untested column and the whole mapping is unknown.
            $weakColumns = @($spec.Insufficient | ForEach-Object { & $splitCombination $_ } | Select-Object -Unique)
            $allKnownWeak = $weakColumns.Count -gt 0 -and
                @($emitted | Where-Object { $_ -notin $weakColumns }).Count -eq 0

            # Where the service has enumerated every sufficient combination, anything that is
            # not a superset of one of them is refused - that is a statement from the service,
            # not an inference. Everywhere else the conservative rule above still decides.
            $knownRefused = -not $hasSufficient -and ($spec.Complete -or $allKnownWeak)

            if ($knownRefused) {
                # Name the fix in the source rule's own vocabulary: reverse the identifier
                # table to find which Sentinel identifiers reach a sufficient column.
                $sufficientColumns = @($spec.Sufficient | ForEach-Object { & $splitCombination $_ } | Select-Object -Unique)
                $identifierFix = @($definition.Identifiers.Keys | Where-Object {
                        $definition.Identifiers[$_] -in $sufficientColumns
                    } | Sort-Object)

                $accepted = if (@($spec.Sufficient).Count -gt 0) {
                    "The '$collection' entity is accepted with [" + (@($spec.Sufficient) -join '] or [') + '].'
                }
                else {
                    "No sufficient combination for the '$collection' entity has been established yet, so " +
                    'the columns that would satisfy it are not known - only that these do not.'
                }

                $inSentinelTerms = if ($identifierFix.Count -gt 0) {
                    " On this entity type that means one of these Sentinel identifiers: $($identifierFix -join ', ')."
                }
                else { '' }

                New-ApiConstraintDiagnostic -Constraint 'EntityIdentifierWeak' -Action 'Unsupported' `
                    -SourceValue "$entityType -> $($emitted -join ', ')" -DiagnosticSink $DiagnosticSink `
                    -Reason ("Rule '$RuleName' maps entity '$entityType' on [$($emitted -join ', ')], and the " +
                    "custom detection API refuses that combination. $accepted$inSentinelTerms") | Out-Null
            }
        }

        if (-not $result.Contains($collection)) {
            $result[$collection] = [System.Collections.Generic.List[object]]::new()
        }
        $result[$collection].Add($graphEntity)
        $mappedCount++
    }

    if ($mappedCount -eq 0) { return $null }

    # Materialize the lists as arrays so YAML/JSON serialization is clean.
    $final = [ordered]@{}
    foreach ($key in $result.Keys) {
        $final[$key] = @($result[$key])
    }
    return $final
}
