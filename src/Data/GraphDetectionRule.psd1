@{
    # -------------------------------------------------------------------------
    # Mapping data for the Microsoft Graph custom-detection target model
    # (microsoft.graph.security.detectionRule, beta).
    #
    # This file is the SINGLE SOURCE OF TRUTH for how a Sentinel analytics rule
    # is rendered into the Graph detectionRule shape. When Microsoft adds an
    # entity mapping kind, a column role or an alert severity value, this is a
    # DATA edit, not a code change.
    #
    # AUTHORITATIVE SOURCES (fetched 2026-08-11):
    #   detectionRule              /graph/api/resources/security-detectionrule
    #   ruleSchedule               /graph/api/resources/security-ruleschedule
    #   alertTemplate              /graph/api/resources/security-alerttemplate
    #   entityMappingConfiguration /graph/api/resources/security-entitymappingconfiguration
    #   detectionAction            /graph/api/resources/security-detectionaction
    #   automatedActionSet         /graph/api/resources/security-automatedactionset
    #   mitreTactic                /graph/api/resources/security-mitretactic
    #   plus the per-entity mapping resources referenced in EntityMappings below.
    # -------------------------------------------------------------------------
    Metadata = @{
        SourceDoc   = 'Microsoft Graph beta - microsoft.graph.security.detectionRule'
        SourceUrl   = 'https://learn.microsoft.com/graph/api/resources/security-detectionrule?view=graph-rest-beta'
        FetchedDate = '2026-08-11'
        ApiVersion  = 'beta'
        Endpoint    = '/security/rules/detectionRules'
        Note        = 'Graph is the canonical target model from v2.0. The legacy XDRConverter YAML shape is rendered from the same decision engine and is opt-in.'
    }

    # -------------------------------------------------------------------------
    # Properties Microsoft has announced for removal on 2026-10-01. The renderer
    # never emits these; they are listed so the deprecation is documented in data
    # and so a reader of the module knows WHY the legacy shape is legacy.
    # -------------------------------------------------------------------------
    DeprecatedProperties = @(
        @{ Path = 'detectionRule.isEnabled';              ReplacedBy = 'status';                       RemovalDate = '2026-10-01' }
        @{ Path = 'detectionRule.detectorId';             ReplacedBy = 'id';                           RemovalDate = '2026-10-01' }
        @{ Path = 'detectionRule.lastRunDetails';         ReplacedBy = '';                             RemovalDate = '2026-10-01' }
        @{ Path = 'ruleSchedule.period';                  ReplacedBy = 'frequency (ISO 8601 duration)'; RemovalDate = '2026-10-01' }
        @{ Path = 'ruleSchedule.nextRunDateTime';         ReplacedBy = '';                             RemovalDate = '2026-10-01' }
        @{ Path = 'alertTemplate.category';               ReplacedBy = 'tactics';                      RemovalDate = '2026-10-01' }
        @{ Path = 'alertTemplate.mitreTechniques';        ReplacedBy = 'tactics[].techniques[]';       RemovalDate = '2026-10-01' }
        @{ Path = 'alertTemplate.impactedAssets';         ReplacedBy = 'entityMappings';               RemovalDate = '2026-10-01' }
        @{ Path = 'detectionAction.responseActions';      ReplacedBy = 'automatedActions';             RemovalDate = '2026-10-01' }
    )

    # -------------------------------------------------------------------------
    # Properties PATCH /security/rules/detectionRules/{id} accepts in its body.
    #
    # Everything else on the resource is server-owned. 'id' is addressed in the
    # URI and is NOT an updatable property; createdBy, createdDateTime,
    # lastModifiedBy, lastModifiedDateTime and @odata.type are set by the
    # service and only ever appear on a response. Echoing any of them back is
    # what turns a second run of a migration into an HTTP 400 — which is the
    # run that matters, because it is the one that updates rather than creates.
    #
    # 'isEnabled' is documented as updatable but is deprecated and removed on
    # 2026-10-01 (see DeprecatedProperties). It is deliberately absent here, so
    # that filtering through this list also strips it from a rule object that
    # came from somewhere other than this converter.
    #
    # SOURCE: /graph/api/security-detectionrule-update?view=graph-rest-beta,
    # 'Request body' — "supply only the values for properties to update".
    # Fetched 2026-08-19.
    # -------------------------------------------------------------------------
    UpdatableProperties = @(
        'description'
        'detectionAction'
        'displayName'
        'queryCondition'
        'schedule'
        'status'
    )

    # -------------------------------------------------------------------------
    # What the service ACTUALLY enforces on alertTemplate.tactics.
    #
    # These two rules are not in the documentation. The mitreTactic resource is
    # modelled as a collection with an optional techniques array, and the
    # renderer was built to that model. Both assumptions are wrong, and the only
    # way to find out was to POST a rule and read the 400:
    #
    #   {"code":"InvalidInput","message":"Only one tactic is currently supported."}
    #   {"code":"InvalidInput","message":"Tactic 'Execution' must specify at least one technique."}
    #
    # The first one confirms what this module's own capability data already said:
    # 'Link multiple MITRE tactics' is State = Planned in
    # CustomDetectionCapabilities.psd1. The renderer overrode that on the grounds
    # that the beta API models the array. It models it; it does not accept it.
    #
    # SOURCE: observed from POST /security/rules/detectionRules against a live
    # tenant on 2026-08-19, NOT from a published document. That is exactly why it
    # is recorded here with its provenance: when Microsoft lifts either limit, a
    # round-trip run will stop reporting the rejection and this becomes a data
    # edit, not an archaeology exercise.
    # -------------------------------------------------------------------------
    # 2026-09-15: RE-PROBED on ids that had never existed in the tenant, and two of the
    # three limits recorded here had gone:
    #
    #   tactic with techniques: []  -> ACCEPTED, stored as {"tactic":"Execution",
    #                                  "techniques":[]}   (was refused on 2026-08-19)
    #   no tactics, no category     -> ACCEPTED            (was refused on 2026-08-19)
    #   two tactics                 -> still refused, new wording:
    #                                  'Multiple MITRE tactics are not supported.
    #                                   Specify a single tactic.'
    #
    # The two that went are almost certainly being retired ahead of 2026-10-01, when
    # 'category' is removed: a requirement for 'tactics or category' would otherwise become
    # 'tactics, mandatory' on that date and make every rule without MITRE data
    # unmigratable. Keeping both switches as DATA is what made this a one-line correction
    # rather than an excavation.
    # LastConfirmed is stamped by tests/Integration/Probes/Probe-ApiBehaviour.ps1 runs (by
    # hand, from the run's output). A constraint whose LastConfirmed is older than the
    # newest run is due a re-probe, not a belief.
    TacticConstraints = @{
        MaxTactics                  = 1
        TechniqueRequiredPerTactic  = $false
        Source                      = 'Observed from the live API (HTTP 400 InvalidInput); not documented.'
        ObservedDate                = '2026-09-15'
        LastConfirmed               = '2026-09-16'
        MaxTacticsError             = 'Multiple MITRE tactics are not supported. Specify a single tactic.'
        TechniqueRequiredError      = ''
        History                     = @(
            @{ Date = '2026-08-19'; MaxTactics = 1; TechniqueRequiredPerTactic = $true; Note = 'A tactic with no technique was refused, and tactics or category was mandatory.' }
            @{ Date = '2026-09-15'; MaxTactics = 1; TechniqueRequiredPerTactic = $false; Note = 'Both of those requirements gone; the one-tactic limit remains, with new error text.' }
        )
    }

    # -------------------------------------------------------------------------
    # What the service accepts as a rule id. Found on 2026-09-16, on the FIRST deploy of
    # a rule carrying its raw Sentinel GUID:
    #
    #   "Invalid rule identifier format. Rule ID must consist of letters, numbers, dashes,
    #    or underscores only, begin with a letter, and not exceed 100 characters."
    #
    # A GUID begins with a digit ten times out of sixteen, so most Sentinel rule ids are
    # refused as-is. Every earlier live run had prefixed its ids ('s2x-validation-',
    # 's2x-probe-') for cleanup, which is exactly why none of them ever tripped this.
    #
    # Ids that already satisfy the pattern are sent unchanged, so a re-run maps to the
    # same detection. Ids that do not are prefixed and sanitised, deterministically, and
    # the change is reported as a diagnostic. Probed 2026-09-16: digit-leading refused,
    # letter-leading accepted, 'r-' + the same GUID accepted, 101 chars refused, '.' refused.
    # -------------------------------------------------------------------------
    RuleIdPolicy = @{
        Pattern       = '^[A-Za-z][A-Za-z0-9_-]{0,99}$'
        Prefix        = 'r-'
        MaxLength     = 100
        Error         = 'Invalid rule identifier format. Rule ID must consist of letters, numbers, dashes, or underscores only, begin with a letter, and not exceed 100 characters.'
        Constraint    = 'RuleIdPrefixed'
        FirstObserved = '2026-09-16'
        LastConfirmed = '2026-09-16'
    }

    # -------------------------------------------------------------------------
    # Fields the service REQUIRES on alertTemplate, and the catch in each.
    #
    # Both requirements name a DEPRECATED property as the acceptable alternative,
    # and both of those are removed on 2026-10-01 (see DeprecatedProperties).
    # That is not a footnote: it means a Sentinel rule with no MITRE data, or no
    # entity mappings, can migrate today only by way of a property that stops
    # existing in weeks. After that date such a rule cannot become a custom
    # detection until the source rule is edited.
    #
    # This module never emits the deprecated forms, so for its output these are
    # hard requirements. A rule that cannot satisfy them is not a conversion
    # warning — it will be refused on deployment, and the assessment has to say
    # so before the user tries.
    #
    # SOURCE: observed from POST /security/rules/detectionRules on 2026-08-19:
    #   {"code":"InvalidInput","message":"Either tactics or category must be provided."}
    #   {"code":"InvalidInput","message":"At least one of impactedAssets or entityMappings must be provided."}
    # An empty entityMappings object counts as absent (same error).
    # -------------------------------------------------------------------------
    # Constraint is the finding name the converter raises when the field is absent;
    # src/Data/MigrationReadiness.psd1 matches on it to decide the impact, so the
    # severity of a missing field is a data decision in that file, not this one.
    #
    # SupersededBy names a finding that already explains the same absence with a
    # better remedy. A rule with tactics but no techniques emits no tactics at all
    # (constraint 2), which then trips this requirement too - but the user needs
    # ONE instruction, 'add relevantTechniques', not two findings describing the
    # same missing field.
    RequiredAlertTemplateFields = @(
        # The 'tactics' entry was removed on 2026-09-15. Until then a rule carrying neither
        # tactics nor category was refused with 'Either tactics or category must be
        # provided.'; a fresh-id probe that day was ACCEPTED. Over the corpus that single
        # line had been grading 795 rules as certain to be rejected, plus 421 more through
        # the technique requirement above - 1,216 rules told they would be refused by a
        # service that takes them. A false rejection is the same failure as a false green,
        # pointed the other way, so it comes out the moment the evidence does.
        @{
            Field           = 'entityMappings'
            Constraint      = 'EntityMappingsMissing'
            FirstObserved   = '2026-08-19'
            LastConfirmed   = '2026-09-16'
            SupersededBy    = ''
            DeprecatedAlternative = 'impactedAssets'
            AlternativeRemovalDate = '2026-10-01'
            Error           = 'At least one of impactedAssets or entityMappings must be provided.'
            SourceRuleFix   = 'Add an entityMappings entry to the Sentinel rule whose identifiers map to a Defender column.'
        }
    )

    # -------------------------------------------------------------------------
    # Entity mappings are validated per entity type, and a mapping carrying the
    # wrong COMBINATION of columns is refused:
    #
    #   "Entity mapping for 'User' is invalid. At least one mandatory field
    #    combination must have non-empty column values."
    #
    # Stated in NEITHER the Graph reference (which lists every column and marks
    # none required) NOR the product documentation. Found by deploying.
    #
    # Sufficiency is a property of column SETS, not of single columns, and the
    # probe run on 2026-08-24 is what settled that: accounts {nameColumn} is
    # REFUSED and accounts {nameColumn, ntDomainColumn} is ACCEPTED, so a name
    # plus a domain is sufficient even though a name is not and the domain alone
    # is untested. The product doc's "strong identifier" list would not have
    # predicted that.
    #
    # FORMAT: each entry is one COMBINATION, written as its columns joined by
    # ' + '. A single column is just a one-column combination. They are strings
    # rather than nested arrays because PowerShell flattens @(@('a'),@('b','c'))
    # into a single array when a .psd1 is imported, which would silently turn
    # 'name AND domain' into 'name OR domain' - the exact over-permissive reading
    # this table exists to prevent.
    #
    # An emitted mapping is ACCEPTED when its columns are a SUPERSET of any
    # Sufficient combination.
    #
    # The converter maps Sentinel identifiers to Graph columns ONE AT A TIME with
    # no notion of a combination, which is why the check happens on the finished
    # entity in Resolve-GraphEntityMapping.
    #
    # HOW TO READ Untested: it means UNKNOWN, not invalid. A combination that is
    # neither a superset of a Sufficient entry nor exactly a confirmed
    # Insufficient one produces NO finding. Grading a rule down on an unprobed
    # combination is the same class of error this whole release removes.
    #
    # EVIDENCE, all from a live tenant:
    #   2026-08-24  tests/Integration/Probes/Probe-EntityCombinations.ps1
    #   2026-08-24  round trip over ./Samples (samples 08 and 10)
    # Four probe cases (accounts upnSuffixColumn, ips addressColumn, mailboxes
    # primaryAddressColumn, urls addressColumn) were CONFOUNDED - the probe query
    # did not project the columns they mapped, so they failed on the
    # projected-columns constraint rather than on identifiers. They are recorded
    # as Untested, not Insufficient. A probe has to be valid in every respect
    # except the one under test, and that one was not.
    # -------------------------------------------------------------------------
    # ---- 2026-09-15: the service now states the table itself -----------------
    # The refusal message changed between the 2026-08-24 and 2026-09-15 runs. It
    # used to say only that 'at least one mandatory field combination' was missing.
    # It now ENUMERATES the combinations:
    #
    #   Entity mapping for 'User' is invalid. Set non-empty column values for all
    #   fields in at least one of these combinations: aadUserIdColumn; sidColumn;
    #   upnColumn; nameColumn + ntDomainColumn; nameColumn + dnsDomainColumn;
    #   nameColumn + upnSuffixColumn.
    #
    # For every entity type below marked Complete = $true, Sufficient is copied
    # VERBATIM from that message, and the rule inverts: a mapping that is not a
    # superset of any listed combination is KNOWN to be refused, because the
    # service has said which ones it accepts. Redundant entries (hosts lists
    # 'nameColumn + ntDomainColumn' although 'nameColumn' alone suffices) are kept
    # as stated, so a future diff against the service message stays trivial.
    #
    # Complete = $false means only accepted cases are known. Those types still
    # follow the original rule: accepted if a superset, refused only if every
    # column is confirmed weak, and otherwise UNKNOWN and silent.
    #
    # Two corrections this made to the 2026-08-24 table, both of which had been
    # making the module UNDER-report: 'nameColumn + dnsDomainColumn' and
    # 'nameColumn + upnSuffixColumn' are sufficient for accounts (upnSuffix had
    # been confounded, dnsDomain untested), and a host on netBiosNameColumn alone
    # is refused.
    # -------------------------------------------------------------------------
    EntityIdentifierRequirements = @{
        Status = 'Complete for accounts, hosts, files, mailMessages and registryValues, as enumerated by the service on 2026-09-15. ips, urls and mailboxes: accepted combinations confirmed, full list not stated.'
        FirstObserved = '2026-08-24'
        LastConfirmed = '2026-09-16'
        Error  = "Entity mapping for '{0}' is invalid. Set non-empty column values for all fields in at least one of these combinations: {1}."
        Confirmed = @{
            accounts = @{
                Complete     = $true
                Sufficient   = @(
                    'aadUserIdColumn'
                    'sidColumn'
                    'upnColumn'
                    'nameColumn + ntDomainColumn'
                    'nameColumn + dnsDomainColumn'
                    'nameColumn + upnSuffixColumn'
                )
                Insufficient = @()
                Untested     = @()
            }
            hosts = @{
                Complete     = $true
                Sufficient   = @(
                    'deviceIdColumn'
                    'nameColumn'
                    'nameColumn + ntDomainColumn'
                    'nameColumn + dnsDomainColumn'
                    'netBiosNameColumn + ntDomainColumn'
                    'netBiosNameColumn + dnsDomainColumn'
                )
                Insufficient = @()
                Untested     = @()
            }
            files = @{
                Complete     = $true
                Sufficient   = @(
                    'sha1Column'
                    'sha256Column'
                    'nameColumn + sha1Column'
                    'nameColumn + sha256Column'
                )
                Insufficient = @()
                Untested     = @()
            }
            mailMessages = @{
                # All four, together. Nothing less is accepted.
                Complete     = $true
                Sufficient   = @(
                    'networkMessageIdColumn + recipientColumn + senderColumn + subjectColumn'
                )
                Insufficient = @()
                Untested     = @()
            }
            registryValues = @{
                # Stated by the service on 2026-09-15 when sample 08 was refused.
                Complete     = $true
                Sufficient   = @(
                    'keyColumn + valueNameColumn'
                )
                Insufficient = @()
                Untested     = @()
            }
            ips = @{
                Complete     = $false
                Sufficient   = @('addressColumn')
                Insufficient = @()
                Untested     = @()
            }
            urls = @{
                Complete     = $false
                Sufficient   = @('addressColumn')
                Insufficient = @()
                Untested     = @()
            }
            mailboxes = @{
                Complete     = $false
                Sufficient   = @('primaryAddressColumn')
                Insufficient = @()
                Untested     = @()
            }
        }
    }

    # -------------------------------------------------------------------------
    # At least one ASSET entity, or an IP, must be present across the whole
    # entityMappings object:
    #
    #   "At least one asset entity (Machine, User, or Mailbox) or an IP entity
    #    must be included."
    #
    # A rule mapping only a file, a URL, a registry value or a cloud application
    # is refused however well-formed those mappings are. Undocumented; found on
    # 2026-08-24 by sample 07 in the round trip.
    #
    # This is a whole-object rule, unlike EntityIdentifierRequirements which is
    # per entity. Collections are the entityMappingConfiguration property names.
    # -------------------------------------------------------------------------
    RequiredEntityKinds = @{
        FirstObserved = '2026-08-24'
        LastConfirmed = '2026-09-16'
        Collections = @('hosts', 'accounts', 'mailboxes', 'ips')
        Error       = 'At least one asset entity (Machine, User, or Mailbox) or an IP entity must be included.'
        Constraint  = 'AssetEntityMissing'
        SourceRuleFix = 'Map a Host, Account, Mailbox or IP entity on the Sentinel rule. The entities already mapped here attach to the alert but cannot carry it on their own.'
    }

    # -------------------------------------------------------------------------
    # alertTemplate.tactics[].techniques[] is a mitreTechnique: ONE parent
    # technique plus a collection of its subtechniques.
    #
    #   { technique: 'T1059', subTechniques: ['T1059.001'] }
    #
    # SOURCE: /graph/api/resources/security-mitretechnique?view=graph-rest-beta
    # (fetched 2026-09-15). This IS documented - and the renderer ignored it,
    # emitting every subtechnique as a technique of its own.
    #
    # How it was found, because the path matters: the round trip on 2026-08-24
    # reported 'sent 2 techniques, stored 1' and it was written up as an
    # undocumented constraint - the service silently discarding a technique.
    # Once the drift report named values instead of counting them (2026-09-15),
    # the stored form turned out to be { technique: T1059, subTechniques:
    # [T1059.001] }: nothing discarded, just our malformed input normalised into
    # the documented shape. It was never a service constraint. It was a renderer
    # bug that a count-only diff made look like one.
    #
    # The grouping is deterministic from the id format, not an inference: a
    # subtechnique id is its parent id plus '.NNN'. A lone subtechnique with no
    # parent listed still gets its parent entry, because the model has nowhere
    # else to put it.
    # -------------------------------------------------------------------------
    # 2026-09-16, Probe-ApiBehaviour.ps1 and the round trip: a technique attached to a tactic
    # it does not belong to (Execution + T1547) came back MISSING on one read-back and
    # PRESENT on the next, same payload, an hour apart; sample 02 lost T1547 on two of two
    # runs. Not established - the read path lags the write path by hours - and therefore
    # not modelled. The round trip names the difference as StoredWithDrift, which is the
    # honest report until a probe settles it.
    TechniqueShape = @{
        ForeignTechniquesInconsistent = $true
        ForeignTechniquesObserved  = '2026-09-16'
        SubtechniquePattern = '^(T\d{4})\.\d{3}$'
        SourceUrl           = 'https://learn.microsoft.com/graph/api/resources/security-mitretechnique?view=graph-rest-beta'
        FetchedDate         = '2026-09-15'
        StoredFormObserved  = '2026-09-15'
    }

    # -------------------------------------------------------------------------
    # detectionRule.status  <-  Sentinel enabled / status
    # Enum: enabled | disabled | autoDisabled | unknownFutureValue
    # autoDisabled is set BY the service; the converter never emits it.
    # -------------------------------------------------------------------------
    Status = @{
        WhenEnabled  = 'enabled'
        WhenDisabled = 'disabled'
        Values       = @('enabled', 'disabled', 'autoDisabled', 'unknownFutureValue')
    }

    # -------------------------------------------------------------------------
    # alertTemplate.severity  <-  Sentinel severity.
    # Graph uses LOWER-CASE values; Sentinel uses Title Case.
    # -------------------------------------------------------------------------
    Severity = @{
        'Informational' = 'informational'
        'Low'           = 'low'
        'Medium'        = 'medium'
        'High'          = 'high'
    }

    # -------------------------------------------------------------------------
    # alertTemplate.tactics[].tactic  <-  Sentinel tactics[]
    #
    # The Graph model carries a COLLECTION of tactics, each with its own
    # techniques -- and the service accepts exactly ONE entry in it, which must
    # carry at least one technique. See TacticConstraints above: the collection
    # is modelled, it is not accepted. This comment previously claimed the
    # opposite and the renderer was built to it; that was wrong, and only a live
    # POST could show it. 'Link multiple MITRE tactics' is State = Planned in
    # CustomDetectionCapabilities.psd1, which was right all along.
    #
    # The table below is unaffected -- it maps NAMES. Which of the mapped tactics
    # survives the one-tactic limit is decided in Resolve-GraphTactic, from
    # TacticConstraints, and the loss is reported as TacticsTruncated.
    #
    # Key   = Sentinel tactic name (as written in analytics rule YAML/ARM)
    # Value = Graph tactic string. $null means Sentinel-only with no ATT&CK
    #         equivalent recognised by the target; those are dropped + diagnosed.
    # -------------------------------------------------------------------------
    Tactics = @{
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
        'Reconnaissance'          = 'Reconnaissance'
        'ResourceDevelopment'     = 'ResourceDevelopment'
        # Sentinel-only tactic names with no ATT&CK Enterprise equivalent.
        'PreAttack'               = 'Reconnaissance'
        'ImpairProcessControl'    = 'Impact'
        'InhibitResponseFunction' = 'Impact'
    }

    # -------------------------------------------------------------------------
    # alertTemplate.entityMappings  <-  Sentinel entityMappings[]
    #
    # Sentinel expresses an entity as { entityType, fieldMappings[{ identifier,
    # columnName }] }. Graph expresses it as a typed object per entity kind, with
    # one property per ROLE, each holding a query COLUMN NAME. So the Sentinel
    # 'identifier' (which the legacy shape threw away) is exactly what selects
    # the Graph column property.
    #
    # Each entry below:
    #   Collection  = the entityMappingConfiguration property to append to
    #   OdataType   = the Graph type (documentation aid; not emitted)
    #   Identifiers = Sentinel identifier -> Graph column property.
    #                 A $null value means the identifier has no target column and
    #                 is dropped with a diagnostic naming the exact identifier.
    #
    # All 11 entityType values and all 22 identifier values that occur in the
    # Azure-Sentinel repo corpus (2730 analytics rule YAML files, checked
    # 2026-08-11) are covered below.
    # -------------------------------------------------------------------------
    EntityMappings = @{
        'Account' = @{
            Collection  = 'accounts'
            OdataType   = 'microsoft.graph.security.accountEntityMapping'
            Identifiers = @{
                'Name'       = 'nameColumn'
                'FullName'   = 'nameColumn'
                'NTDomain'   = 'ntDomainColumn'
                'DnsDomain'  = 'dnsDomainColumn'
                'UPNSuffix'  = 'upnSuffixColumn'
                'Upn'        = 'upnColumn'
                'Sid'        = 'sidColumn'
                'AadUserId'  = 'aadUserIdColumn'
                'ObjectGuid' = 'aadUserIdColumn'
                'IsDomainJoined' = $null
                'DisplayName'    = 'nameColumn'
                'CloudAppAccountId' = $null
            }
        }
        'Host' = @{
            Collection  = 'hosts'
            OdataType   = 'microsoft.graph.security.hostEntityMapping'
            Identifiers = @{
                'HostName'    = 'nameColumn'
                'FullName'    = 'nameColumn'
                'NetBiosName' = 'netBiosNameColumn'
                'NTDomain'    = 'ntDomainColumn'
                'DnsDomain'   = 'dnsDomainColumn'
                'AzureID'     = 'deviceIdColumn'
                'OMSAgentID'  = 'deviceIdColumn'
                'OSVersion'   = $null
                'OSFamily'    = $null
            }
        }
        'IP' = @{
            Collection  = 'ips'
            OdataType   = 'microsoft.graph.security.ipEntityMapping'
            Identifiers = @{
                'Address' = 'addressColumn'
            }
        }
        'URL' = @{
            Collection  = 'urls'
            OdataType   = 'microsoft.graph.security.urlEntityMapping'
            Identifiers = @{
                'Url' = 'addressColumn'
            }
        }
        'File' = @{
            Collection  = 'files'
            OdataType   = 'microsoft.graph.security.fileEntityMapping'
            Identifiers = @{
                'Name'      = 'nameColumn'
                'Directory' = $null
            }
        }
        'FileHash' = @{
            Collection  = 'files'
            OdataType   = 'microsoft.graph.security.fileEntityMapping'
            # Sentinel models a hash as a separate entity with an Algorithm +
            # Value pair. Graph models the hash as columns ON the file entity,
            # one property per algorithm. The Algorithm identifier carries the
            # algorithm NAME column, not a hash, so it has no target; the Value
            # identifier needs the algorithm to pick sha1Column vs sha256Column,
            # which is resolved by the HashAlgorithmColumns map below.
            Identifiers = @{
                'Algorithm' = $null
                'Value'     = 'sha256Column'
            }
        }
        'Process' = @{
            Collection  = 'processes'
            OdataType   = 'microsoft.graph.security.processEntityMapping'
            # The Graph process entity carries hash columns only. Sentinel's
            # ProcessId / CommandLine have no target column and are dropped with
            # a diagnostic that names them (they are usually better carried as
            # customDetails).
            Identifiers = @{
                'ProcessId'   = $null
                'CommandLine' = $null
                'ElevationToken' = $null
            }
        }
        'Mailbox' = @{
            Collection  = 'mailboxes'
            OdataType   = 'microsoft.graph.security.mailboxEntityMapping'
            Identifiers = @{
                'MailboxPrimaryAddress' = 'primaryAddressColumn'
                'DisplayName'           = $null
                'Upn'                   = 'primaryAddressColumn'
            }
        }
        'MailMessage' = @{
            Collection  = 'mailMessages'
            OdataType   = 'microsoft.graph.security.mailMessageEntityMapping'
            Identifiers = @{
                'NetworkMessageId'  = 'networkMessageIdColumn'
                'Recipient'         = 'recipientColumn'
                'Subject'           = 'subjectColumn'
                'P1Sender'          = 'senderColumn'
                'P2Sender'          = 'senderColumn'
                'Sender'            = 'senderColumn'
                'SenderIP'          = $null
                'InternetMessageId' = $null
                'DeliveryAction'    = $null
                'DeliveryLocation'  = $null
            }
        }
        'RegistryKey' = @{
            Collection  = 'registryValues'
            OdataType   = 'microsoft.graph.security.registryValueEntityMapping'
            # Sentinel splits key and value across two entity types; Graph has a
            # single registryValue entity carrying both columns.
            Identifiers = @{
                'Key'  = 'keyColumn'
                'Hive' = $null
            }
        }
        'RegistryValue' = @{
            Collection  = 'registryValues'
            OdataType   = 'microsoft.graph.security.registryValueEntityMapping'
            Identifiers = @{
                'Name'      = 'valueNameColumn'
                'Value'     = $null
                'ValueType' = $null
            }
        }
        'AzureResource' = @{
            Collection  = 'azureResources'
            OdataType   = 'microsoft.graph.security.azureResourceEntityMapping'
            Identifiers = @{
                'ResourceId' = 'resourceIdColumn'
            }
        }
        'CloudApplication' = @{
            Collection  = 'cloudApplications'
            OdataType   = 'microsoft.graph.security.cloudApplicationEntityMapping'
            Identifiers = @{
                'AppId'        = 'appIdColumn'
                'Name'         = 'nameColumn'
                'InstanceName' = $null
            }
        }
        'DNS' = @{
            Collection  = 'dns'
            OdataType   = 'microsoft.graph.security.dnsEntityMapping'
            Identifiers = @{
                'DomainName' = 'domainNameColumn'
                'IpAddress'  = 'hostIpAddressColumn'
                'DnsServerIp' = 'serverIpColumn'
            }
        }
        'SecurityGroup' = @{
            Collection  = 'securityGroups'
            OdataType   = 'microsoft.graph.security.securityGroupEntityMapping'
            # PowerShell hashtable keys are case-insensitive, so Sentinel's 'SID'
            # spelling for this entity resolves through the same entry as 'Sid'.
            Identifiers = @{
                'DistinguishedName' = 'distinguishedNameColumn'
                'Sid'               = 'sidColumn'
                'ObjectGuid'        = 'objectIdColumn'
            }
        }
        'MailCluster' = @{
            Collection  = 'mailClusters'
            OdataType   = 'microsoft.graph.security.mailClusterEntityMapping'
            # No documented column roles line up with Sentinel's NetworkMessageIds
            # / Query / CountByDeliveryStatus identifiers. Entries resolve to
            # $null and are dropped with a diagnostic rather than guessed.
            Identifiers = @{
                'NetworkMessageIds'      = $null
                'CountByDeliveryStatus'  = $null
                'Query'                  = $null
            }
        }
        # ---------------------------------------------------------------------
        # Sentinel entity types with NO entityMappingConfiguration collection.
        # Collection = $null means: drop the whole entity + diagnose, naming the
        # type. Do not silently skip.
        # ---------------------------------------------------------------------
        'IoTDevice' = @{
            Collection  = $null
            OdataType   = ''
            Identifiers = @{}
        }
        'Malware' = @{
            Collection  = $null
            OdataType   = ''
            Identifiers = @{}
        }
        'SubmissionMail' = @{
            Collection  = $null
            OdataType   = ''
            Identifiers = @{}
        }
    }

    # -------------------------------------------------------------------------
    # FileHash resolution: Sentinel's FileHash entity pairs an Algorithm column
    # with a Value column. When the algorithm is a literal we can pick the right
    # Graph column; when it is a query column name we cannot know the value at
    # conversion time and default to SHA256 with a diagnostic.
    # -------------------------------------------------------------------------
    HashAlgorithmColumns = @{
        'SHA1'    = 'sha1Column'
        'SHA256'  = 'sha256Column'
        'MD5'     = $null      # no MD5 column on the Graph file entity
        'SHA512'  = $null
        'Default' = 'sha256Column'
    }

    # -------------------------------------------------------------------------
    # Graph entity collections that accept a file hash, used when routing a
    # FileHash entity. Documented here so the renderer does not hardcode it.
    # -------------------------------------------------------------------------
    HashCapableCollections = @('files', 'processes')

    # -------------------------------------------------------------------------
    # detectionAction.automatedActions - the response actions a custom detection
    # can run. Sentinel analytics rules have nothing to map FROM, so the
    # converter never fabricates these. Listed so the enrichment diagnostic and
    # the deploy-side validation can name them from data.
    # -------------------------------------------------------------------------
    AutomatedActionSets = @(
        @{ Name = 'isolateDevices';               Target = 'device'  }
        @{ Name = 'collectInvestigationPackages'; Target = 'device'  }
        @{ Name = 'runAntivirusScans';            Target = 'device'  }
        @{ Name = 'initiateInvestigations';       Target = 'device'  }
        @{ Name = 'restrictAppExecutions';        Target = 'device'  }
        @{ Name = 'allowFiles';                   Target = 'file'    }
        @{ Name = 'blockFiles';                   Target = 'file'    }
        @{ Name = 'stopAndQuarantineFiles';       Target = 'file'    }
        @{ Name = 'disableUsers';                 Target = 'account' }
        @{ Name = 'forceUserPasswordResets';      Target = 'account' }
        @{ Name = 'markUsersAsCompromised';       Target = 'account' }
        @{ Name = 'softDeleteEmails';             Target = 'email'   }
        @{ Name = 'hardDeleteEmails';             Target = 'email'   }
        @{ Name = 'moveEmailsToJunk';             Target = 'email'   }
        @{ Name = 'moveEmailsToInbox';            Target = 'email'   }
        @{ Name = 'moveEmailsToDeletedItems';     Target = 'email'   }
    )

    # -------------------------------------------------------------------------
    # Key order used when serializing the Graph object to YAML/JSON. Purely
    # cosmetic; it keeps generated files diff-friendly and readable.
    # -------------------------------------------------------------------------
    KeyOrder = @{
        DetectionRule = @('id', 'displayName', 'description', 'status', 'queryCondition', 'schedule', 'detectionAction')
        AlertTemplate = @('title', 'description', 'severity', 'recommendedActions', 'category', 'tactics', 'entityMappings', 'customDetails')
    }
}
