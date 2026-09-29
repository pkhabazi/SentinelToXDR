@{
    # -------------------------------------------------------------------------
    # How a conversion diagnostic translates into migration effort.
    #
    # The converter already records WHAT it did to every rule. This file decides
    # what that MEANS for the person doing the migration: is the rule ready to
    # deploy, does it need a decision first, or can it not be migrated at all.
    #
    # Impact levels:
    #   Blocking  The rule cannot become a custom detection. Nothing to deploy.
    #   High      It deploys, but it will not behave the way it did in Sentinel,
    #             and only a human can decide whether that is acceptable.
    #   Medium    It deploys and behaves the same, provided a prerequisite holds
    #             (usually: the Sentinel data is available in the Defender
    #             portal) or a value is confirmed.
    #   Low       Worth knowing, needs no action. Does not affect the verdict.
    #
    # Rules are matched IN ORDER, first match wins. A rule matches when every
    # field it specifies matches the diagnostic; omitted fields match anything.
    # Anything unmatched falls through to DefaultImpact.
    #
    # This is the file to edit when you disagree with a verdict. Nothing in the
    # scoring code knows any capability name.
    # -------------------------------------------------------------------------
    Metadata = @{
        SourceDoc   = 'Derived from the conversion diagnostics this module emits'
        PopulatedOn = '2026-08-11'
        Note        = 'Impact classification for migration readiness verdicts. Edit here, not in code.'
    }

    DefaultImpact = 'Low'

    # -------------------------------------------------------------------------
    # A dated fact about the ESTATE rather than about any one rule.
    #
    # Two of the undocumented API constraints - 'tactics or category' and
    # 'entityMappings or impactedAssets' - name a DEPRECATED property as the
    # acceptable alternative, and both alternatives are removed on 2026-10-01
    # (see DeprecatedProperties in GraphDetectionRule.psd1).
    #
    # So a rule that trips one of these can migrate today only by way of a
    # property that stops existing. This module never emits either form, so for
    # its output they are already hard requirements - but for anyone planning an
    # estate move the DATE is the point, and it belongs in front of them rather
    # than buried in a per-rule remedy. Over the public Azure-Sentinel corpus
    # this was 1,889 of 5,161 rules (36.6%) on 2026-09-16, measured by
    # tests/Integration/Measure-Corpus.ps1 (it was 2,173 / 42.1% while the two
    # tactics constraints were still on the list).
    #
    # AppliesToSummaries lists the findings that put a rule inside the window.
    # 'no sufficient identifier' is deliberately absent: a weak account
    # identifier is not something impactedAssets would have rescued.
    #
    # Report code reads this block generically and knows none of the strings.
    # Samples.Tests.ps1 checks every Summary here still exists in Rules.
    # -------------------------------------------------------------------------
    DeprecationWindow = @{
        Date    = '2026-10-01'
        Summary = 'Rules that can only migrate today by way of a property Microsoft removes on 2026-10-01'
        Detail  = 'The custom detection API requires entityMappings OR impactedAssets. impactedAssets is deprecated and removed on 2026-10-01, and this module never emits it. After that date a rule with no entity mappings cannot become a custom detection by any route until the source rule is edited. (Until 2026-09-15 the same was true of tactics OR category; the service no longer requires either.) Fixing these in Microsoft Sentinel before the date is cheaper than discovering it afterwards.'
        # Two views of the same three findings. The readiness report works from
        # CLASSIFIED findings, which carry a Summary; the conversion batch summary
        # works from raw diagnostics, which carry the constraint name as TargetValue.
        # Samples.Tests.ps1 checks the two lists stay the same length and that every
        # Summary here still exists in Rules.
        # The two tactics entries came out on 2026-09-15: the service no longer requires
        # tactics-or-category, so those rules are not waiting on a deprecated property any
        # more. entityMappings-or-impactedAssets is still enforced, so this window is now
        # about entity mappings alone - and 2026-10-01 is the date impactedAssets goes.
        AppliesToSummaries = @(
            'The service will refuse this: a custom detection needs an entity mapping'
        )
        AppliesToConstraints = @(
            'EntityMappingsMissing'
        )
    }

    Rules = @(
        # ---- Blocking -------------------------------------------------------
        @{
            Severity = 'Blocking'
            Impact   = 'Blocking'
            Summary  = 'Cannot be migrated'
            Remedy  = 'Nothing to change on this rule. Keep it running in Microsoft Sentinel, or use the Defender XDR capability that replaces it (incident correlation for Fusion, native alert ingestion for Microsoft security products, threat intelligence matching for TI rules). If the source file is a stub pointing elsewhere, assess the file it points to instead.'
        }

        # ---- High: structurally convertible, but the service refuses it -----
        # TacticsMissing and TechniqueMissing were here until 2026-09-15. They said a rule
        # with no MITRE data, or a tactic with no technique, would be refused - true when
        # measured on 2026-08-19, and not true any more. Between them they were grading
        # 1,216 corpus rules as certain rejections that the service now accepts. Deleted
        # rather than downgraded: with the requirement gone there is no conversion gap
        # left to report. The tactic is emitted, the techniques the source never had are
        # not invented, and nothing is lost. See TacticConstraints.History.
        # These three say something the other rules do not: the rule converts, it
        # validates against CustomDetection.schema.json, the query runs in
        # advanced hunting - and POST /security/rules/detectionRules answers 400.
        #
        # They are NOT Blocking. Nothing here is impossible and in every case one
        # added field on the SOURCE rule fixes it, which is why the remedy names
        # the field rather than telling the user to give up.
        #
        # Every one of them was found by deploying to a live tenant and reading
        # the error. None appears in the Graph reference or the product docs.
        # See docs/API-Constraints.md, and TacticConstraints /
        # RequiredAlertTemplateFields / EntityIdentifierRequirements in
        # GraphDetectionRule.psd1 for the constraint data itself.
        #
        # Matched on TargetValue because all five share one capability - the same
        # disambiguation the 'Sentinel analytics tier' pair below uses. They come
        # first in the High block: 'this will be refused' outranks 'this deploys
        # but behaves differently'.
        @{
            Capability  = 'Custom detection API requirements'
            TargetValue = 'EntityMappingsMissing'
            Impact      = 'High'
            Summary     = 'The service will refuse this: a custom detection needs an entity mapping'
            Remedy     = 'Add an entityMappings entry to the Sentinel rule whose identifiers map to a column the Defender entity supports. The only alternative the service accepts is the deprecated impactedAssets property, removed on 2026-10-01, so after that date this rule cannot be created at all until the source rule is edited.'
        }
        @{
            Capability  = 'Custom detection API requirements'
            TargetValue = 'AssetEntityMissing'
            Impact      = 'High'
            Summary     = 'The service will refuse this: no asset entity or IP is mapped'
            Remedy     = 'The API requires at least one asset entity (Host, Account or Mailbox) or an IP across the whole rule. File, URL, registry and cloud-application mappings attach to an alert but cannot carry one on their own. Map an identifying Host, Account, Mailbox or IP column on the Sentinel rule.'
        }
        @{
            Capability  = 'Custom detection API requirements'
            TargetValue = 'EntityIdentifierWeak'
            Impact      = 'High'
            Summary     = 'The service will refuse this entity mapping: no sufficient identifier'
            Remedy     = 'The API validates every entity mapping against a set of sufficient identifier combinations, and refuses one that carries only a weak identifier. An Account mapped on a name alone is the common case: map AccountSid, AccountUpn or AccountObjectId as well, and the mapping is accepted. The finding names the entity type and the columns that were emitted.'
        }

        # ---- High: behaviour materially differs -----------------------------
        @{
            Capability = 'Near-real-time (NRT) rules on Sentinel data'
            Action     = 'Constrained'
            Impact     = 'High'
            Summary    = 'Near-real-time downgraded to a scheduled run'
            Remedy    = 'To keep near-real-time behaviour, simplify the query until it satisfies the continuous-detection restrictions: one table, no join, union, externaldata or comments. Otherwise accept the shortest scheduled frequency and confirm the detection delay is acceptable for this use case.'
        }
        @{
            Capability = 'Flexible entity mapping over Sentinel data'
            Action     = 'Unsupported'
            Impact     = 'High'
            Summary    = 'An entity is missing from the alert: the type has no equivalent in Defender XDR'
            Remedy    = 'Map the identifying columns onto an entity type Defender XDR does support, or carry them as custom detail columns so the values still reach the alert. Investigation experiences that relied on the original entity type will need adjusting.'
        }
        @{
            Capability = 'Choose between all events under one alert and one alert per event'
            Impact     = 'High'
            Summary    = 'Trigger threshold dropped: the detection fires on every result row'
            Remedy    = 'Move the threshold into the query. A Sentinel ''trigger when results > N'' becomes a summarize plus a where in KQL, for example: | summarize Count = count() by <grouping column> | where Count > N. Without that the detection alerts on every row.'
        }
        @{
            Capability = 'Customize alert grouping logic'
            Impact     = 'High'
            Summary    = 'Event grouping dropped: the correlation engine decides grouping'
            Remedy    = 'Decide grouping in the query rather than in rule configuration: summarize to one row per entity you want one alert for. Defender XDR then groups alerts into incidents through its own correlation engine, which you cannot configure per rule.'
        }
        @{
            Capability = 'Alerts suppression - Define alert suppression after the rule runs'
            Impact     = 'High'
            Summary    = 'Alert suppression window dropped'
            Remedy    = 'There is no per-rule suppression in a custom detection. Reduce noise inside the query instead - summarize over the window you were suppressing, or exclude the repeat condition - and rely on Defender XDR incident correlation to collapse related alerts.'
        }
        @{
            Capability = 'Create alerts without incidents'
            Impact     = 'High'
            Summary    = 'Alerts will now create incidents'
            Remedy    = 'A custom detection always creates an incident. If this rule existed only to enrich or feed automation without alerting, consider not migrating it, or expect the extra incident volume and tune the query to fire less often.'
        }
        @{
            Capability = 'Support flexible and high frequency for Sentinel data'
            Action     = 'Rounded'
            Impact     = 'High'
            Summary    = 'Run frequency changed to fit a supported value'
            Remedy    = 'Confirm the new frequency is acceptable for the detection''s purpose. If the original cadence matters, check whether the rule reads Defender tables it does not need - a query on Sentinel data only can keep a custom frequency.'
        }
        @{
            Capability = 'Support flexible and high frequency for Sentinel data'
            Action     = 'Constrained'
            Impact     = 'High'
            Summary    = 'Run frequency constrained'
            Remedy    = 'Confirm the constrained cadence still detects what this rule was written to detect, and widen the query window if the longer gap could miss activity.'
        }
        @{
            Capability = 'Define all alerts properties dynamically - Integrate query results in runtime'
            Impact     = 'High'
            Summary    = 'Dynamic alert properties (severity/tactics from the query) not migrated'
            Remedy    = 'Severity and tactics become fixed values on the detection. Either accept one fixed value, or split the rule into one detection per severity or tactic with the query filtered accordingly.'
        }
        @{
            Capability = 'Link multiple MITRE tactics'
            Action     = 'Dropped'
            Severity   = 'Warning'
            Impact     = 'High'
            Summary    = 'A MITRE tactic could not be carried'
            Remedy    = 'A MITRE tactic on this rule has no Defender XDR equivalent, or could not be carried into the shape being emitted; the finding names it. If the ATT&CK coverage matters to your reporting, split the rule into one detection per tactic with the query filtered accordingly. On the legacy -Format XDRConverter shape you can also pick the tactic that best represents the detection with -AlertCategory.'
        }
        @{
            # A bare _Name() call is the Sentinel convention for a workspace-saved function.
            # This was Medium ('confirm it resolves') on the argument that the pattern can
            # also match an ordinary name. The API settled it: on 2026-09-16 a round trip
            # POSTed Samples/22 and the service refused it with 'Unknown function:
            # _MyOrgDeviceBaseline' (docs/API-Constraints.md). A saved function is a
            # workspace-only dependency like any other, so it is graded like one. The
            # remedy stays specific to functions; TargetValue keeps it ahead of the
            # generic workspace-dependency row below.
            Feature     = 'Rule query'
            Severity    = 'Warning'
            TargetValue = 'SavedFunction'
            Impact      = 'High'
            Summary     = 'The query calls a workspace-saved function, which does not exist in Defender XDR'
            Remedy     = 'Saved functions live in the Log Analytics workspace and advanced hunting has no equivalent, so the custom detection API refuses the query at creation. Inline the function body into the query, or recreate it as a function in advanced hunting, before deploying. Test-XDRDetectionQuery confirms it in one call.'
        }
        @{
            # The query reaches something that exists only in the Log Analytics workspace —
            # a watchlist, an ASIM parser, another workspace, an externaldata URI. The rule
            # converts perfectly and the detection then fails on its first run. That is not
            # 'behaves the same provided a prerequisite holds'; it is the definition of
            # NeedsWork, and grading it any lower is how a false green happens.
            Feature  = 'Rule query'
            Severity = 'Warning'
            Impact   = 'High'
            Summary  = 'The query depends on something that does not exist in Defender XDR and will not run'
            Remedy  = 'Remove the workspace-only dependency before deploying: inline a watchlist as a datatable, rewrite an ASIM parser against the underlying Defender tables, materialise an externaldata list into the query, and scope any cross-workspace reference to local tables. Confirm with Test-XDRDetectionQuery.'
        }

        # ---- Medium: prerequisite, or confirm a value -----------------------
        @{
            # The API accepts exactly ONE tactic per detection - undocumented, found
            # by deployment (see docs/API-Constraints.md). The rule still deploys and
            # still detects the same activity, so this is not High: what is lost is
            # ATT&CK breadth on the alert, not behaviour.
            Capability  = 'Custom detection API requirements'
            TargetValue = 'TacticsTruncated'
            Impact      = 'Medium'
            Summary     = 'Only one MITRE tactic is carried'
            Remedy     = 'The custom detection API accepts exactly one tactic, so the remaining tactics on this rule were dropped. The finding names the one kept and the ones lost. Techniques that belonged to the dropped tactics may not survive either: on 2026-09-16 a round trip read one back missing and a probe read the same shape back intact, so check the stored rule. If the full ATT&CK coverage matters to your reporting, split the rule into one detection per tactic with the query filtered accordingly.'
        }
        @{
            # The mixed-tier trap, and the reason it needs its own row: a query that touches
            # even one Defender table forfeits custom frequency for the WHOLE rule, so this
            # is a fact about this rule's schedule, not a tenant prerequisite. Impact stays
            # Medium — if the rule's frequency already fits a supported value it costs
            # nothing, and the frequency diagnostic grades that case High on its own.
            Capability  = 'Sentinel analytics tier'
            TargetValue = 'Mixed'
            Impact      = 'Medium'
            Summary     = 'Mixed Defender and Sentinel data in one rule: custom run frequency is forfeited for the whole rule'
            Remedy     = 'If the original cadence matters, split the rule: keep the Sentinel-data part as its own detection so it can keep a custom frequency, and move the Defender-table part into a separate detection.'
        }
        @{
            # True of every Sentinel-tier rule in the estate at once. Checked once, for the
            # tenant, not per rule — so it is reported once rather than on every row.
            Capability  = 'Sentinel analytics tier'
            Impact      = 'Medium'
            EstateLevel = $true
            Summary     = 'Needs Microsoft Sentinel data available in the Defender portal'
            Remedy     = 'One tenant-level check, not per-rule work: confirm Microsoft Sentinel is connected to the Defender portal and the relevant tables are available in advanced hunting. Once that holds, these rules need no further change.'
        }
        @{
            Capability = 'Lookback support'
            Action     = 'Constrained'
            Impact     = 'Medium'
            Summary    = 'Lookback window shortened'
            Remedy    = 'Defender XDR fixes the lookback per frequency and it cannot be set per rule. Either accept the shorter window, or choose a lower frequency to get a longer fixed lookback, and confirm the detection still has enough history to fire.'
        }
        @{
            # The entity still attaches to the alert, but with fewer columns: the Graph
            # entity types carry a fixed set of column roles and some Sentinel identifiers
            # have no home (a process command line, a file directory, a registry value).
            # The data is still in the query output and can be carried as a custom detail,
            # so this is worth knowing, not a redesign.
            Capability = 'Flexible entity mapping over Sentinel data'
            Action     = 'Dropped'
            Severity   = 'Warning'
            Impact     = 'Medium'
            Summary    = 'Some entity columns could not be mapped'
            Remedy    = 'The entity still attaches, with fewer columns. Add the dropped columns as custom details so the values remain in the alert for the analyst, or rename them in the query to a column role the Graph entity does support.'
        }
        @{
            Capability = 'Enrich alerts with custom details'
            Action     = 'RequiresReview'
            Impact     = 'Medium'
            Summary    = 'Custom details not migrated'
            Remedy    = 'Re-add the values as custom detail columns on the custom detection, or make sure the query projects them so they are visible in the alert.'
        }
        @{
            # customDetails that is not a name-to-column map: a bare string, a list. The
            # converter used to enumerate the string's own properties and emit {Length: 10}
            # as a custom detail on a Ready rule (2026-09-16). Now it drops the block and
            # says so.
            Capability = 'Enrich alerts with custom details'
            Action     = 'Dropped'
            Impact     = 'Medium'
            Summary    = 'Custom details block is malformed and was not carried'
            Remedy    = 'customDetails must map a detail name to a query column, e.g. { CommandLine: ProcessCommandLine }. Rewrite it as a map on the Sentinel rule; nothing from the malformed block reached the detection.'
        }
        # ---- Input integrity: things about the SOURCE that a deploy would trip over ----
        # Matched on TargetValue, ahead of the generic 'Manage rules from API' row below,
        # which would otherwise claim them (first match wins, omitted fields match anything).
        @{
            Capability  = 'Manage rules from API'
            TargetValue = 'DuplicateId'
            Impact      = 'Medium'
            Summary     = 'Another rule in this batch has the same id'
            Remedy     = 'Two source rules share one id, so deploying both would create one detection and fail the other with a conflict. Give each rule its own GUID in the source, or pass -Guid for one of them.'
        }
        @{
            Capability  = 'Manage rules from API'
            TargetValue = 'DisplayNameSanitised'
            Impact      = 'Medium'
            Summary     = 'The display name contained control or bidirectional-override characters, which were removed'
            Remedy     = 'The Sentinel rule name carried characters that do not print (control codes) or that reorder text on screen (Unicode bidirectional overrides). They were stripped from the detection name; check the name still reads as intended and fix it in the source.'
        }
        @{
            Capability  = 'Manage rules from API'
            TargetValue = 'DisplayNameMissing'
            Impact      = 'Medium'
            Summary     = 'The rule has no display name; the detection was named after its id'
            Remedy     = 'displayName is mandatory on a custom detection, so the converter named it "Unnamed rule <id>". Give the Sentinel rule a real name and convert again.'
        }
        @{
            Capability = 'Manage rules from API'
            Action     = 'RequiresReview'
            Impact     = 'Medium'
            Summary    = 'No rule id in the source: a new one was generated'
            Remedy    = 'If this rule already exists in the tenant, pass its existing id with -Guid so a redeploy updates it instead of creating a duplicate. Record the generated id if you intend to keep it.'
        }
        @{
            Capability = 'Sentinel automation rules with incident trigger'
            Impact     = 'Medium'
            Summary    = 'Downstream automation or playbooks may depend on this rule'
            Remedy    = 'Check what is bound to this rule in Sentinel - automation rules, playbooks, incident triggers - and rebuild the equivalent in Defender XDR before you retire the Sentinel rule, otherwise the response stops silently.'
        }

        # ---- Low: informational, no action ----------------------------------
        # These fire on almost every rule and say nothing about that rule in
        # particular, so they must not drive a verdict.
        @{
            Capability = 'Reflect custom detections in MITRE ATT&CK page'
            Impact     = 'Low'
            Summary    = 'ATT&CK coverage page does not yet show custom detections'
            Remedy    = 'Nothing to change on the rule. Track ATT&CK coverage outside the portal page until Microsoft ships this.'
        }
        @{
            Capability = 'Support full list of MITRE techniques and subtechniques'
            Impact     = 'Low'
            Summary    = 'Confirm the technique ids are accepted'
            Remedy    = 'Check the emitted technique ids against what the custom detection API accepts, and drop any it rejects.'
        }
        @{
            Action  = 'Mapped'
            Impact  = 'Low'
            Summary = 'Mapped'
        }
    )

    # -------------------------------------------------------------------------
    # Verdicts, worst first. A rule takes the first verdict whose trigger impact
    # is present in its findings.
    # -------------------------------------------------------------------------
    Verdicts = @(
        @{
            Name        = 'Blocked'
            Trigger     = 'Blocking'
            Description = 'Cannot become a custom detection. Nothing to deploy.'
        }
        @{
            Name        = 'NeedsWork'
            Trigger     = 'High'
            Description = 'Converts, but the detection will not behave the way it did in Sentinel. Decide whether that is acceptable before deploying.'
        }
        @{
            Name        = 'Review'
            Trigger     = 'Medium'
            Description = 'Converts and behaves the same, provided the prerequisites hold. Check them once, they usually apply to the whole estate.'
        }
        @{
            Name        = 'Ready'
            Trigger     = ''
            Description = 'Converts cleanly. Deploy it.'
        }
    )

    # -------------------------------------------------------------------------
    # Score is a rough 0-100 readability aid, not a measurement. It exists so a
    # long list can be sorted by how much work it represents.
    # -------------------------------------------------------------------------
    ScoreWeights = @{
        Start    = 100
        Blocking = 100
        High     = 15
        Medium   = 5
        Low      = 0
    }
}
