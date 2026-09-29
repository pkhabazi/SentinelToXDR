@{
    # -------------------------------------------------------------------------
    # What each sample is supposed to demonstrate.
    #
    # This file is not documentation, it is a test fixture: Samples.Tests.ps1
    # asserts that every sample still produces the verdict and findings claimed
    # here. That keeps the folder honest — a change in the converter that
    # silently reclassifies a sample fails the build instead of quietly making
    # the demo wrong.
    #
    # If a change here is deliberate, update the entry AND the comment header in
    # the sample file itself.
    # -------------------------------------------------------------------------
    Metadata = @{
        Purpose = 'One Sentinel analytics rule per migration use case, used by the demo, the tests and the round-trip validation.'
        Note    = 'Every id starts 5a1e (a weak pun on "Sample") so they are obvious in a tenant.'
    }

    Samples = @(
        @{
            File            = '01-ready-defender-only.yaml'
            UseCase         = 'The clean migration: native Defender tables, one tactic, entities that map fully.'
            ExpectedVerdict = 'Ready'
            ExpectedTier    = 'DefenderOnly'
        }
        @{
            File            = '02-review-multi-tactic.yaml'
            UseCase         = 'Three MITRE tactics, one carried. The Graph model holds a collection and the service accepts exactly one entry in it, which is not in any document - it was found by deploying. Renamed from 02-ready- when that turned out to be a Review, not a Ready.'
            ExpectedVerdict = 'Review'
            ExpectedTier    = 'DefenderOnly'
            ExpectedTacticCount = 1
            MustContain     = 'Only one MITRE tactic is carried'
        }
        @{
            File            = '03-review-sentinel-tier.yaml'
            UseCase         = 'Sentinel-tier data: works as before, once the data is in the Defender portal.'
            ExpectedVerdict = 'Review'
            ExpectedTier    = 'SentinelOnly'
            MustContain     = 'Needs Microsoft Sentinel data available in the Defender portal'
        }
        @{
            File            = '04-needswork-mixed-tier-frequency.yaml'
            UseCase         = 'The mixed-tier trap: one Defender table forfeits custom frequency for the whole rule.'
            ExpectedVerdict = 'NeedsWork'
            ExpectedTier    = 'Mixed'
            MustContain     = 'Run frequency changed to fit a supported value'
            ExpectedFrequency = 'PT1H'
        }
        @{
            File            = '05-needswork-nrt-downgrade.yaml'
            UseCase         = 'A near-real-time rule that joins, so it cannot stay continuous.'
            ExpectedVerdict = 'NeedsWork'
            MustContain     = 'Near-real-time downgraded to a scheduled run'
        }
        @{
            File            = '06-needswork-behaviour-dropped.yaml'
            UseCase         = 'Trigger threshold, suppression, event grouping and alerts-without-incidents all dropped.'
            ExpectedVerdict = 'NeedsWork'
            MustContain     = 'Trigger threshold dropped: the detection fires on every result row'
        }
        @{
            File            = '07-needswork-entity-no-equivalent.yaml'
            UseCase         = 'An entity type Defender XDR has no home for; the entity beside it still maps.'
            ExpectedVerdict = 'NeedsWork'
            MustContain     = @('An entity is missing from the alert: the type has no equivalent in Defender XDR', 'The service will refuse this: no asset entity or IP is mapped')
        }
        @{
            File            = '08-review-entity-columns-dropped.yaml'
            UseCase         = 'Partial entity loss: the entity attaches, some columns have no target role.'
            ExpectedVerdict = 'Review'
            MustContain     = 'Some entity columns could not be mapped'
        }
        @{
            File            = '09-review-lookback-shortened.yaml'
            UseCase         = 'A 14 day lookback meeting the fixed four hour window of an hourly Defender-tier rule.'
            ExpectedVerdict = 'Review'
            MustContain     = 'Lookback window shortened'
        }
        @{
            File            = '10-review-enrichment.yaml'
            UseCase         = 'Custom details and a dynamic title carry; dynamic severity and tactics do not.'
            ExpectedVerdict = 'NeedsWork'
            MustContain     = 'Dynamic alert properties (severity/tactics from the query) not migrated'
        }
        @{
            File            = '11-blocked-fusion.json'
            UseCase         = 'A Microsoft-managed rule kind with no query. Nothing to convert.'
            ExpectedVerdict = 'Blocked'
        }
        @{
            File            = '12-blocked-no-query.yaml'
            UseCase         = 'A scheduled rule with no query.'
            ExpectedVerdict = 'Blocked'
        }
        @{
            File            = '13-review-arm-template.json'
            UseCase         = 'Content Hub shape: rule nested in a content template, GUID inside a [concat()] expression.'
            ExpectedVerdict = 'Review'
            ExpectedId      = '5a1e0013-0000-4000-8000-000000000013'
        }
        @{
            File            = '14-review-timespan-pascalcase.json'
            UseCase         = 'PascalCase members and serialized TimeSpan objects instead of ISO 8601. Also carries no id, so one is generated.'
            ExpectedVerdict = 'Review'
            ExpectedFrequency = 'PT6H'
            # This shape ships no id at all, so the converter generates one and says so.
            # That is the correct behaviour and part of what the sample demonstrates, so it
            # is exempt from the 5a1e naming convention the other samples follow.
            GeneratesId     = $true
            MustContain     = 'No rule id in the source: a new one was generated'
        }
        @{
            File            = '15-blindspot-watchlist.yaml'
            UseCase         = 'A watchlist dependency: the rule converts perfectly and the query cannot run. Was a false green until the query-dependency scan; now caught offline, and Test-XDRDetectionQuery still proves it against a tenant.'
            ExpectedVerdict = 'NeedsWork'
            MustContain     = 'The query depends on something that does not exist in Defender XDR and will not run'
        }
        @{
            File            = '16-multi-rule-file.yaml'
            UseCase         = 'Two rules in one file. A one-rule-per-file reader drops the second.'
            ExpectedVerdict = 'Ready'
            ExpectedRuleCount = 2
        }
        @{
            File            = '18-needswork-watchlist-dependency.yaml'
            UseCase         = 'The false green: every structural check passes and the query cannot run, because a watchlist does not exist in advanced hunting.'
            ExpectedVerdict = 'NeedsWork'
            ExpectedTier    = 'DefenderOnly'
            MustContain     = 'The query depends on something that does not exist in Defender XDR and will not run'
        }
        @{
            File            = '19-needswork-asim-parser.yaml'
            UseCase         = 'An ASIM parser is a workspace function, not a table. Converts perfectly, fails on first run.'
            ExpectedVerdict = 'NeedsWork'
            MustContain     = 'The query depends on something that does not exist in Defender XDR and will not run'
        }
        @{
            File            = '20-needswork-externaldata.yaml'
            UseCase         = 'externaldata pulls a list from a URI at query time; custom detections do not support it.'
            ExpectedVerdict = 'NeedsWork'
            MustContain     = 'The query depends on something that does not exist in Defender XDR and will not run'
        }
        @{
            File            = '21-needswork-cross-workspace.yaml'
            UseCase         = 'The workspace() operator reaches a second workspace. A custom detection only sees its own tenant.'
            ExpectedVerdict = 'NeedsWork'
            MustContain     = 'The query depends on something that does not exist in Defender XDR and will not run'
        }
        @{
            File            = '22-needswork-saved-function.yaml'
            UseCase         = 'A workspace-saved function. Graded NeedsWork with the other workspace-only dependencies: the API refused this query at POST with an unknown-function error, so it has to be inlined before the rule deploys.'
            ExpectedVerdict = 'NeedsWork'
            MustContain     = 'The query calls a workspace-saved function, which does not exist in Defender XDR'
        }
        @{
            File            = '23-ready-custom-details.yaml'
            UseCase         = 'Custom details are supported and must survive the trip. Community YAML parses into a Hashtable, and reading it as a PSCustomObject deployed one garbage key instead of two real ones - 863 rules in Azure-Sentinel use custom details.'
            ExpectedVerdict = 'Ready'
            ExpectedTier    = 'DefenderOnly'
            ExpectedCustomDetails = @{ CommandLine = 'ProcessCommandLine'; Initiator = 'InitiatingProcessFileName' }
        }
        @{
            File            = '24-notarule-placeholder.yaml'
            UseCase         = 'A redirect stub left behind when a rule moved. Not a detection that failed to migrate - not a detection at all. Azure-Sentinel has 312.'
            ExpectedRuleCount = 0
        }
        @{
            File            = '25-review-comment-apostrophe.yaml'
            UseCase         = "An apostrophe in a KQL comment used to open a phantom string that blanked the rest of the query, hiding tables and dependencies and silently changing the data tier of 22 corpus rules."
            ExpectedVerdict = 'Review'
            ExpectedTier    = 'SentinelOnly'
        }
        @{
            File            = '26-ready-awkward-name.yaml'
            UseCase         = 'A display name with a slash and a bracketed prefix. Both used to be discarded as ARM artefacts, leaving 94 unnamed rows in a corpus report.'
            ExpectedVerdict = 'Ready'
            ExpectedDisplayName = '[Entra ID] Devices flapping online/offline'
        }
        @{
            File            = '27-needswork-zero-frequency.yaml'
            UseCase         = 'A malformed rule: zero frequency on a scheduled rule. Zero means continuous in Defender XDR, so passing it through would silently turn a broken rule into a continuous detection.'
            ExpectedVerdict = 'NeedsWork'
            MustContain     = 'Run frequency constrained'
        }
        # ---- The five undocumented API constraints -------------------------
        # Every one of these converts cleanly, validates against
        # CustomDetection.schema.json and runs in advanced hunting, and is then
        # refused on deployment. They exist so that Samples.Tests.ps1 keeps a
        # rule triggering each classification, and so the round-trip validation
        # has something to prove the verdicts against a live tenant.
        # See docs/API-Constraints.md.
        @{
            # Both of these were NeedsWork until 2026-09-15, on requirements the service has
            # since dropped. They are kept, and inverted, because a sample that proves the
            # module does NOT invent a rejection is worth as much as one that proves it
            # reports a real one.
            File                = '28-ready-tactic-without-technique.yaml'
            UseCase             = 'A tactic with no technique is accepted and stored with an empty techniques collection; the tactic must be carried, not dropped.'
            ExpectedVerdict     = 'Ready'
            ExpectedTacticCount = 1
        }
        @{
            File            = '29-ready-no-mitre-data.yaml'
            UseCase         = 'No tactics and no category is accepted; a rule with no ATT&CK context still converts and deploys.'
            ExpectedVerdict = 'Ready'
        }
        @{
            File            = '30-needswork-no-entity-mappings.yaml'
            UseCase         = 'Constraint 4: entityMappings or impactedAssets is mandatory, and impactedAssets is removed on 2026-10-01.'
            ExpectedVerdict = 'NeedsWork'
            MustContain     = 'The service will refuse this: a custom detection needs an entity mapping'
        }
        @{
            File            = '31-needswork-weak-account-identifier.yaml'
            UseCase         = 'Constraint 5, the widest blast radius: an Account mapped on a name alone is refused, while a Host on a name alone is accepted.'
            ExpectedVerdict = 'NeedsWork'
            MustContain     = 'The service will refuse this entity mapping: no sufficient identifier'
        }
        # ---- Input the converter had not seen: found by the 2026-09-16 stress test ----
        @{
            File            = '32-needswork-arm-threshold-parameter.json'
            UseCase         = 'A triggerThreshold that is an ARM parameter with no default, inside a nested Microsoft.Resources/deployments template. The rule used to vanish on an [int] cast after a warning that said everything else converts normally.'
            ExpectedVerdict = 'NeedsWork'
            ExpectedId      = '5a1e0032-0000-4000-8000-000000000032'
            MustContain     = 'Trigger threshold dropped: the detection fires on every result row'
        }
        @{
            File            = '33-review-custom-details-malformed.yaml'
            UseCase         = 'customDetails as a bare string. The converter used to emit {Length: 18} as a custom detail on a Ready rule.'
            ExpectedVerdict = 'Review'
            MustContain     = 'Custom details block is malformed and was not carried'
            ExpectedCustomDetails = @{}
        }
        @{
            File            = '34-review-hostile-display-name.yaml'
            UseCase         = 'A display name with a bidirectional override, tabs, a newline, a leading = and an HTML tag. Controls and overrides are stripped and reported; the rest is neutralised per report format.'
            ExpectedVerdict = 'Review'
            MustContain     = 'The display name contained control or bidirectional-override characters, which were removed'
            ExpectedDisplayName = '=Sample <b>reversed</b> name with tabs and a newline'
        }
        @{
            File            = '35-review-duplicate-id-first.yaml'
            UseCase         = 'First of two rules sharing one id. Clean on its own.'
            ExpectedVerdict = 'Ready'
        }
        @{
            File            = '35-review-duplicate-id-second.yaml'
            UseCase         = 'Second rule with the same id as 35-first. Deploying both would create one detection and a 409.'
            ExpectedVerdict = 'Review'
            MustContain     = 'Another rule in this batch has the same id'
        }
        @{
            File            = '36-review-no-display-name.yaml'
            UseCase         = 'A rule with an empty name. displayName is mandatory, so the detection is named after its id and the finding says so; it used to go out nameless with no finding.'
            ExpectedVerdict = 'Review'
            MustContain     = 'The rule has no display name; the detection was named after its id'
        }
        @{
            File            = '17-not-a-rule.json'
            UseCase         = 'A workbook. Not a rule, and must not be reported as one.'
            ExpectedRuleCount = 0
        }
    )
}
