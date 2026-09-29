@{
    # -------------------------------------------------------------------------
    # Microsoft Sentinel analytics rule KINDS and whether each one can become a
    # Defender XDR custom detection at all.
    #
    # Only query-backed rules (Scheduled, NRT) have a KQL query and a schedule,
    # which is everything the custom-detection model is built from. The rest are
    # service-side detections: they have no query to carry, so there is nothing
    # to convert. Before this file existed the converter emitted a valid-looking
    # detection with an empty queryText for them, which is worse than refusing.
    #
    # Source: Microsoft.SecurityInsights/alertRules 'kind' discriminator
    #   https://learn.microsoft.com/rest/api/securityinsights/alert-rules
    # -------------------------------------------------------------------------
    Metadata = @{
        SourceDoc   = 'Microsoft.SecurityInsights alertRules resource - kind discriminator'
        SourceUrl   = 'https://learn.microsoft.com/rest/api/securityinsights/alert-rules'
        FetchedDate = '2026-08-11'
        Note        = 'Convertible = the rule carries a KQL query + schedule. Everything else is a Blocking verdict, never a silent empty conversion.'
    }

    # Kind used when a source file carries no explicit kind. Community YAML rules
    # in the Azure-Sentinel repo frequently omit it; they are scheduled rules.
    DefaultKind = 'Scheduled'

    Kinds = @(
        @{
            Kind        = 'Scheduled'
            Convertible = $true
            Reason      = 'Query-backed scheduled rule. Maps to a scheduled custom detection.'
        }
        @{
            Kind        = 'NRT'
            Convertible = $true
            Reason      = 'Query-backed near-real-time rule. Maps to a continuous custom detection when the query satisfies the continuous-query restrictions, otherwise it is downgraded to the shortest scheduled frequency.'
        }
        @{
            Kind        = 'Fusion'
            Convertible = $false
            Reason      = 'Fusion is a Microsoft-managed multistage attack correlation engine. It has no KQL query and no schedule, so there is nothing to convert. Defender XDR performs equivalent correlation natively through the incident correlation engine.'
        }
        @{
            Kind        = 'MLBehaviorAnalytics'
            Convertible = $false
            Reason      = 'Machine-learning behaviour analytics rules run Microsoft-managed models. They carry no query and cannot be expressed as a custom detection.'
        }
        @{
            Kind        = 'MicrosoftSecurityIncidentCreation'
            Convertible = $false
            Reason      = 'This rule kind only forwards alerts from another Microsoft security product into Sentinel incidents. In the Defender portal those alerts arrive natively, so the rule has no migration target.'
        }
        @{
            Kind        = 'ThreatIntelligence'
            Convertible = $false
            Reason      = 'Threat-intelligence matching rules are Microsoft-managed and match indicators server side. They carry no query. Use Defender XDR threat intelligence / IoC matching instead.'
        }
        @{
            Kind        = 'Anomaly'
            Convertible = $false
            Reason      = 'Anomaly rules are customizable Microsoft-managed models with tunable thresholds rather than a portable KQL query.'
        }
        @{
            Kind        = 'HuntingQuery'
            Convertible = $false
            Reason      = 'This is a hunting query, not an analytics rule. It carries a KQL query but no schedule, severity or entity mappings, so converting it would mean inventing the detection behaviour rather than migrating it. Hunting queries can become custom detections, but that is an authoring decision: promote the query to a scheduled analytics rule first, then convert it.'
        }
    )

    # -------------------------------------------------------------------------
    # Placeholder files: a rule that is not a rule.
    #
    # Content repositories leave redirect stubs behind when a rule moves. They
    # keep an id, a name and a kind, but carry no query and no rule content —
    # only a description saying where the real rule went. They are not analytics
    # rules that failed to convert; they are signposts, and counting them as
    # Blocked overstates how much of an estate cannot migrate. The Azure-Sentinel
    # repository contains 312 of them.
    #
    # Matched only when the candidate has NO query, so a real rule that happens
    # to mention a migration in its description is never discarded.
    # -------------------------------------------------------------------------
    PlaceholderMarkers = @(
        'As part of content migration, this file is moved'
        'this file is moved to a new location'
        'This rule has been deprecated and moved'
    )

    # -------------------------------------------------------------------------
    # Verdict emitted for a non-convertible kind. Blocking is the highest
    # diagnostic severity: the rule produces NO output object at all.
    # -------------------------------------------------------------------------
    NonConvertible = @{
        Severity = 'Blocking'
        Action   = 'Unsupported'
        Feature  = 'Rules management'
        Capability = 'Manage rules from API'
    }
}
