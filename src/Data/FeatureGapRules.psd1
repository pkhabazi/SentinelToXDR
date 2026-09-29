@{
    # -------------------------------------------------------------------------
    # Remaining feature-gap rules (Stage 5 of the Edge-Case plan).
    #
    # This file is the DATA SOURCE that maps each remaining Sentinel source
    # feature that the converter previously DROPPED SILENTLY to the compare-doc
    # capability row that governs it. The converter reads the live STATE for each
    # row at runtime via Get-CustomDetectionCapabilities (single source of truth
    # for States) and decides map / drop / diagnose accordingly. A Microsoft
    # parity flip (e.g. Planned -> Supported, or NotSupported -> Supported) is a
    # pure DATA edit here + in CustomDetectionCapabilities.psd1 — no code change.
    #
    # The string pairs below MUST match the rows in
    # CustomDetectionCapabilities.psd1 EXACTLY (a guard test asserts this).
    #
    # Source of truth (compare doc):
    #   "Feature comparison- Microsoft Sentinel analytics rules and Microsoft
    #    Defender custom detections.md"
    # -------------------------------------------------------------------------
    Metadata = @{
        SourceDoc    = 'Feature comparison- Microsoft Sentinel analytics rules and Microsoft Defender custom detections.md'
        GitCommitId  = '5c6b247409b0a426e2a24485684a6bcd0a14cf05'
        MsDate       = '2026-05-19'
        DocReference = 'Stage 5 — Remaining feature gaps (matrix-driven drop + diagnose)'
        Note         = 'Each Sentinel source feature -> the compare-doc capability row gating it. States are read from CustomDetectionCapabilities.psd1 at runtime so a parity flip is a data edit.'
    }

    Capabilities = @{
        # A. alertDetailsOverride: dynamic title/description IS supported.
        DynamicTitleDescription = @{
            Feature    = 'Alert enrichment'
            Capability = 'Define alert title and description dynamically - Integrate query results in runtime'
        }
        # A. alertDetailsOverride: the OTHER sub-properties (dynamic severity,
        #    tactics column, alertDynamicProperties) fall under "all properties
        #    dynamic" which is Planned.
        DynamicAllProperties = @{
            Feature    = 'Alert enrichment'
            Capability = 'Define all alerts properties dynamically - Integrate query results in runtime'
        }
        # B. customDetails: enriching alerts with custom details IS supported.
        CustomDetails = @{
            Feature    = 'Alert enrichment'
            Capability = 'Enrich alerts with custom details'
        }
        # B. (related) grouping events when custom details / dynamic details /
        #    entities are identical — Supported; surfaced informationally.
        GroupOnIdentical = @{
            Feature    = 'Control alerts and events grouping'
            Capability = 'Group events to one alert when custom details, alert dynamic details, and entities are identical'
        }
        # C. eventGroupingSettings: customizing alert grouping logic — NotSupported.
        CustomizeGrouping = @{
            Feature    = 'Control alerts and events grouping'
            Capability = 'Customize alert grouping logic'
        }
        # C. eventGroupingSettings.aggregationKind (one-alert vs one-per-event) — NotSupported.
        EventsPerAlert = @{
            Feature    = 'Control alerts and events grouping'
            Capability = 'Choose between all events under one alert and one alert per event'
        }
        # D. incidentConfiguration.createIncident=false: alerts without incidents — NotSupported.
        AlertsWithoutIncidents = @{
            Feature    = 'Control incidents and alerts creation'
            Capability = 'Create alerts without incidents'
        }
        # E. suppression: define alert suppression after the rule runs — NotSupported.
        AlertSuppression = @{
            Feature    = 'Control incidents and alerts creation'
            Capability = 'Alerts suppression - Define alert suppression after the rule runs'
        }
        # F. native XDR remediation actions — Supported (enrichment opportunity).
        NativeRemediationActions = @{
            Feature    = 'Automated actions'
            Capability = 'Native Defender XDR remediation actions'
        }
        # G. Sentinel automation rules (incident / alert trigger) — Planned.
        AutomationIncidentTrigger = @{
            Feature    = 'Automated actions'
            Capability = 'Sentinel automation rules with incident trigger'
        }
        AutomationAlertTrigger = @{
            Feature    = 'Automated actions'
            Capability = 'Sentinel automation rules with alert trigger'
        }
    }

    # -------------------------------------------------------------------------
    # The native XDR remediation actionType enum (CustomDetection.schema.json).
    # Surfaced in the Stage 5 enrichment-opportunity Info diagnostic (feature F).
    # Data-driven so a new supported action is a one-line edit, not a code change.
    # -------------------------------------------------------------------------
    NativeActionTypes = @(
        'IsolateMachine'
        'CollectInvestigationPackage'
        'RunAntivirusScan'
        'InitiateInvestigation'
        'RestrictAppExecution'
    )
}
