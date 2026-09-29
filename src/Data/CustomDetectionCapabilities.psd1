@{
    # -------------------------------------------------------------------------
    # Capability matrix mirroring the compare doc table row-for-row.
    # Source of truth: "Feature comparison- Microsoft Sentinel analytics rules
    #                   and Microsoft Defender custom detections.md"
    # The Metadata block is stamped with the doc's git_commit_id / ms.date so
    # drift between this matrix and the live doc is detectable.
    #
    # State is the *Custom detections* column, normalized to one of:
    #   Supported | NotSupported | Planned | PublicPreview
    # -------------------------------------------------------------------------
    Metadata = @{
        SourceDoc   = 'Feature comparison- Microsoft Sentinel analytics rules and Microsoft Defender custom detections.md'
        GitCommitId = '5c6b247409b0a426e2a24485684a6bcd0a14cf05'
        MsDate      = '2026-05-19'
    }

    Capabilities = @(
        @{
            Feature    = 'Alert enrichment'
            Capability = 'Flexible entity mapping over Sentinel data'
            State      = 'Supported'
            DocAnchor  = '#compare-analytics-rules-and-custom-detections-features'
            Handler    = ''
            Notes      = ''
        }
        @{
            Feature    = 'Alert enrichment'
            Capability = 'Reflect custom detections in MITRE ATT&CK page'
            State      = 'Planned'
            DocAnchor  = '/en-us/azure/sentinel/mitre-coverage?tabs=defender-portal'
            Handler    = ''
            Notes      = ''
        }
        @{
            Feature    = 'Alert enrichment'
            Capability = 'Link multiple MITRE tactics'
            State      = 'Planned'
            DocAnchor  = '#compare-analytics-rules-and-custom-detections-features'
            Handler    = ''
            Notes      = 'XDR custom detections support only one alertCategory today.'
        }
        @{
            Feature    = 'Alert enrichment'
            Capability = 'Support full list of MITRE techniques and subtechniques'
            State      = 'Planned'
            DocAnchor  = '#compare-analytics-rules-and-custom-detections-features'
            Handler    = ''
            Notes      = ''
        }
        @{
            Feature    = 'Alert enrichment'
            Capability = 'Enrich alerts with custom details'
            State      = 'Supported'
            DocAnchor  = '#compare-analytics-rules-and-custom-detections-features'
            Handler    = ''
            Notes      = ''
        }
        @{
            Feature    = 'Alert enrichment'
            Capability = 'Define alert title and description dynamically - Integrate query results in runtime'
            State      = 'Supported'
            DocAnchor  = '#compare-analytics-rules-and-custom-detections-features'
            Handler    = ''
            Notes      = ''
        }
        @{
            Feature    = 'Alert enrichment'
            Capability = 'Define all alerts properties dynamically - Integrate query results in runtime'
            State      = 'Planned'
            DocAnchor  = '#compare-analytics-rules-and-custom-detections-features'
            Handler    = ''
            Notes      = ''
        }
        @{
            Feature    = 'Rule frequency'
            Capability = 'Support flexible and high frequency for Sentinel data'
            State      = 'Supported'
            DocAnchor  = '#compare-analytics-rules-and-custom-detections-features'
            Handler    = ''
            Notes      = ''
        }
        @{
            Feature    = 'Rule frequency'
            Capability = 'Near-real-time (NRT) rules on Sentinel data'
            State      = 'Supported'
            DocAnchor  = '/en-us/defender-xdr/custom-detection-rules#queries-you-can-run-continuously'
            Handler    = ''
            Notes      = ''
        }
        @{
            Feature    = 'Rule frequency'
            Capability = 'NRT streaming technology - Test events as they stream, not sensitive to ingestion delays'
            State      = 'Supported'
            DocAnchor  = '#compare-analytics-rules-and-custom-detections-features'
            Handler    = ''
            Notes      = 'Not supported in analytics rules (which test events after ingestion).'
        }
        @{
            Feature    = 'Rule frequency'
            Capability = "Determine rule's first run"
            State      = 'NotSupported'
            DocAnchor  = '#compare-analytics-rules-and-custom-detections-features'
            Handler    = ''
            Notes      = ''
        }
        @{
            Feature    = 'Rule lookback'
            Capability = 'Lookback support'
            State      = 'PublicPreview'
            DocAnchor  = '/en-us/defender-xdr/custom-detection-rules#lookback'
            Handler    = ''
            Notes      = 'Parity with analytics rules on Sentinel data.'
        }
        @{
            Feature    = 'Rule data'
            Capability = 'Defender XDR data'
            State      = 'Supported'
            DocAnchor  = '#compare-analytics-rules-and-custom-detections-features'
            Handler    = ''
            Notes      = ''
        }
        @{
            Feature    = 'Rule data'
            Capability = 'Sentinel analytics tier'
            State      = 'Supported'
            DocAnchor  = '#compare-analytics-rules-and-custom-detections-features'
            Handler    = ''
            Notes      = ''
        }
        @{
            Feature    = 'Automated actions'
            Capability = 'Native Defender XDR remediation actions'
            State      = 'Supported'
            DocAnchor  = '#compare-analytics-rules-and-custom-detections-features'
            Handler    = ''
            Notes      = ''
        }
        @{
            Feature    = 'Automated actions'
            Capability = 'Sentinel automation rules with incident trigger'
            State      = 'Planned'
            DocAnchor  = '#compare-analytics-rules-and-custom-detections-features'
            Handler    = ''
            Notes      = ''
        }
        @{
            Feature    = 'Automated actions'
            Capability = 'Sentinel automation rules with alert trigger'
            State      = 'Planned'
            DocAnchor  = '#compare-analytics-rules-and-custom-detections-features'
            Handler    = ''
            Notes      = ''
        }
        @{
            Feature    = 'Audit and health visibility'
            Capability = 'Rules audit logs available in advanced hunting'
            State      = 'Supported'
            DocAnchor  = '#compare-analytics-rules-and-custom-detections-features'
            Handler    = ''
            Notes      = 'Exposed in the CloudAppEvents table for Microsoft Defender for Cloud Apps users; coming to all users in the future.'
        }
        @{
            Feature    = 'Audit and health visibility'
            Capability = 'Rules health logs available in advanced hunting'
            State      = 'Planned'
            DocAnchor  = '#compare-analytics-rules-and-custom-detections-features'
            Handler    = ''
            Notes      = ''
        }
        @{
            Feature    = 'Control alerts and events grouping'
            Capability = 'Customize alert grouping logic'
            State      = 'NotSupported'
            DocAnchor  = '#compare-analytics-rules-and-custom-detections-features'
            Handler    = ''
            Notes      = 'The SIEM/XDR correlation engine handles alert grouping.'
        }
        @{
            Feature    = 'Control alerts and events grouping'
            Capability = 'Choose between all events under one alert and one alert per event'
            State      = 'NotSupported'
            DocAnchor  = '#compare-analytics-rules-and-custom-detections-features'
            Handler    = ''
            Notes      = ''
        }
        @{
            Feature    = 'Control alerts and events grouping'
            Capability = 'Group events to one alert when custom details, alert dynamic details, and entities are identical'
            State      = 'Supported'
            DocAnchor  = '#compare-analytics-rules-and-custom-detections-features'
            Handler    = ''
            Notes      = 'Not supported in analytics rules.'
        }
        @{
            Feature    = 'Control incidents and alerts creation'
            Capability = 'Exclude incidents from correlation engine - Ensure that incidents from different rules remain separated'
            State      = 'Planned'
            DocAnchor  = '#compare-analytics-rules-and-custom-detections-features'
            Handler    = ''
            Notes      = ''
        }
        @{
            Feature    = 'Control incidents and alerts creation'
            Capability = 'Create alerts without incidents'
            State      = 'NotSupported'
            DocAnchor  = '#compare-analytics-rules-and-custom-detections-features'
            Handler    = ''
            Notes      = ''
        }
        @{
            Feature    = 'Control incidents and alerts creation'
            Capability = 'Alerts suppression - Define alert suppression after the rule runs'
            State      = 'NotSupported'
            DocAnchor  = '#compare-analytics-rules-and-custom-detections-features'
            Handler    = ''
            Notes      = ''
        }
        @{
            Feature    = 'Rules management'
            Capability = 'Rerun rule on demand on a previous time window'
            State      = 'Planned'
            DocAnchor  = '#compare-analytics-rules-and-custom-detections-features'
            Handler    = ''
            Notes      = ''
        }
        @{
            Feature    = 'Rules management'
            Capability = 'Run rule on demand'
            State      = 'Supported'
            DocAnchor  = '#compare-analytics-rules-and-custom-detections-features'
            Handler    = ''
            Notes      = 'Not supported in analytics rules.'
        }
        @{
            Feature    = 'Rules management'
            Capability = 'Health and quality workbooks'
            State      = 'Planned'
            DocAnchor  = '#compare-analytics-rules-and-custom-detections-features'
            Handler    = ''
            Notes      = ''
        }
        @{
            Feature    = 'Rules management'
            Capability = 'Integration with Sentinel repositories'
            State      = 'Planned'
            DocAnchor  = '#compare-analytics-rules-and-custom-detections-features'
            Handler    = ''
            Notes      = ''
        }
        @{
            Feature    = 'Rules management'
            Capability = 'Manage rules from API'
            State      = 'Supported'
            DocAnchor  = '#compare-analytics-rules-and-custom-detections-features'
            Handler    = ''
            Notes      = ''
        }
        @{
            Feature    = 'Rules management'
            Capability = 'Bicep support'
            State      = 'Planned'
            DocAnchor  = '#compare-analytics-rules-and-custom-detections-features'
            Handler    = ''
            Notes      = ''
        }
        @{
            Feature    = 'Content hub'
            Capability = 'Create rules from content hub'
            State      = 'Planned'
            DocAnchor  = '#compare-analytics-rules-and-custom-detections-features'
            Handler    = ''
            Notes      = ''
        }
        @{
            Feature    = 'Multi workspace'
            Capability = 'Create custom detections on any workspaces onboarded to Defender'
            State      = 'Planned'
            DocAnchor  = '#compare-analytics-rules-and-custom-detections-features'
            Handler    = ''
            Notes      = ''
        }
        @{
            Feature    = 'Multi workspace'
            Capability = 'Cross workspaces detection using the workspace operator'
            State      = 'Planned'
            DocAnchor  = '#compare-analytics-rules-and-custom-detections-features'
            Handler    = ''
            Notes      = ''
        }
        @{
            Feature    = 'Testing and validations'
            Capability = "Rule simulation from the rule's wizard"
            State      = 'Planned'
            DocAnchor  = '#compare-analytics-rules-and-custom-detections-features'
            Handler    = ''
            Notes      = ''
        }
    )
}
