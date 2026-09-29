@{
    # -------------------------------------------------------------------------
    # Catalog of Microsoft Defender XDR advanced-hunting table names.
    #
    # BINARY CLASSIFICATION RULE (locked decision #3 in the Edge-Case plan):
    #   A table listed here is a Defender XDR table. EVERY other table referenced
    #   in a KQL query — including custom, let-defined, or function tables that
    #   aren't in this list — is treated as a Sentinel-tier table. There is NO
    #   "Unknown" bucket. Adding a new Defender table is a one-line catalog edit.
    #
    # Source: Microsoft Defender XDR advanced hunting schema reference
    #   https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-schema-tables
    # The Metadata block is stamped with the date this catalog was populated so
    # drift from the live schema is detectable / maintainable.
    # -------------------------------------------------------------------------
    Metadata = @{
        SourceDoc    = 'Microsoft Defender XDR advanced hunting schema reference'
        SourceUrl    = 'https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-schema-tables'
        PopulatedOn  = '2026-06-04'
        Note         = 'Any table NOT in the Tables list below is treated as Sentinel-tier (binary rule).'
    }

    Tables = @(
        # Device / endpoint (Microsoft Defender for Endpoint)
        'DeviceInfo'
        'DeviceNetworkInfo'
        'DeviceProcessEvents'
        'DeviceNetworkEvents'
        'DeviceFileEvents'
        'DeviceRegistryEvents'
        'DeviceLogonEvents'
        'DeviceImageLoadEvents'
        'DeviceEvents'
        'DeviceFileCertificateInfo'

        # Threat & vulnerability management (TVM)
        'DeviceTvmSoftwareInventory'
        'DeviceTvmSoftwareVulnerabilities'
        'DeviceTvmSoftwareVulnerabilitiesKB'
        'DeviceTvmSecureConfigurationAssessment'
        'DeviceTvmSecureConfigurationAssessmentKB'
        'DeviceTvmInfoGathering'
        'DeviceTvmInfoGatheringKB'
        'DeviceTvmBrowserExtensions'
        'DeviceTvmBrowserExtensionsKB'
        'DeviceTvmCertificateInfo'
        'DeviceTvmHardwareFirmware'

        # Security baseline compliance
        'DeviceBaselineComplianceProfiles'
        'DeviceBaselineComplianceAssessment'
        'DeviceBaselineComplianceAssessmentKB'

        # Email (Microsoft Defender for Office 365)
        'EmailEvents'
        'EmailAttachmentInfo'
        'EmailUrlInfo'
        'EmailPostDeliveryEvents'
        'UrlClickEvents'

        # Identity (Microsoft Defender for Identity)
        'IdentityLogonEvents'
        'IdentityQueryEvents'
        'IdentityDirectoryEvents'
        'IdentityInfo'

        # Cloud apps (Microsoft Defender for Cloud Apps)
        'CloudAppEvents'
        'AppFileEvents'   # deprecated, retained for backward compatibility

        # Alerts & incidents
        'AlertInfo'
        'AlertEvidence'

        # Behaviors
        'BehaviorInfo'
        'BehaviorEntities'

        # Exposure management graph
        'ExposureGraphNodes'
        'ExposureGraphEdges'
    )
}
