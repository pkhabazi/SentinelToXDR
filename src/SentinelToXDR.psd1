@{
    RootModule        = 'SentinelToXDR.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = '8c7b5caf-fd95-460e-baba-6af3f6848cf6'
    Author            = 'Pouyan Khabazi'
    CompanyName       = 'Pouyan Khabazi'
    Copyright         = '(c) 2026 Pouyan Khabazi. Licensed under the MIT License.'
    RequiredModules   = @('powershell-yaml')
    Description       = 'Read Microsoft Sentinel analytics rules from files, a content repository or a live workspace, convert them to Microsoft Defender XDR custom detections (YAML or Graph JSON), and deploy them.'
    PowerShellVersion = '7.0'
    FunctionsToExport = @(
        'Invoke-SentinelToXDRMigration'
        'Get-SentinelAnalyticsRule'
        'Test-XDRMigrationReadiness'
        'Test-XDRDetectionQuery'
        'ConvertTo-XDRCustomDetection'
        'Export-XDRCustomDetection'
        'Export-XDRMigrationReport'
        'Connect-SentinelToXDR'
        'Get-SentinelToXDRContext'
        'Get-XDRCustomDetection'
        'New-XDRCustomDetection'
        'Set-XDRCustomDetection'
        'Remove-XDRCustomDetection'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    PrivateData       = @{
        PSData = @{
            Tags         = @('Sentinel', 'XDR', 'Defender', 'Detection', 'YAML', 'JSON', 'Security', 'MITRE', 'Conversion')
            LicenseUri   = 'https://github.com/pkhabazi/SentinelToXDR/blob/main/LICENSE'
            ProjectUri   = 'https://github.com/pkhabazi/SentinelToXDR'
            ReleaseNotes = 'See CHANGELOG.md: https://github.com/pkhabazi/SentinelToXDR/blob/main/CHANGELOG.md'
        }
    }
}
