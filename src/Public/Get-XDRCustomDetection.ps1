function Get-XDRCustomDetection {
    <#
    .SYNOPSIS
        Reads custom detection rules from Microsoft Defender XDR.

    .DESCRIPTION
        Calls GET /security/rules/detectionRules on Microsoft Graph and returns the
        detection rules in the tenant, following paging automatically.

        Reading before writing is what makes a migration re-runnable: compare what is
        already deployed against what you are about to deploy, so a second run updates
        rather than duplicates.

        Requires the CustomDetection.ReadWrite.All permission (or its read-only equivalent
        if your tenant has one) and one of the Defender XDR roles that grants detection
        tuning.

    .PARAMETER Id
        Read one detection rule by id. Without it, every rule is returned.

    .PARAMETER AccessToken
        Bearer token for Microsoft Graph. Optional when Connect-SentinelToXDR was called or
        an Az.Accounts context is signed in.

    .PARAMETER GraphEndpoint
        Graph base URI. Defaults to the beta endpoint, which is where detectionRules lives.

    .EXAMPLE
        Get-XDRCustomDetection

        Lists every custom detection in the tenant.

    .EXAMPLE
        Get-XDRCustomDetection -Id 'office-encoded-powershell'

        Reads one rule.

    .EXAMPLE
        (Get-XDRCustomDetection).id

        The ids already deployed, for comparison against a conversion run.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Position = 0, ValueFromPipelineByPropertyName)]
        [string]$Id,

        [Parameter()]
        [AllowNull()]
        [object]$AccessToken,

        [Parameter()]
        [string]$GraphEndpoint = 'https://graph.microsoft.com/beta'
    )

    process {
        $base = "$($GraphEndpoint.TrimEnd('/'))/security/rules/detectionRules"

        if ($Id) {
            Invoke-S2XRestRequest -Uri "$base/$Id" -Audience 'Graph' -AccessToken $AccessToken
            return
        }

        Invoke-S2XRestRequest -Uri $base -Audience 'Graph' -AccessToken $AccessToken -Paginate
    }
}
