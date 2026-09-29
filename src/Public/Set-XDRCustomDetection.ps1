function Set-XDRCustomDetection {
    <#
    .SYNOPSIS
        Updates existing custom detection rules in Microsoft Defender XDR.

    .DESCRIPTION
        Sends PATCH /security/rules/detectionRules/{id} for rules that already exist. Use
        this when you are re-converting rules you have already deployed and want the
        detection updated in place, keeping its id and its alert history association.

        New-XDRCustomDetection -Update covers the common case (create, or patch on
        conflict). This cmdlet is the explicit form for when you know the rule exists and
        want an update to be the only possible outcome, so a typo in an id fails loudly
        instead of quietly creating a second rule.

    .PARAMETER Detection
        A detection object from ConvertTo-XDRCustomDetection -As Object, or a Graph rule
        object. Accepts pipeline input.

    .PARAMETER Id
        Override the id to patch. Defaults to the id on the detection object.

    .PARAMETER Status
        Set the run status without touching anything else: enabled or disabled. When given
        with -Id and no -Detection, only the status is patched.

    .PARAMETER AccessToken
        Bearer token for Microsoft Graph.

    .PARAMETER GraphEndpoint
        Graph base URI. Defaults to the beta endpoint.

    .PARAMETER Force
        Update without prompting.

    .EXAMPLE
        Get-SentinelAnalyticsRule -Path ./rules |
            ConvertTo-XDRCustomDetection -As Object -Force |
            Set-XDRCustomDetection -Force

        Re-applies a whole converted set over the deployed rules.

    .EXAMPLE
        Set-XDRCustomDetection -Id 'office-encoded-powershell' -Status enabled -Force

        Turns one detection on after reviewing it in the portal.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High', DefaultParameterSetName = 'Detection')]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Detection', ValueFromPipeline)]
        [PSObject]$Detection,

        [Parameter(ParameterSetName = 'Detection')]
        [Parameter(Mandatory, ParameterSetName = 'Status', Position = 0)]
        [string]$Id,

        [Parameter(Mandatory, ParameterSetName = 'Status')]
        [ValidateSet('enabled', 'disabled')]
        [string]$Status,

        [Parameter()]
        [AllowNull()]
        [object]$AccessToken,

        [Parameter()]
        [string]$GraphEndpoint = 'https://graph.microsoft.com/beta',

        [Parameter()]
        [switch]$Force
    )

    begin {
        $base = "$($GraphEndpoint.TrimEnd('/'))/security/rules/detectionRules"
        if ($Force -and -not $PSBoundParameters.ContainsKey('Confirm')) {
            $ConfirmPreference = 'None'
        }
    }

    process {
        # ---- status-only patch -------------------------------------------------
        if ($PSCmdlet.ParameterSetName -eq 'Status') {
            if (-not $PSCmdlet.ShouldProcess("custom detection '$Id'", "Set status to '$Status'")) { return }
            try {
                $response = Invoke-S2XRestRequest -Uri "$base/$Id" -Method 'PATCH' -Body ([ordered]@{ status = $Status }) `
                    -Audience 'Graph' -AccessToken $AccessToken
                return [PSCustomObject]@{
                    PSTypeName = 'SentinelToXDR.DeploymentResult'
                    Id = $Id; RuleName = [string]$response.displayName; Status = 'Updated'; Method = 'PATCH'; Error = $null
                ServiceMessage = ''
                    Response = $response
                }
            } catch {
                $message = $_.Exception.Message
                $serviceMessage = Get-S2XServiceMessage -Message $message
                Write-Error "Setting status on custom detection '$Id' failed: $serviceMessage"
                return [PSCustomObject]@{
                    PSTypeName = 'SentinelToXDR.DeploymentResult'
                    Id = $Id; RuleName = ''; Status = 'Failed'; Method = 'PATCH'; Error = $message
                    ServiceMessage = $serviceMessage
                }
            }
        }

        # ---- full rule patch ---------------------------------------------------
        $rule = $null
        if ($Detection.PSObject.TypeNames -contains 'SentinelToXDR.CustomDetection') {
            if ($Detection.Blocked) {
                Write-Warning "Skipping '$($Detection.RuleName)': the rule was blocked during conversion."
                return
            }
            if ($Detection.Format -ne 'Graph') {
                Write-Warning ("Skipping '$($Detection.RuleName)': it was converted with -Format $($Detection.Format), " +
                    "which the custom detection API does not accept.")
                return
            }
            $rule = $Detection.Rule
        } else {
            $rule = $Detection
        }

        if ($null -eq $rule) { return }

        $ruleId = if ($Id) { $Id } else { [string]$rule.id }
        $ruleName = [string]$rule.displayName

        if ([string]::IsNullOrWhiteSpace($ruleId)) {
            Write-Error "Cannot update '$ruleName': no rule id. Supply -Id."
            return
        }

        if (-not $PSCmdlet.ShouldProcess("custom detection '$ruleName' (id $ruleId)", 'Update in Microsoft Defender XDR')) {
            return [PSCustomObject]@{
                PSTypeName = 'SentinelToXDR.DeploymentResult'
                Id = $ruleId; RuleName = $ruleName; Status = 'WhatIf'; Method = 'PATCH'; Error = $null
                ServiceMessage = ''
            }
        }

        try {
            # Only the properties PATCH accepts. The id addresses the rule in the URI, and
            # the service-owned fields a read-back carries would be rejected outright.
            $patchBody = ConvertTo-DetectionPatchBody -Rule $rule
            $response = Invoke-S2XRestRequest -Uri "$base/$ruleId" -Method 'PATCH' -Body $patchBody `
                -Audience 'Graph' -AccessToken $AccessToken
            [PSCustomObject]@{
                PSTypeName = 'SentinelToXDR.DeploymentResult'
                Id = $ruleId; RuleName = $ruleName; Status = 'Updated'; Method = 'PATCH'; Error = $null
                ServiceMessage = ''
                Response = $response
            }
        } catch {
            $message = $_.Exception.Message
            $serviceMessage = Get-S2XServiceMessage -Message $message
            Write-Error "Updating custom detection '$ruleName' (id $ruleId) failed: $serviceMessage"
            [PSCustomObject]@{
                PSTypeName = 'SentinelToXDR.DeploymentResult'
                Id = $ruleId; RuleName = $ruleName; Status = 'Failed'; Method = 'PATCH'; Error = $message
                ServiceMessage = $serviceMessage
            }
        }
    }
}
