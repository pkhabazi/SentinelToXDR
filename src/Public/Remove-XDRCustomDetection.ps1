function Remove-XDRCustomDetection {
    <#
    .SYNOPSIS
        Deletes custom detection rules from Microsoft Defender XDR.

    .DESCRIPTION
        Sends DELETE /security/rules/detectionRules/{id}.

        Deletion is irreversible and there is no undo in the product, so this cmdlet
        prompts for every rule by default and requires -Id explicitly. There is no
        "delete everything" switch on purpose: if you want that, pipe Get-XDRCustomDetection
        into it deliberately and answer the prompts.

        The usual reason to reach for this is cleaning up after a test migration into a lab
        tenant.

        A 404 from the service means it does not have that rule, so there is nothing left
        to delete. This cmdlet reports those as 'AlreadyDeleted' with one summary warning
        rather than an error, so a cleanup pipeline is not stopped by a rule that is
        already gone. Every other refusal is 'Failed' and writes an error.

        Observed 2026-09-17: a cleanup run piping Get-XDRCustomDetection into this cmdlet
        met 404s for ids the list had just served. Whether those rules had been deleted by
        an earlier run, or the list is serving rules the delete endpoint does not have, is
        not established - deleting in the portal is reflected there at once. Ask the
        service for a single rule with Get-XDRCustomDetection -Id to see which it is.

    .PARAMETER Id
        Id of the detection rule to delete. Accepts pipeline input by property name, so
        Get-XDRCustomDetection output pipes straight in.

    .PARAMETER AccessToken
        Bearer token for Microsoft Graph.

    .PARAMETER GraphEndpoint
        Graph base URI. Defaults to the beta endpoint.

    .EXAMPLE
        Remove-XDRCustomDetection -Id 'office-encoded-powershell'

        Deletes one rule, after confirming.

    .EXAMPLE
        Get-XDRCustomDetection | Where-Object { $_.displayName -like 'TEST-*' } |
            Remove-XDRCustomDetection -WhatIf

        Shows which lab rules would be removed.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [string]$Id,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$DisplayName,

        [Parameter()]
        [AllowNull()]
        [object]$AccessToken,

        [Parameter()]
        [string]$GraphEndpoint = 'https://graph.microsoft.com/beta'
    )

    begin {
        $base = "$($GraphEndpoint.TrimEnd('/'))/security/rules/detectionRules"
        $alreadyDeleted = [System.Collections.Generic.List[string]]::new()
    }

    process {
        $label = if ($DisplayName) { "custom detection '$DisplayName' (id $Id)" } else { "custom detection '$Id'" }

        if (-not $PSCmdlet.ShouldProcess($label, 'Delete from Microsoft Defender XDR')) {
            return [PSCustomObject]@{
                PSTypeName = 'SentinelToXDR.DeploymentResult'
                Id = $Id; RuleName = $DisplayName; Status = 'WhatIf'; Method = 'DELETE'; Error = $null
                ServiceMessage = ''
            }
        }

        try {
            Invoke-S2XRestRequest -Uri "$base/$Id" -Method 'DELETE' -Audience 'Graph' -AccessToken $AccessToken | Out-Null
            [PSCustomObject]@{
                PSTypeName = 'SentinelToXDR.DeploymentResult'
                Id = $Id; RuleName = $DisplayName; Status = 'Deleted'; Method = 'DELETE'; Error = $null
                ServiceMessage = ''
            }
        } catch {
            $message = $_.Exception.Message
            $serviceMessage = Get-S2XServiceMessage -Message $message

            # A 404 on DELETE means the service does not have the rule, so there is
            # nothing left to delete and the pipeline must not stop. Observed 2026-09-17
            # on a cleanup run whose ids all came straight from Get-XDRCustomDetection:
            # the list served rules the delete endpoint answered 404 for. Why the two
            # endpoints disagree is not established - a portal delete is reflected in the
            # portal immediately - so this reports what happened and does not name a cause.
            if ($message -match 'failed with HTTP 404\b|"code"\s*:\s*"(Resource)?NotFound"|\bwas not found\b') {
                $alreadyDeleted.Add($Id)
                Write-Verbose "$label was reported as not found by the service; nothing left to delete."
                return [PSCustomObject]@{
                    PSTypeName = 'SentinelToXDR.DeploymentResult'
                    Id = $Id; RuleName = $DisplayName; Status = 'AlreadyDeleted'; Method = 'DELETE'; Error = $null
                    ServiceMessage = $serviceMessage
                }
            }

            Write-Error "Deleting $label failed: $serviceMessage"
            [PSCustomObject]@{
                PSTypeName = 'SentinelToXDR.DeploymentResult'
                Id = $Id; RuleName = $DisplayName; Status = 'Failed'; Method = 'DELETE'; Error = $message
                ServiceMessage = $serviceMessage
            }
        }
    }

    end {
        if ($alreadyDeleted.Count -gt 0) {
            $noun = if ($alreadyDeleted.Count -eq 1) { 'rule was' } else { 'rules were' }
            Write-Warning ("$($alreadyDeleted.Count) $noun reported as not found, so nothing was deleted for " +
                "$(if ($alreadyDeleted.Count -eq 1) { 'it' } else { 'them' }) (status AlreadyDeleted). If an id came " +
                'from Get-XDRCustomDetection, the list and the delete endpoint disagree: check with ' +
                'Get-XDRCustomDetection -Id <id>, which asks the service for that one rule.')
        }
    }
}
