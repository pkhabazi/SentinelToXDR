function New-XDRCustomDetection {
    <#
    .SYNOPSIS
        Deploys custom detection rules to Microsoft Defender XDR.

    .DESCRIPTION
        Sends detections to POST /security/rules/detectionRules. Accepts the objects
        produced by ConvertTo-XDRCustomDetection -As Object, a raw Graph rule object, or a
        JSON file written by Export-XDRCustomDetection, so a deployment can run straight
        off a conversion or off a reviewed artifact in a repository.

        Deployment is a write against a live tenant, so it is deliberately cautious:

          - ConfirmImpact is High. Every rule prompts unless you pass -Confirm:$false or
            -Force, and -WhatIf shows exactly what would be sent without sending it.
          - Rules blocked during conversion are refused, not attempted.
          - -Format XDRConverter output is refused: only the Graph shape is deployable.
          - A rule that already exists returns HTTP 409. With -Update the rule is patched
            instead, which is what makes a re-run safe.
          - Failures do not stop the batch. Each result carries Status and Error, so one
            bad rule in 200 does not cost you the other 199.

        Requires the CustomDetection.ReadWrite.All permission and a Defender XDR role that
        grants detection tuning (Detection tuning (Manage), Security Administrator, or
        Security Operator).

    .PARAMETER Detection
        A detection object from ConvertTo-XDRCustomDetection -As Object, or a Graph rule
        object with id / displayName / queryCondition. Accepts pipeline input.

    .PARAMETER Path
        A .json file (or folder of them) written by Export-XDRCustomDetection. A file
        holding a JSON array deploys every rule in it.

    .PARAMETER Update
        PATCH a rule that already exists instead of failing on the conflict.

    .PARAMETER Disabled
        Deploy every rule with status 'disabled' regardless of the source rule. Use this
        for the first pass into production: get the rules in, review them in the portal,
        then turn them on.

    .PARAMETER AccessToken
        Bearer token for Microsoft Graph. Optional when Connect-SentinelToXDR was called or
        an Az.Accounts context is signed in.

    .PARAMETER GraphEndpoint
        Graph base URI. Defaults to the beta endpoint.

    .PARAMETER Force
        Deploy without prompting. Equivalent to -Confirm:$false.

    .EXAMPLE
        Get-SentinelAnalyticsRule -Path ./rules |
            ConvertTo-XDRCustomDetection -As Object -Force |
            New-XDRCustomDetection -WhatIf

        Shows what a deployment would send, without sending it.

    .EXAMPLE
        Get-SentinelAnalyticsRule -Path ./rules |
            ConvertTo-XDRCustomDetection -As Object -Force |
            New-XDRCustomDetection -Disabled -Update -Force

        Deploys every convertible rule turned off, updating any that already exist.

    .EXAMPLE
        New-XDRCustomDetection -Path ./out/customDetections.json -Force

        Deploys from a reviewed artifact.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High', DefaultParameterSetName = 'Detection')]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Detection', ValueFromPipeline)]
        [PSObject]$Detection,

        [Parameter(Mandatory, ParameterSetName = 'Path', Position = 0)]
        [ValidateScript({
            if (-not (Test-Path -LiteralPath $_)) { throw "Path '$_' was not found." }
            $true
        })]
        [string[]]$Path,

        [Parameter()]
        [switch]$Update,

        [Parameter()]
        [switch]$Disabled,

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

        # Turn any accepted input into a Graph rule object, or explain why it cannot be.
        function Resolve-DeployableRule {
            param([PSObject]$Candidate)

            if ($null -eq $Candidate) { return $null }

            if ($Candidate.PSObject.TypeNames -contains 'SentinelToXDR.CustomDetection') {
                if ($Candidate.Blocked) {
                    $reason = ($Candidate.Diagnostics | Where-Object { $_.Severity -eq 'Blocking' } |
                        Select-Object -First 1).Reason
                    Write-Warning "Skipping '$($Candidate.RuleName)': the rule was blocked during conversion. $reason"
                    return $null
                }
                if ($Candidate.Format -ne 'Graph') {
                    Write-Warning ("Skipping '$($Candidate.RuleName)': it was converted with -Format $($Candidate.Format), " +
                        "which the custom detection API does not accept. Convert with -Format Graph to deploy.")
                    return $null
                }
                return $Candidate.Rule
            }

            # A raw Graph rule object.
            $hasId = $Candidate.PSObject.Properties['id'] -or ($Candidate -is [System.Collections.IDictionary] -and $Candidate.Contains('id'))
            $hasQuery = $Candidate.PSObject.Properties['queryCondition'] -or ($Candidate -is [System.Collections.IDictionary] -and $Candidate.Contains('queryCondition'))
            if ($hasId -and $hasQuery) { return $Candidate }

            Write-Warning "Skipping an input object that is not a Graph detection rule (no id / queryCondition)."
            return $null
        }

        function Send-DetectionRule {
            param([object]$Rule)

            $ruleId = [string]$Rule.id
            $ruleName = [string]$Rule.displayName

            if ($Disabled) {
                # Copy rather than mutate: the caller's object is theirs. Input can be an
                # ordered hashtable (from the converter) or a PSCustomObject (from JSON).
                $payload = [ordered]@{}
                if ($Rule -is [System.Collections.IDictionary]) {
                    foreach ($key in $Rule.Keys) { $payload[$key] = $Rule[$key] }
                } else {
                    foreach ($property in $Rule.PSObject.Properties) { $payload[$property.Name] = $property.Value }
                }
                $payload['status'] = 'disabled'
                $Rule = $payload
            }

            $target = "custom detection '$ruleName' (id $ruleId)"
            if (-not $PSCmdlet.ShouldProcess($target, 'Deploy to Microsoft Defender XDR')) {
                return [PSCustomObject]@{
                    PSTypeName = 'SentinelToXDR.DeploymentResult'
                    Id = $ruleId; RuleName = $ruleName; Status = 'WhatIf'; Method = 'POST'; Error = $null
                    ServiceMessage = ''
                }
            }

            try {
                $response = Invoke-S2XRestRequest -Uri $base -Method 'POST' -Body $Rule `
                    -Audience 'Graph' -AccessToken $AccessToken
                return [PSCustomObject]@{
                    PSTypeName = 'SentinelToXDR.DeploymentResult'
                    Id = $ruleId; RuleName = $ruleName; Status = 'Created'; Method = 'POST'; Error = $null
                    ServiceMessage = ''
                    Response = $response
                }
            } catch {
                $message = $_.Exception.Message

                # Already there: patch it when the caller asked for that.
                if ($Update -and $message -match 'HTTP 409') {
                    try {
                        # PATCH takes only the updatable properties, not the whole object we
                        # just POSTed: the id lives in the URI, and sending it back is refused.
                        $patchBody = ConvertTo-DetectionPatchBody -Rule $Rule
                        $response = Invoke-S2XRestRequest -Uri "$base/$ruleId" -Method 'PATCH' -Body $patchBody `
                            -Audience 'Graph' -AccessToken $AccessToken
                        return [PSCustomObject]@{
                            PSTypeName = 'SentinelToXDR.DeploymentResult'
                            Id = $ruleId; RuleName = $ruleName; Status = 'Updated'; Method = 'PATCH'; Error = $null
                            ServiceMessage = ''
                            Response = $response
                        }
                    } catch {
                        $patchMessage = $_.Exception.Message
                        $patchService = Get-S2XServiceMessage -Message $patchMessage
                        Write-Error "Updating custom detection '$ruleName' (id $ruleId) failed: $patchService"
                        return [PSCustomObject]@{
                            PSTypeName = 'SentinelToXDR.DeploymentResult'
                            Id = $ruleId; RuleName = $ruleName; Status = 'Failed'; Method = 'PATCH'; Error = $patchMessage
                            ServiceMessage = $patchService
                        }
                    }
                }

                if ($message -match 'HTTP 409') {
                    Write-Warning ("Custom detection '$ruleName' (id $ruleId) already exists. " +
                        "Re-run with -Update to patch it.")
                    return [PSCustomObject]@{
                        PSTypeName = 'SentinelToXDR.DeploymentResult'
                        Id = $ruleId; RuleName = $ruleName; Status = 'Conflict'; Method = 'POST'; Error = $message
                        ServiceMessage = Get-S2XServiceMessage -Message $message
                    }
                }

                # One bad rule must not cost the rest of the batch. The error names the
                # service's reason; the full response stays on the result's Error property.
                $serviceMessage = Get-S2XServiceMessage -Message $message
                Write-Error "Deploying custom detection '$ruleName' (id $ruleId) failed: $serviceMessage"
                return [PSCustomObject]@{
                    PSTypeName = 'SentinelToXDR.DeploymentResult'
                    Id = $ruleId; RuleName = $ruleName; Status = 'Failed'; Method = 'POST'; Error = $message
                    ServiceMessage = $serviceMessage
                }
            }
        }
    }

    process {
        if ($PSCmdlet.ParameterSetName -eq 'Path') {
            foreach ($item in $Path) {
                $files = if (Test-Path -LiteralPath $item -PathType Container) {
                    @(Get-ChildItem -Path $item -Filter '*.json' -File)
                } else {
                    @(Get-Item -LiteralPath $item)
                }

                foreach ($file in $files) {
                    $parsed = $null
                    try {
                        $parsed = Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json -ErrorAction Stop
                    } catch {
                        Write-Error "File '$($file.FullName)' is not valid JSON: $($_.Exception.Message)"
                        continue
                    }
                    foreach ($candidate in @($parsed)) {
                        $rule = Resolve-DeployableRule -Candidate $candidate
                        if ($rule) { Send-DetectionRule -Rule $rule }
                    }
                }
            }
            return
        }

        $rule = Resolve-DeployableRule -Candidate $Detection
        if ($rule) { Send-DetectionRule -Rule $rule }
    }
}
