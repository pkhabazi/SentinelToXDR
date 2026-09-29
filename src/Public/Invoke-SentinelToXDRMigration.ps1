function Invoke-SentinelToXDRMigration {
    <#
    .SYNOPSIS
        Runs a whole Sentinel-to-Defender-XDR migration: assess, report, convert, deploy.

    .DESCRIPTION
        The single entry point for the four questions a migration actually asks:

          1. Which of my Sentinel analytics rules can become custom detections?
          2. Which cannot, and what is blocking them?
          3. Give me the ones that can, in the XDR schema.
          4. Put them in the tenant.

        Everything here is done by the individual cmdlets — Get-SentinelAnalyticsRule,
        Test-XDRMigrationReadiness, Export-XDRMigrationReport, Export-XDRCustomDetection,
        Test-XDRDetectionQuery, New-XDRCustomDetection. This one orders them, carries the
        converted detection between stages so nothing is converted twice, and returns a
        single summary. Use the individual cmdlets when you want a different order or only
        one step; use this one for the whole job.

        Nothing is written and nothing is deployed unless you ask:

          no -ReportPath    no report file
          no -OutputFolder  nothing written to disk
          no -Deploy        nothing reaches the tenant, ever

        -Deploy is the only route to a write, it honours -WhatIf, and it still asks per
        rule unless you pass -Force. Blocked rules cannot be deployed by any combination of
        parameters. Rules the assessment called NeedsWork are held back unless you say
        -DeployVerdict NeedsWork, which is a deliberate act rather than a default.

    .PARAMETER Path
        File or folder of Sentinel analytics rules — community YAML, ARM templates, or
        REST exports.

    .PARAMETER Recurse
        Search subfolders when -Path is a folder.

    .PARAMETER Filter
        Filename patterns to consider when -Path is a folder.

    .PARAMETER SubscriptionId
        Subscription of the Sentinel workspace to read rules from.

    .PARAMETER ResourceGroupName
        Resource group of the Sentinel workspace.

    .PARAMETER WorkspaceName
        Log Analytics workspace backing Sentinel.

    .PARAMETER ArmAccessToken
        ARM token for reading the workspace. Named ArmAccessToken because -AccessToken is
        the Graph token used by the validate and deploy stages; a migration that reads a
        live workspace and deploys needs both.

    .PARAMETER ApiVersion
        SecurityInsights API version used to read the workspace.

    .PARAMETER InputObject
        Rules from Get-SentinelAnalyticsRule, or detections already converted with
        ConvertTo-XDRCustomDetection -As Object. Accepts pipeline input.

    .PARAMETER ReportPath
        Where to write the migration readiness report. Omit it and no report is written.

    .PARAMETER ReportFormat
        Csv, Markdown or Html. Inferred from the -ReportPath extension when not given.

    .PARAMETER ReportTitle
        Title for the report.

    .PARAMETER OutputFolder
        Where to write the converted detections. Omit it and nothing is written to disk.

    .PARAMETER ExportFormat
        Yaml, Json or Both for the exported detections.

    .PARAMETER NameBy
        Name exported files by rule Id or DisplayName.

    .PARAMETER Combine
        Write one customDetections.json array instead of a file per rule.

    .PARAMETER Force
        Overwrite existing exported files, and skip the per-rule deployment confirmation.

    .PARAMETER ValidateQuery
        Run each converted query against the tenant with Test-XDRDetectionQuery before
        deciding anything. Read-only; needs ThreatHunting.Read.All. This is the only stage
        that catches a query which converts cleanly but cannot run — a watchlist reference,
        an ASIM parser, a saved function. Worth the time on a first migration.

    .PARAMETER QueryTimespan
        Timespan for the validation queries.

    .PARAMETER DelayMilliseconds
        Pause between validation queries, so a large estate does not trip the hunting quota.

    .PARAMETER RequireQueryValid
        Deploy only rules whose query was validated successfully. Needs -ValidateQuery.

    .PARAMETER Deploy
        Deploy the eligible detections to Defender XDR. Without this switch nothing is sent.

    .PARAMETER DeployVerdict
        The worst verdict still eligible to deploy. Ready deploys only clean rules; Review
        (the default) also deploys rules whose only finding is a prerequisite; NeedsWork
        also deploys rules that will not behave as they did in Sentinel. Blocked is not an
        accepted value.

    .PARAMETER DeployDisabled
        Create the detections disabled, so they can be reviewed in the portal before they
        start running. The safe way to do a first deployment.

    .PARAMETER Update
        Patch a detection that already exists instead of failing on the conflict, which
        makes re-running the migration idempotent.

    .PARAMETER AccessToken
        Graph token for the validate and deploy stages. Defaults to the session established
        by Connect-SentinelToXDR.

    .PARAMETER GraphEndpoint
        Graph endpoint for the validate and deploy stages.

    .PARAMETER PassThru
        Keep the converted detection on every result row. Off by default, because a
        thousand-rule estate summary is a lot easier to read, store and pipe without them.

    .EXAMPLE
        Invoke-SentinelToXDRMigration -Path ./Samples -ReportPath ./migration.html

        The assessment. Reads the rules, works out which migrate, writes the report.
        Touches no tenant and writes nothing else.

    .EXAMPLE
        Invoke-SentinelToXDRMigration -Path ./Solutions -Recurse -ReportPath ./migration.html -OutputFolder ./out

        The same, plus the converted detections on disk ready for review or a pipeline.

    .EXAMPLE
        Invoke-SentinelToXDRMigration -Path ./rules -Recurse -ValidateQuery -Deploy -WhatIf

        The dry run to do before the real one: proves every query actually executes in the
        tenant, and shows exactly what would be deployed without deploying it.

    .EXAMPLE
        Invoke-SentinelToXDRMigration -Path ./rules -Recurse -ValidateQuery -RequireQueryValid `
            -Deploy -DeployDisabled -Force -ReportPath ./migration.html

        The real one: deploy every rule that both assesses clean and proves it runs, created
        disabled so they can be checked before they fire.

    .EXAMPLE
        Invoke-SentinelToXDRMigration -SubscriptionId $sub -ResourceGroupName rg-soc `
            -WorkspaceName law-soc -ReportPath ./migration.html

        Assess a live Sentinel workspace rather than a folder.

    .LINK
        Test-XDRMigrationReadiness
    .LINK
        New-XDRCustomDetection
    .LINK
        Connect-SentinelToXDR
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium', DefaultParameterSetName = 'Path')]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Path', Position = 0, ValueFromPipelineByPropertyName)]
        [Alias('FullName', 'PSPath')]
        [string[]]$Path,

        [Parameter(ParameterSetName = 'Path')]
        [switch]$Recurse,

        [Parameter(ParameterSetName = 'Path')]
        [string[]]$Filter = @('*.yaml', '*.yml', '*.json'),

        [Parameter(Mandatory, ParameterSetName = 'Workspace')]
        [string]$SubscriptionId,

        [Parameter(Mandatory, ParameterSetName = 'Workspace')]
        [string]$ResourceGroupName,

        [Parameter(Mandatory, ParameterSetName = 'Workspace')]
        [string]$WorkspaceName,

        [Parameter(ParameterSetName = 'Workspace')]
        [AllowNull()]
        [object]$ArmAccessToken,

        [Parameter(ParameterSetName = 'Workspace')]
        [string]$ApiVersion = '2024-09-01',

        [Parameter(Mandatory, ParameterSetName = 'InputObject', ValueFromPipeline)]
        [PSObject]$InputObject,

        [Parameter()]
        [string]$ReportPath,

        [Parameter()]
        [ValidateSet('Csv', 'Markdown', 'Html')]
        [string]$ReportFormat,

        [Parameter()]
        [string]$ReportTitle = 'Sentinel to Defender XDR migration readiness',

        [Parameter()]
        [string]$OutputFolder,

        [Parameter()]
        [ValidateSet('Yaml', 'Json', 'Both')]
        [string]$ExportFormat = 'Both',

        [Parameter()]
        [ValidateSet('Id', 'DisplayName')]
        [string]$NameBy = 'Id',

        [Parameter()]
        [switch]$Combine,

        [Parameter()]
        [switch]$Force,

        [Parameter()]
        [switch]$ValidateQuery,

        [Parameter()]
        [string]$QueryTimespan = 'PT5M',

        [Parameter()]
        [int]$DelayMilliseconds = 250,

        [Parameter()]
        [switch]$RequireQueryValid,

        [Parameter()]
        [switch]$Deploy,

        # Blocked is deliberately absent: a rule that cannot become a custom detection must
        # not be expressible as a deployment target. This is a binding error, not a runtime
        # check, which is the difference between a guard and a hope.
        [Parameter()]
        [ValidateSet('Ready', 'Review', 'NeedsWork')]
        [string]$DeployVerdict = 'Review',

        [Parameter()]
        [switch]$DeployDisabled,

        [Parameter()]
        [switch]$Update,

        [Parameter()]
        [AllowNull()]
        [object]$AccessToken,

        [Parameter()]
        [string]$GraphEndpoint = 'https://graph.microsoft.com/beta',

        [Parameter()]
        [switch]$PassThru
    )

    begin {
        # "Cannot do X" has two very different causes and one useless message. Not being
        # signed in at all is the common one — a Connect-MgGraph session does not survive
        # the process, so connecting in one shell and running in another looks exactly like
        # a missing permission. Telling someone to grant a scope they already have is worse
        # than saying nothing.
        function Get-AuthFailureReason {
            param([PSObject]$Context, [string]$Scope)

            if (-not $Context.Account) {
                return ('there is no sign-in in this session. Run Connect-SentinelToXDR ' +
                    'first, in this same session — a Graph sign-in does not carry across ' +
                    'PowerShell processes.')
            }
            return ("the sign-in '$($Context.Account)' does not have $Scope. " +
                'Reconnect with Connect-SentinelToXDR and consent to that permission.')
        }

        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        $inputObjects = [System.Collections.Generic.List[object]]::new()
        $paths = [System.Collections.Generic.List[string]]::new()

        # Ready is best. The comparison is "this verdict or better", so Blocked at 3 is
        # unreachable given DeployVerdict tops out at NeedsWork.
        $verdictRank = @{ 'Ready' = 0; 'Review' = 1; 'NeedsWork' = 2; 'Blocked' = 3 }

        # ---- fail fast on combinations that cannot do what they look like ----
        # These fire before a single rule is read, because discovering that -Combine is
        # incompatible with -Format Yaml after converting 3,000 rules helps nobody.
        if ($Combine -and $ExportFormat -eq 'Yaml') {
            throw "-Combine writes a single JSON array; use -ExportFormat Json or -ExportFormat Both."
        }

        if (-not $OutputFolder) {
            foreach ($name in @('ExportFormat', 'NameBy', 'Combine')) {
                if ($PSBoundParameters.ContainsKey($name)) {
                    Write-Warning "-$name was given without -OutputFolder, so nothing will be exported to disk."
                }
            }
        }
        if (-not $ReportPath -and $PSBoundParameters.ContainsKey('ReportFormat')) {
            Write-Warning '-ReportFormat was given without -ReportPath, so no report will be written.'
        }
        if (-not $Deploy) {
            foreach ($name in @('DeployVerdict', 'DeployDisabled', 'Update')) {
                if ($PSBoundParameters.ContainsKey($name)) {
                    Write-Warning "-$name was given without -Deploy. Nothing will be deployed."
                }
            }
        }
        if ($RequireQueryValid -and -not $ValidateQuery) {
            Write-Warning '-RequireQueryValid needs -ValidateQuery to mean anything; it will be ignored.'
        }
    }

    process {
        switch ($PSCmdlet.ParameterSetName) {
            'Path'        { foreach ($item in $Path) { $paths.Add($item) } }
            'InputObject' { if ($null -ne $InputObject) { $inputObjects.Add($InputObject) } }
        }
    }

    end {
        $summary = [ordered]@{
            PSTypeName       = 'SentinelToXDR.MigrationSummary'
            Source           = $PSCmdlet.ParameterSetName
            RuleCount        = 0
            Assessed         = 0
            Ready            = 0
            Review           = 0
            NeedsWork        = 0
            Blocked          = 0
            ReportPath       = $null
            ExportFolder     = $null
            Exported         = 0
            QueriesValidated = 0
            QueriesFailed    = 0
            Deployed         = 0
            Updated          = 0
            DeploySkipped    = 0
            DeployFailed     = 0
            WhatIf           = [bool]$WhatIfPreference
            Duration         = [timespan]::Zero
            Results          = @()
        }

        # ---- Stage 1: read the rules ----------------------------------------
        Write-Verbose 'Stage 1/6: reading Sentinel analytics rules.'
        $rules = @()
        switch ($PSCmdlet.ParameterSetName) {
            'Path' {
                $getParams = @{ Path = $paths.ToArray(); Filter = $Filter }
                if ($Recurse) { $getParams['Recurse'] = $true }
                $rules = @(Get-SentinelAnalyticsRule @getParams -ErrorAction Continue)
            }
            'Workspace' {
                $getParams = @{
                    SubscriptionId    = $SubscriptionId
                    ResourceGroupName = $ResourceGroupName
                    WorkspaceName     = $WorkspaceName
                    ApiVersion        = $ApiVersion
                }
                if ($PSBoundParameters.ContainsKey('ArmAccessToken')) { $getParams['AccessToken'] = $ArmAccessToken }
                $rules = @(Get-SentinelAnalyticsRule @getParams -ErrorAction Continue)
            }
            'InputObject' { $rules = $inputObjects.ToArray() }
        }

        $summary['RuleCount'] = $rules.Count
        if ($rules.Count -eq 0) {
            Write-Warning 'No Sentinel analytics rules were found; there is nothing to migrate.'
            $stopwatch.Stop()
            $summary['Duration'] = $stopwatch.Elapsed
            return [PSCustomObject]$summary
        }

        # ---- Stage 2: assess -------------------------------------------------
        Write-Verbose "Stage 2/6: assessing $($rules.Count) rule(s)."
        # -PassThruDetection is what lets stages 4-6 reuse the conversion instead of doing
        # it again. Conversion warnings are silenced here and re-surfaced, deduplicated and
        # ranked, through the verdict Headline and the report: replaying several thousand
        # raw warnings is exactly the noise this cmdlet exists to remove. -Verbose still
        # shows the detail.
        $readiness = @($rules | Test-XDRMigrationReadiness -PassThruDetection -WarningAction SilentlyContinue -ErrorAction Continue)

        $results = foreach ($row in $readiness) {
            $result = [ordered]@{ PSTypeName = 'SentinelToXDR.MigrationResult' }
            foreach ($property in $row.PSObject.Properties) {
                if ($property.Name -eq 'Detection') { continue }
                $result[$property.Name] = $property.Value
            }
            $result['QueryValid']       = $null
            $result['QueryFailureKind'] = $null
            $result['DeployStatus']     = 'NotAttempted'
            $result['DeployError']      = $null
            $result['DeployServiceMessage'] = $null
            $result['Detection']        = $row.Detection
            [PSCustomObject]$result
        }
        $results = @($results)

        $summary['Assessed'] = $results.Count
        foreach ($name in @('Ready', 'Review', 'NeedsWork', 'Blocked')) {
            $summary[$name] = @($results | Where-Object { $_.Verdict -eq $name }).Count
        }

        # ---- Stage 3: report -------------------------------------------------
        # Before the export and the deploy on purpose: if a later stage falls over, the
        # assessment — the thing the user most needs — is already on disk.
        if ($ReportPath) {
            Write-Verbose "Stage 3/6: writing the readiness report to $ReportPath."
            try {
                $reportParams = @{ Path = $ReportPath; Title = $ReportTitle }
                if ($PSBoundParameters.ContainsKey('ReportFormat')) { $reportParams['Format'] = $ReportFormat }
                # Piped, never passed by argument: -Result is a scalar [PSObject], so an
                # array handed to it binds as one object and reports a single nonsense row.
                $results | Export-XDRMigrationReport @reportParams | Out-Null
                $summary['ReportPath'] = $ReportPath
            } catch {
                Write-Error "The readiness report could not be written: $($_.Exception.Message)"
            }
        }

        # ---- Stage 4: export -------------------------------------------------
        if ($OutputFolder) {
            Write-Verbose "Stage 4/6: exporting converted detections to $OutputFolder."
            try {
                $detections = @($results | Where-Object { $_.Detection } | ForEach-Object { $_.Detection })
                $exportParams = @{ Path = $OutputFolder; Format = $ExportFormat; NameBy = $NameBy }
                if ($Force) { $exportParams['Force'] = $true }
                if ($Combine) { $exportParams['Combine'] = $true }
                # Export-XDRCustomDetection skips blocked detections itself; no need to
                # filter them here and no need to duplicate the rule.
                $detections | Export-XDRCustomDetection @exportParams | Out-Null
                $summary['ExportFolder'] = $OutputFolder
                $summary['Exported'] = @($detections | Where-Object { -not $_.Blocked }).Count
            } catch {
                Write-Error "The detections could not be exported: $($_.Exception.Message)"
            }
        }

        # ---- Stage 5: validate the queries against the tenant ----------------
        if ($ValidateQuery -and $WhatIfPreference) {
            # -WhatIf promises that nothing leaves this machine. Query validation is a POST
            # per rule to runHuntingQuery, read-only but still a request, and it used to run
            # under -WhatIf. Skip it and say so, so the dry run is a dry run.
            Write-Warning 'Query validation was skipped under -WhatIf: it would send every query to the tenant.'
            $summary['QueryValidationSkipped'] = 'WhatIf'
        }
        elseif ($ValidateQuery) {
            Write-Verbose 'Stage 5/6: running each converted query against the tenant.'
            try {
                $context = Get-SentinelToXDRContext
                $canValidate = $context.CanValidateQueries
                if ($canValidate -eq $false) {
                    # A warning, not an error: query validation is optional enrichment and
                    # must never cost the user a report that was otherwise fine.
                    Write-Warning ('Query validation was skipped: ' + (Get-AuthFailureReason -Context $context -Scope 'ThreatHunting.Read.All'))
                } else {
                    if ($null -eq $canValidate) {
                        Write-Warning 'Cannot confirm the token grants ThreatHunting.Read.All; attempting validation anyway.'
                    }
                    $targets = @($results | Where-Object { $_.Detection -and -not $_.Detection.Blocked })
                    $validations = @($targets | Test-XDRDetectionQuery -Timespan $QueryTimespan `
                            -DelayMilliseconds $DelayMilliseconds -AccessToken $AccessToken `
                            -GraphEndpoint $GraphEndpoint -ErrorAction Continue)

                    $byId = @{}
                    foreach ($validation in $validations) {
                        $key = if ($validation.Id) { [string]$validation.Id } else { [string]$validation.RuleName }
                        if ($key) { $byId[$key] = $validation }
                    }

                    foreach ($result in $results) {
                        $key = if ($result.Id) { [string]$result.Id } else { [string]$result.RuleName }
                        if (-not $key -or -not $byId.ContainsKey($key)) { continue }
                        $validation = $byId[$key]
                        $result.QueryFailureKind = $validation.FailureKind
                        # NotAttempted is the circuit-breaker after an auth or throttling
                        # failure. It means "we never asked", which must not be recorded as
                        # "the query is broken".
                        if ($validation.FailureKind -ne 'NotAttempted') {
                            $result.QueryValid = [bool]$validation.QueryValid
                        }
                    }

                    $summary['QueriesValidated'] = @($results | Where-Object { $_.QueryValid -eq $true }).Count
                    $summary['QueriesFailed'] = @($results | Where-Object { $_.QueryValid -eq $false }).Count
                }
            } catch {
                Write-Error "Query validation failed: $($_.Exception.Message)"
            }
        }

        # ---- Stage 6: deploy -------------------------------------------------
        if ($Deploy) {
            Write-Verbose 'Stage 6/6: deploying eligible detections.'
            try {
                $context = Get-SentinelToXDRContext
                $canDeploy = $context.CanManageDetections
                if ($canDeploy -eq $false) {
                    Write-Error ('Nothing was deployed: ' +
                        (Get-AuthFailureReason -Context $context -Scope 'CustomDetection.ReadWrite.All') +
                        ' The assessment above is unaffected.')
                } else {
                    if ($null -eq $canDeploy) {
                        Write-Warning ('Cannot confirm the token grants CustomDetection.ReadWrite.All; ' +
                            'proceeding. An HTTP 403 here means that scope is missing.')
                    }

                    $eligible = @($results | Where-Object {
                            $_.Detection -and
                            -not $_.Detection.Blocked -and
                            $verdictRank.ContainsKey([string]$_.Verdict) -and
                            $verdictRank[[string]$_.Verdict] -le $verdictRank[$DeployVerdict] -and
                            (-not ($RequireQueryValid -and $ValidateQuery) -or $_.QueryValid -eq $true)
                        })

                    foreach ($result in $results) {
                        if ($eligible -notcontains $result) { $result.DeployStatus = 'Skipped' }
                    }
                    $summary['DeploySkipped'] = @($results | Where-Object { $_.DeployStatus -eq 'Skipped' }).Count

                    if ($eligible.Count -eq 0) {
                        Write-Warning "No detections were eligible to deploy at -DeployVerdict $DeployVerdict."
                    } elseif ($PSCmdlet.ShouldProcess("$($eligible.Count) custom detection(s)", 'Deploy to Microsoft Defender XDR')) {
                        $deployParams = @{ GraphEndpoint = $GraphEndpoint }
                        if ($PSBoundParameters.ContainsKey('AccessToken')) { $deployParams['AccessToken'] = $AccessToken }
                        if ($Update) { $deployParams['Update'] = $true }
                        if ($DeployDisabled) { $deployParams['Disabled'] = $true }
                        # -Force is forwarded, not forced: without it every rule still gets
                        # New-XDRCustomDetection's own high-impact confirmation, which is
                        # the last barrier between a typo and a tenant.
                        if ($Force) { $deployParams['Force'] = $true }

                        # Piped for the same reason as the report: -Detection is a scalar.
                        $deployed = @($eligible | ForEach-Object { $_.Detection } |
                                New-XDRCustomDetection @deployParams -ErrorAction Continue)

                        # Match results back by POSITION when the counts agree - the cmdlet
                        # emits one result per input, in order - and only fall back to the id
                        # when they do not. Keying on id alone gave two rules that share an
                        # id the same deploy status, one of them wrong.
                        $byIndex = $deployed.Count -eq $eligible.Count
                        $byId = @{}
                        foreach ($deployment in $deployed) {
                            if ($deployment.Id -and -not $byId.ContainsKey([string]$deployment.Id)) { $byId[[string]$deployment.Id] = $deployment }
                        }
                        for ($i = 0; $i -lt $eligible.Count; $i++) {
                            $result = $eligible[$i]
                            $key = [string]$result.Id
                            $deployment = if ($byIndex) { $deployed[$i] } elseif ($key -and $byId.ContainsKey($key)) { $byId[$key] } else { $null }
                            if ($deployment) {
                                $result.DeployStatus = $deployment.Status
                                $result.DeployError = $deployment.Error
                                # ServiceMessage is what a table shows; DeployError keeps the whole response.
                                $result.DeployServiceMessage = if ($deployment.PSObject.Properties['ServiceMessage']) {
                                    $deployment.ServiceMessage
                                } else {
                                    Get-S2XServiceMessage -Message $deployment.Error
                                }
                            } else {
                                $result.DeployStatus = 'Failed'
                                $result.DeployError = 'The deployment returned no result for this rule.'
                                $result.DeployServiceMessage = $result.DeployError
                            }
                        }
                    } else {
                        foreach ($result in $eligible) { $result.DeployStatus = 'WhatIf' }
                    }

                    $summary['Deployed'] = @($results | Where-Object { $_.DeployStatus -eq 'Created' }).Count
                    $summary['Updated'] = @($results | Where-Object { $_.DeployStatus -eq 'Updated' }).Count
                    $summary['DeploySkipped'] = @($results | Where-Object { $_.DeployStatus -eq 'Skipped' }).Count
                    $summary['DeployFailed'] = @($results | Where-Object { $_.DeployStatus -in @('Failed', 'Conflict') }).Count
                }
            } catch {
                Write-Error "The deployment stage failed: $($_.Exception.Message)"
            }
        }

        # ---- Stage 7: hand back one summary ----------------------------------
        if (-not $PassThru) {
            foreach ($result in $results) { $result.PSObject.Properties.Remove('Detection') }
        }

        $stopwatch.Stop()
        $summary['Duration'] = $stopwatch.Elapsed
        $summary['Results'] = $results
        [PSCustomObject]$summary
    }
}
