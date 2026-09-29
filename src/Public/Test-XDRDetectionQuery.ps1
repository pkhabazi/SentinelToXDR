function Test-XDRDetectionQuery {
    <#
    .SYNOPSIS
        Runs a converted detection's KQL against a tenant to prove it actually executes.

    .DESCRIPTION
        The readiness assessment reasons about a rule from its shape. This runs the query
        through advanced hunting (POST /security/runHuntingQuery) and finds out what the
        product thinks. It is the difference between "this should work" and "this works
        here".

        It is READ-ONLY: it creates no detection, changes nothing, and needs only
        ThreatHunting.Read.All. Safe to run against a production tenant.

        What it catches that static analysis cannot:

          - A Sentinel-tier table the tenant has not onboarded to the Defender portal. The
            assessment can only say "you will need this"; this says whether you have it.
          - Watchlists (`_GetWatchlist`), ASIM parsers (`_Im_*`, `ASim*`) and saved
            functions. These are the module's largest known blind spot: a rule using them
            over Defender tables is currently reported clean and would fail here.
          - Operators, functions or syntax the Defender query engine rejects.
          - Columns the query projects that do not exist in the target schema.

        Cost control matters: advanced hunting enforces a CPU quota per 15 minutes and a
        10-minute per-query timeout, and a large estate is a lot of queries. The default
        -Timespan of five minutes keeps each one cheap — the service applies whichever is
        shorter, the timespan or a time filter inside the query — and validation only needs
        the query to parse and resolve, not to return data. -DelayMilliseconds paces a batch.

    .PARAMETER Detection
        A detection from ConvertTo-XDRCustomDetection -As Object, a readiness result from
        Test-XDRMigrationReadiness -PassThruDetection, or a raw Graph rule object. Accepts
        pipeline input.

    .PARAMETER Query
        A raw KQL string to validate, instead of a detection.

    .PARAMETER Timespan
        ISO 8601 interval to query over. Defaults to PT5M, which is enough to prove the
        query resolves while scanning almost nothing.

    .PARAMETER DelayMilliseconds
        Pause between queries, to stay inside the advanced hunting CPU quota on a large
        batch. Defaults to 250.

    .PARAMETER AccessToken
        Bearer token for Microsoft Graph, with ThreatHunting.Read.All.

    .PARAMETER GraphEndpoint
        Graph base URI. Defaults to the beta endpoint.

    .EXAMPLE
        Test-XDRMigrationReadiness -Path ./rules -Recurse -PassThruDetection |
            Test-XDRDetectionQuery

        Proves which of the assessed rules actually run in this tenant.

    .EXAMPLE
        Test-XDRMigrationReadiness -Path ./rules -Recurse -PassThruDetection |
            Where-Object Verdict -eq 'Ready' |
            Test-XDRDetectionQuery |
            Where-Object { -not $_.QueryValid }

        The important question: does anything the assessment called Ready fail for real?

    .EXAMPLE
        Test-XDRDetectionQuery -Query 'DeviceProcessEvents | take 1'

        Check one query.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Detection')]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Detection', ValueFromPipeline)]
        [PSObject]$Detection,

        [Parameter(Mandatory, ParameterSetName = 'Query')]
        [string]$Query,

        [Parameter()]
        [string]$Timespan = 'PT5M',

        [Parameter()]
        [int]$DelayMilliseconds = 250,

        [Parameter()]
        [AllowNull()]
        [object]$AccessToken,

        [Parameter()]
        [string]$GraphEndpoint = 'https://graph.microsoft.com/beta'
    )

    begin {
        $uri = "$($GraphEndpoint.TrimEnd('/'))/security/runHuntingQuery"

        # A permission or throttling failure is about the CALLER, not the rule, and it will
        # be identical for every rule that follows. Stop after the first one: fifteen
        # identical 403s teach nothing and still cost quota.
        #
        # A hashtable, not a plain variable: assigning to a variable inside the nested
        # function below would create a local copy and the flag would never reach the next
        # iteration. Mutating a shared object does.
        # Same reason 'First' lives here: the pacing flag is mutated from inside the nested
        # function too, so it has to be a property on a shared object rather than a variable.
        $state = @{ AuthFailureKind = $null; First = $true }

        # Classify the failure. The kind is what makes a batch result actionable: 200
        # rules failing on UnknownTable is one onboarding conversation, while 200 failing
        # on SyntaxError is a converter bug.
        function Get-FailureKind {
            param([string]$Message, [string]$QueryText = '')

            # The hunting endpoint answers a workspace() reference with nothing more than
            # 'The request had some invalid properties' (observed 2026-09-16). When the
            # service says that little, and the query carries a construct the offline scan
            # already knows cannot run here, name the construct rather than 'Other'.
            if ($Message -match '[Ii]nvalid properties' -and $QueryText -match '\bworkspace\s*\(') { return 'CrossWorkspaceDependency' }

            switch -Regex ($Message) {
                "[Ff]ailed to resolve (table or column|scalar|entity) expression" { return 'UnresolvedName' }
                "'?_GetWatchlist'?|[Ww]atchlist"                                  { return 'WatchlistDependency' }
                "\b_Im_\w+|\bASim\w+|imProcessCreate"                             { return 'AsimParserDependency' }
                "[Uu]nknown function|[Ff]unction .* (not found|does not exist)"    { return 'MissingFunction' }
                "[Ss]yntax error|[Pp]arse error|has the wrong number of arguments" { return 'SyntaxError' }
                "HTTP 429|[Tt]hrottl|[Qq]uota"                                     { return 'Throttled' }
                "HTTP 40[13]|[Ff]orbidden|[Uu]nauthorized"                         { return 'Permission' }
                "[Tt]imed out|[Tt]imeout"                                          { return 'Timeout' }
                default                                                            { return 'Other' }
            }
        }

        function Test-OneQuery {
            param([string]$QueryText, [string]$RuleName, [string]$RuleId)

            if ($state.AuthFailureKind) {
                return [PSCustomObject]@{
                    PSTypeName = 'SentinelToXDR.QueryValidationResult'
                    RuleName = $RuleName; Id = $RuleId; QueryValid = $false
                    FailureKind = 'NotAttempted'
                    ServiceMessage = ''
                    Error = "Skipped: an earlier query failed with $($state.AuthFailureKind). Fix that first."
                    ResultCount = 0; ElapsedMs = 0
                }
            }

            if ([string]::IsNullOrWhiteSpace($QueryText)) {
                return [PSCustomObject]@{
                    PSTypeName = 'SentinelToXDR.QueryValidationResult'
                    RuleName = $RuleName; Id = $RuleId; QueryValid = $false
                    FailureKind = 'NoQuery'; Error = 'The detection carries no query.'; ServiceMessage = ''
                    ResultCount = 0; ElapsedMs = 0
                }
            }

            # Pace the batch so a large estate does not trip the CPU quota.
            if (-not $state.First -and $DelayMilliseconds -gt 0) { Start-Sleep -Milliseconds $DelayMilliseconds }
            $state.First = $false

            $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
            try {
                $body = [ordered]@{ query = $QueryText; timespan = $Timespan }
                $response = Invoke-S2XRestRequest -Uri $uri -Method 'POST' -Body $body `
                    -Audience 'Graph' -AccessToken $AccessToken
                $stopwatch.Stop()

                [PSCustomObject]@{
                    PSTypeName = 'SentinelToXDR.QueryValidationResult'
                    RuleName = $RuleName; Id = $RuleId; QueryValid = $true
                    FailureKind = $null; Error = $null; ServiceMessage = ''
                    ResultCount = @($response.results).Count
                    ElapsedMs = [int]$stopwatch.ElapsedMilliseconds
                }
            } catch {
                $stopwatch.Stop()
                $message = $_.Exception.Message
                $kind = Get-FailureKind -Message $message -QueryText $QueryText
                # The service's own sentence, without the HTTP wrapper, so a table can show it.
                $serviceMessage = Get-S2XServiceMessage -Message $message

                if ($kind -in 'Permission', 'Throttled') {
                    $state.AuthFailureKind = $kind
                    $hint = if ($kind -eq 'Permission') {
                        "The token needs the ThreatHunting.Read.All scope and a role that grants advanced hunting access (Security Reader, Security Operator, Security Administrator, or a Defender XDR RBAC role). The remaining rules were not attempted."
                    } else {
                        "Advanced hunting is throttling this tenant. Wait for the quota window to reset and re-run, or raise -DelayMilliseconds. The remaining rules were not attempted."
                    }
                    Write-Error "Query validation stopped after the first failure. $hint`n`n$message"
                }

                [PSCustomObject]@{
                    PSTypeName = 'SentinelToXDR.QueryValidationResult'
                    RuleName = $RuleName; Id = $RuleId; QueryValid = $false
                    FailureKind = $kind
                    Error = $message
                    ServiceMessage = $serviceMessage
                    ResultCount = 0
                    ElapsedMs = [int]$stopwatch.ElapsedMilliseconds
                }
            }
        }
    }

    process {
        if ($PSCmdlet.ParameterSetName -eq 'Query') {
            Test-OneQuery -QueryText $Query -RuleName '<inline query>' -RuleId ''
            return
        }

        # Unwrap whichever shape arrived.
        $rule = $null
        $name = ''
        $id = ''

        if ($Detection.PSObject.TypeNames -contains 'SentinelToXDR.ReadinessResult') {
            if (-not $Detection.PSObject.Properties['Detection'] -or $null -eq $Detection.Detection) {
                Write-Warning ("Readiness result for '$($Detection.RuleName)' carries no detection. " +
                    "Re-run Test-XDRMigrationReadiness with -PassThruDetection.")
                return
            }
            $rule = $Detection.Detection.Rule
            $name = [string]$Detection.RuleName
            $id   = [string]$Detection.Id
        } elseif ($Detection.PSObject.TypeNames -contains 'SentinelToXDR.CustomDetection') {
            if ($Detection.Blocked) {
                Write-Verbose "Skipping '$($Detection.RuleName)': blocked during conversion, no query to run."
                return
            }
            $rule = $Detection.Rule
            $name = [string]$Detection.RuleName
            $id   = [string]$Detection.Id
        } else {
            $rule = $Detection
            $name = [string]$Detection.displayName
            $id   = [string]$Detection.id
        }

        if ($null -eq $rule) { return }
        Test-OneQuery -QueryText ([string]$rule.queryCondition.queryText) -RuleName $name -RuleId $id
    }
}
