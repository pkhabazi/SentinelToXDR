function Get-SentinelAnalyticsRule {
    <#
    .SYNOPSIS
        Reads Microsoft Sentinel analytics rules from files, a repository tree, or a live workspace.

    .DESCRIPTION
        The single entry point for getting rules INTO the module. Every supported source
        produces the same normalized rule object, so the conversion, export and deployment
        cmdlets never need to know where a rule came from.

        Sources:

          -Path       A file, a folder, or a whole repository tree. Handles community
                      content-hub YAML, ARM resources, ARM deployment templates (including
                      Content Hub mainTemplate.json, where rules are nested several levels
                      deep), REST list responses, and bare arrays of rules. Point it at a
                      clone of Azure/Azure-Sentinel and it reads the lot.

          -Workspace  A live Sentinel workspace, read over the Azure Resource Manager API.
                      Requires a token: pass -AccessToken, or sign in with Connect-AzAccount
                      and the module picks the context up.

        Rules of a kind that cannot become a custom detection (Fusion, MLBehaviorAnalytics,
        ThreatIntelligence, MicrosoftSecurityIncidentCreation, Anomaly) are returned like
        any other rule. They are not filtered out here on purpose: the point of an
        assessment is to see them and know why they are blocked. Conversion is where they
        are rejected, with a reason.

    .PARAMETER Path
        File or folder to read. A folder is searched for *.yaml, *.yml and *.json.
        Accepts pipeline input by value and by property name, so
        'Get-ChildItem *.yaml | Get-SentinelAnalyticsRule' works.

    .PARAMETER Recurse
        Search subfolders when -Path is a folder.

    .PARAMETER Filter
        Restrict which files are read when -Path is a folder. Defaults to all supported
        extensions.

    .PARAMETER SubscriptionId
        Azure subscription holding the Sentinel workspace.

    .PARAMETER ResourceGroupName
        Resource group holding the Log Analytics workspace.

    .PARAMETER WorkspaceName
        Log Analytics workspace name that Sentinel runs on.

    .PARAMETER AccessToken
        Bearer token for Azure Resource Manager. Optional when an Az.Accounts context is
        signed in. Accepts a SecureString.

    .PARAMETER ApiVersion
        Sentinel ARM API version. Defaults to a version known to return all rule kinds.

    .EXAMPLE
        Get-SentinelAnalyticsRule -Path ./Detections -Recurse

        Reads every analytics rule under a folder of community YAML files.

    .EXAMPLE
        Get-SentinelAnalyticsRule -Path ~/repos/Azure-Sentinel/Solutions -Recurse |
            Where-Object Kind -eq 'Scheduled'

        Reads the whole Content Hub solutions tree and keeps the scheduled rules.

    .EXAMPLE
        Get-SentinelAnalyticsRule -SubscriptionId $sub -ResourceGroupName rg-soc -WorkspaceName law-soc

        Reads every analytics rule from a live workspace using the current Az sign-in.

    .EXAMPLE
        Get-SentinelAnalyticsRule -Path ./rules | ConvertTo-XDRCustomDetection -Force

        The normal pipeline: read, then convert.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Path')]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Path', Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
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
        [object]$AccessToken,

        [Parameter(ParameterSetName = 'Workspace')]
        [string]$ApiVersion = '2024-09-01'
    )

    begin {
        $seenFiles = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    }

    process {
        if ($PSCmdlet.ParameterSetName -eq 'Workspace') {
            $uri = ("https://management.azure.com/subscriptions/{0}/resourceGroups/{1}" +
                    "/providers/Microsoft.OperationalInsights/workspaces/{2}" +
                    "/providers/Microsoft.SecurityInsights/alertRules?api-version={3}") -f
                    $SubscriptionId, $ResourceGroupName, $WorkspaceName, $ApiVersion

            Write-Verbose "Reading analytics rules from $uri"
            $count = 0
            foreach ($rule in (Invoke-S2XRestRequest -Uri $uri -Audience 'Arm' -AccessToken $AccessToken -Paginate)) {
                if ($null -eq $rule) { continue }
                $resourceId = if ($rule.PSObject.Properties['id']) { [string]$rule.id } else { '' }
                ConvertTo-NormalizedSentinelRule -InputObject $rule -SourceFormat 'LiveApi' -SourcePath $resourceId
                $count++
            }
            Write-Verbose "Read $count rule(s) from workspace '$WorkspaceName'."
            return
        }

        foreach ($item in $Path) {
            # -LiteralPath throughout: community rule filenames contain [ and ], which
            # PowerShell treats as wildcard character classes on -Path. Roughly a dozen
            # rules in the Azure-Sentinel repo are named '[Entra ID] ...' and would
            # otherwise fail to open.
            if (-not (Test-Path -LiteralPath $item)) {
                Write-Error "Path '$item' was not found."
                continue
            }

            $files = if (Test-Path -LiteralPath $item -PathType Container) {
                # -Include on Get-ChildItem only applies with -Recurse or a wildcard path,
                # which silently returns nothing for a plain folder. Filter in code instead.
                $searchParams = @{ LiteralPath = $item; File = $true }
                if ($Recurse) { $searchParams['Recurse'] = $true }
                @(Get-ChildItem @searchParams | Where-Object {
                    $name = $_.Name
                    foreach ($pattern in $Filter) {
                        if ($name -like $pattern) { return $true }
                    }
                    return $false
                }) | Sort-Object FullName
            } else {
                @(Get-Item -LiteralPath $item)
            }

            # A folder holds far more non-rule content than rules (workbooks, playbooks,
            # parsers, connectors). Tell the importer it is scanning so it reports those
            # through Write-Verbose instead of warning about every one.
            $isScan = Test-Path -LiteralPath $item -PathType Container

            $scanned = 0
            $emitted = 0
            foreach ($file in $files) {
                if ($file.Extension -notin '.yaml', '.yml', '.json') { continue }
                # A folder scan plus an explicit file can name the same path twice.
                if (-not $seenFiles.Add($file.FullName)) { continue }
                $scanned++
                foreach ($rule in (Import-SentinelRuleFile -Path $file.FullName -Scanning:$isScan)) {
                    $emitted++
                    $rule
                }
            }

            # A scan that looked at files and found no rule in any of them is worth one
            # warning with the count, because the per-file reasons went to Verbose. A user
            # who pointed this at the folder of converted detections it had just written
            # got 'nothing to migrate' and no clue why (2026-09-16).
            if ($isScan -and $scanned -gt 0 -and $emitted -eq 0) {
                $sample = @($files | Where-Object { $_.Extension -in '.yaml', '.yml', '.json' } | Select-Object -First 1)
                $hint = ''
                if ($sample.Count -gt 0) {
                    $probe = $null
                    try {
                        $raw = Get-Content -LiteralPath $sample[0].FullName -Raw
                        $probe = if ($sample[0].Extension -eq '.json') { $raw | ConvertFrom-Json -ErrorAction Stop } else { ConvertFrom-Yaml -Yaml $raw -ErrorAction Stop }
                    } catch { $probe = $null }
                    $hint = ' ' + (Get-NotARuleMessage -Path $sample[0].FullName -Candidate $probe)
                }
                Write-Warning ("Scanned $scanned file(s) under '$item' and none contains a Sentinel analytics rule. " +
                    "Run with -Verbose to see why each file was skipped. First file:$hint")
            }
        }
    }
}
