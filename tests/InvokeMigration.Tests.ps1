Describe 'Invoke-SentinelToXDRMigration' {

    BeforeAll {
        $ModulePath = Split-Path -Path $PSScriptRoot -Parent
        $ModulePath = Join-Path -Path $ModulePath -ChildPath 'src' | Join-Path -ChildPath 'SentinelToXDR.psd1'
        Import-Module -Name $ModulePath -Force

        $script:TestRoot = Join-Path ([System.IO.Path]::GetTempPath()) "s2x-migrate-$([System.Guid]::NewGuid())"
        $script:RuleRoot = Join-Path $script:TestRoot 'rules'
        New-Item -ItemType Directory -Path $script:RuleRoot -Force | Out-Null

        function New-TestFile {
            param([string]$Name, [string]$Content)
            $path = Join-Path $script:RuleRoot $Name
            Set-Content -LiteralPath $path -Value $Content -Encoding utf8NoBOM
            return $path
        }

        # One rule per verdict, so a single folder exercises the whole eligibility ladder.
        # Same fixtures as MigrationReadiness.Tests.ps1: if the verdicts ever move, both
        # files fail together and the cause is obvious.
        New-TestFile -Name 'ready.yaml' -Content @'
id: 11111111-1111-1111-1111-111111111111
name: Clean Defender Rule
description: Runs entirely on Defender data.
severity: High
kind: Scheduled
queryFrequency: PT1H
queryPeriod: PT1H
tactics:
  - Execution
relevantTechniques:
  - T1059
query: |
  DeviceProcessEvents
  | where FileName == "powershell.exe"
entityMappings:
  - entityType: Host
    fieldMappings:
      - identifier: HostName
        columnName: DeviceName
'@ | Out-Null

        New-TestFile -Name 'review.yaml' -Content @'
id: 22222222-2222-2222-2222-222222222222
name: Sentinel Tier Rule
description: Runs on Sentinel-tier data.
severity: Medium
kind: Scheduled
queryFrequency: PT1H
queryPeriod: PT1H
tactics:
  - Execution
relevantTechniques:
  - T1059
query: |
  SecurityEvent
  | where EventID == 4688
entityMappings:
  - entityType: Host
    fieldMappings:
      - identifier: HostName
        columnName: Computer
'@ | Out-Null

        New-TestFile -Name 'needswork.yaml' -Content @'
id: 33333333-3333-3333-3333-333333333333
name: Lossy Rule
description: Loses behaviour on migration.
severity: High
kind: Scheduled
queryFrequency: PT1H
queryPeriod: PT1H
suppressionEnabled: true
suppressionDuration: PT5H
tactics:
  - Impact
relevantTechniques:
  - T1486
query: |
  DeviceEvents
  | where ActionType == "Something"
eventGroupingSettings:
  aggregationKind: AlertPerResult
entityMappings:
  - entityType: IoTDevice
    fieldMappings:
      - identifier: DeviceId
        columnName: DeviceId
'@ | Out-Null

        New-TestFile -Name 'blocked.json' -Content @'
{
  "type": "Microsoft.SecurityInsights/alertRules",
  "kind": "Fusion",
  "properties": { "displayName": "Fusion Rule", "enabled": true }
}
'@ | Out-Null

        function New-OutFolder {
            $path = Join-Path $script:TestRoot ([System.Guid]::NewGuid().ToString('N'))
            return $path
        }
    }

    AfterAll {
        if ($script:TestRoot -and (Test-Path $script:TestRoot)) {
            Remove-Item -Path $script:TestRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    BeforeEach {
        # Only the two stages that touch a tenant are mocked. Reading, assessing, reporting
        # and exporting run for real against temp files — they are fast, and they are
        # precisely the composition this cmdlet exists to get right, so mocking them would
        # test nothing but the mocks.
        Mock -ModuleName SentinelToXDR -CommandName Get-SentinelToXDRContext -MockWith {
            [PSCustomObject]@{ CanManageDetections = $true; CanValidateQueries = $true }
        }
        Mock -ModuleName SentinelToXDR -CommandName New-XDRCustomDetection -MockWith {
            [PSCustomObject]@{
                PSTypeName = 'SentinelToXDR.DeploymentResult'
                Id = [string]$Detection.Rule.id; RuleName = [string]$Detection.RuleName
                Status = 'Created'; Method = 'POST'; Error = $null
            }
        }
        Mock -ModuleName SentinelToXDR -CommandName Test-XDRDetectionQuery -MockWith {
            [PSCustomObject]@{
                PSTypeName = 'SentinelToXDR.QueryValidationResult'
                RuleName = [string]$Detection.RuleName; Id = [string]$Detection.Id
                QueryValid = $true; FailureKind = $null; Error = $null
            }
        }
        # The backstop. If any safety test is wrong, this turns a silent tenant write into
        # a loud test failure.
        Mock -ModuleName SentinelToXDR -CommandName Invoke-S2XRestRequest -MockWith {
            throw 'A test reached the network. No test may make a real request.'
        }
    }

    Context 'Public surface' {

        It 'Should be exported by the module' {
            (Get-Command Invoke-SentinelToXDRMigration -ErrorAction SilentlyContinue).CommandType |
                Should -Be 'Function'
        }

        It 'Should support -WhatIf and -Confirm' {
            $command = Get-Command Invoke-SentinelToXDRMigration
            $command.Parameters.Keys | Should -Contain 'WhatIf'
            $command.Parameters.Keys | Should -Contain 'Confirm'
        }

        It 'Should make -Deploy a switch, so no value can turn it on by accident' {
            (Get-Command Invoke-SentinelToXDRMigration).Parameters['Deploy'].ParameterType |
                Should -Be ([switch])
        }

        It 'Should refuse -DeployVerdict Blocked at parameter binding' {
            # A rule that cannot become a custom detection must not be expressible as a
            # deployment target. This is the guard; if it regresses to a runtime check the
            # test still passes only if the throw survives.
            { Invoke-SentinelToXDRMigration -Path $script:RuleRoot -Deploy -DeployVerdict 'Blocked' } |
                Should -Throw
        }

        It 'Should default -DeployVerdict to Review' {
            (Get-Command Invoke-SentinelToXDRMigration).Parameters['DeployVerdict'].Attributes.Where{
                $_ -is [System.Management.Automation.ValidateSetAttribute]
            }.ValidValues | Should -Be @('Ready', 'Review', 'NeedsWork')
        }
    }

    Context 'Assessment and reporting' {

        It 'Should emit exactly one summary object' {
            $result = @(Invoke-SentinelToXDRMigration -Path $script:RuleRoot -WarningAction SilentlyContinue)
            $result.Count | Should -Be 1
            $result[0].PSObject.TypeNames | Should -Contain 'SentinelToXDR.MigrationSummary'
        }

        It 'Should count every verdict across the folder' {
            $summary = Invoke-SentinelToXDRMigration -Path $script:RuleRoot -WarningAction SilentlyContinue
            $summary.RuleCount | Should -Be 4
            $summary.Assessed  | Should -Be 4
            $summary.Ready     | Should -Be 1
            $summary.Review    | Should -Be 1
            $summary.NeedsWork | Should -Be 1
            $summary.Blocked   | Should -Be 1
        }

        It 'Should write the report when -ReportPath is given' {
            $path = Join-Path (New-OutFolder) 'report.html'
            $summary = Invoke-SentinelToXDRMigration -Path $script:RuleRoot -ReportPath $path -WarningAction SilentlyContinue
            Test-Path -LiteralPath $path | Should -BeTrue
            $summary.ReportPath | Should -Be $path
        }

        It 'Should say why a rule is blocked, not just that it is' {
            # The whole point of the report: 'Cannot be migrated' is a label, not an
            # answer. Every format must carry the diagnostic Reason, or the reader has to
            # re-run the tool to learn which rule kind blocked them.
            $folder = New-OutFolder
            foreach ($extension in @('html', 'md', 'csv')) {
                $path = Join-Path $folder "report.$extension"
                Invoke-SentinelToXDRMigration -Path $script:RuleRoot -ReportPath $path -WarningAction SilentlyContinue | Out-Null
                # No quotes in the pattern: the HTML format escapes them, the other two do not.
                (Get-Content -LiteralPath $path -Raw) | Should -Match 'Fusion is a Microsoft-managed'
            }
        }

        It 'Should give every finding it shows an explanation' {
            # The report's contract: what it SHOWS and what it EXPLAINS are the same set.
            # A bullet with no reason underneath sends the reader back to the tool.
            $path = Join-Path (New-OutFolder) 'report.html'
            Invoke-SentinelToXDRMigration -Path $script:RuleRoot -ReportPath $path -WarningAction SilentlyContinue | Out-Null
            $html = Get-Content -LiteralPath $path -Raw

            # The NeedsWork fixture drops a suppression window; that is a Medium/High
            # finding whose reason must reach the page, not just its label.
            $html | Should -Match 'suppression'
            $html | Should -Match 'IoTDevice'
        }

        It 'Should report a tenant prerequisite once, not on every row' {
            $path = Join-Path (New-OutFolder) 'report.html'
            Invoke-SentinelToXDRMigration -Path $script:RuleRoot -ReportPath $path -WarningAction SilentlyContinue | Out-Null
            $html = Get-Content -LiteralPath $path -Raw

            $html | Should -Match 'Tenant prerequisites'
            # Once in the panel, and nowhere in the per-rule column.
            ([regex]::Matches($html, 'Needs Microsoft Sentinel data available in the Defender portal')).Count |
                Should -Be 1
        }

        It 'Should not call a rule clean when it is only waiting on the prerequisite' {
            # 'Nothing to review' on a rule that still needs Sentinel data in the portal
            # reads as 'ready to deploy', which is the opposite of true.
            $path = Join-Path (New-OutFolder) 'report.html'
            Invoke-SentinelToXDRMigration -Path $script:RuleRoot -ReportPath $path -WarningAction SilentlyContinue | Out-Null
            (Get-Content -LiteralPath $path -Raw) | Should -Match 'only the tenant prerequisite above'
        }

        It 'Should give every report format a changes-required column' {
            $folder = New-OutFolder
            foreach ($extension in @('html', 'md', 'csv')) {
                $path = Join-Path $folder "changes.$extension"
                Invoke-SentinelToXDRMigration -Path $script:RuleRoot -ReportPath $path -WarningAction SilentlyContinue | Out-Null
                # The NeedsWork fixture drops a suppression window; the remedy for that is
                # to reduce noise in the query, and it has to reach the page.
                (Get-Content -LiteralPath $path -Raw) | Should -Match 'no per-rule suppression'
            }
        }

        It 'Should write no report when -ReportPath is omitted' {
            $summary = Invoke-SentinelToXDRMigration -Path $script:RuleRoot -WarningAction SilentlyContinue
            $summary.ReportPath | Should -BeNullOrEmpty
        }

        It 'Should honour an explicit -ReportFormat over the file extension' {
            $path = Join-Path (New-OutFolder) 'report.html'
            Invoke-SentinelToXDRMigration -Path $script:RuleRoot -ReportPath $path -ReportFormat 'Csv' -WarningAction SilentlyContinue | Out-Null
            (Get-Content -LiteralPath $path -Raw) | Should -Match '"RuleName"'
        }

        It 'Should drop the Detection from the rows unless -PassThru' {
            $summary = Invoke-SentinelToXDRMigration -Path $script:RuleRoot -WarningAction SilentlyContinue
            $summary.Results[0].PSObject.Properties['Detection'] | Should -BeNullOrEmpty

            $withDetection = Invoke-SentinelToXDRMigration -Path $script:RuleRoot -PassThru -WarningAction SilentlyContinue
            $withDetection.Results[0].PSObject.Properties['Detection'] | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Export' {

        It 'Should export every convertible rule and skip the blocked one' {
            $folder = New-OutFolder
            $summary = Invoke-SentinelToXDRMigration -Path $script:RuleRoot -OutputFolder $folder -WarningAction SilentlyContinue
            $summary.Exported | Should -Be 3
            @(Get-ChildItem -Path $folder -Filter '*.yaml').Count | Should -Be 3
            @(Get-ChildItem -Path $folder -Filter '*.json').Count | Should -Be 3
        }

        It 'Should write nothing to disk when -OutputFolder is omitted' {
            # Guards against inheriting ConvertTo-XDRCustomDetection's temp-folder default:
            # an assessment must never leave files behind.
            $before = @(Get-ChildItem -Path $script:TestRoot -Recurse -File).Count
            $summary = Invoke-SentinelToXDRMigration -Path $script:RuleRoot -WarningAction SilentlyContinue
            $summary.ExportFolder | Should -BeNullOrEmpty
            @(Get-ChildItem -Path $script:TestRoot -Recurse -File).Count | Should -Be $before
        }
    }

    Context 'Deployment safety' {

        It 'Should never deploy without -Deploy' {
            Invoke-SentinelToXDRMigration -Path $script:RuleRoot -WarningAction SilentlyContinue | Out-Null
            Should -Invoke -ModuleName SentinelToXDR -CommandName New-XDRCustomDetection -Times 0 -Exactly
        }

        It 'Should send nothing under -WhatIf and mark the eligible rows WhatIf' {
            $summary = Invoke-SentinelToXDRMigration -Path $script:RuleRoot -Deploy -WhatIf -WarningAction SilentlyContinue
            Should -Invoke -ModuleName SentinelToXDR -CommandName New-XDRCustomDetection -Times 0 -Exactly
            $summary.Deployed | Should -Be 0
            @($summary.Results | Where-Object { $_.DeployStatus -eq 'WhatIf' }).Count | Should -Be 2
        }

        It 'Should never hand a blocked rule to the deployment cmdlet' {
            Invoke-SentinelToXDRMigration -Path $script:RuleRoot -Deploy -Force -WarningAction SilentlyContinue | Out-Null
            Should -Invoke -ModuleName SentinelToXDR -CommandName New-XDRCustomDetection -Times 0 -Exactly `
                -ParameterFilter { $Detection.RuleName -eq 'Fusion Rule' }
        }

        It 'Should hold back NeedsWork at the default verdict threshold' {
            $summary = Invoke-SentinelToXDRMigration -Path $script:RuleRoot -Deploy -Force -WarningAction SilentlyContinue
            $summary.Deployed | Should -Be 2
            ($summary.Results | Where-Object { $_.RuleName -eq 'Lossy Rule' }).DeployStatus | Should -Be 'Skipped'
        }

        It 'Should deploy NeedsWork only when explicitly asked for' {
            $summary = Invoke-SentinelToXDRMigration -Path $script:RuleRoot -Deploy -DeployVerdict 'NeedsWork' -Force -WarningAction SilentlyContinue
            $summary.Deployed | Should -Be 3
            ($summary.Results | Where-Object { $_.RuleName -eq 'Lossy Rule' }).DeployStatus | Should -Be 'Created'
        }

        It 'Should deploy only Ready at -DeployVerdict Ready' {
            $summary = Invoke-SentinelToXDRMigration -Path $script:RuleRoot -Deploy -DeployVerdict 'Ready' -Force -WarningAction SilentlyContinue
            $summary.Deployed | Should -Be 1
        }

        It 'Should refuse to deploy without the scope, and still return the assessment' {
            Mock -ModuleName SentinelToXDR -CommandName Get-SentinelToXDRContext -MockWith {
                [PSCustomObject]@{ CanManageDetections = $false; CanValidateQueries = $false }
            }
            $path = Join-Path (New-OutFolder) 'report.html'
            $summary = Invoke-SentinelToXDRMigration -Path $script:RuleRoot -ReportPath $path -Deploy -Force `
                -WarningAction SilentlyContinue -ErrorAction SilentlyContinue

            Should -Invoke -ModuleName SentinelToXDR -CommandName New-XDRCustomDetection -Times 0 -Exactly
            # The point: an unauthorised deploy leg must not cost the user the work that
            # already succeeded.
            $summary.Assessed | Should -Be 4
            Test-Path -LiteralPath $path | Should -BeTrue
        }

        It 'Should proceed with a warning when the token scopes cannot be read' {
            # $null is "opaque cached token, cannot tell" — not "no". Treating it as no
            # would break every Connect-SentinelToXDR -GraphAccessToken caller.
            Mock -ModuleName SentinelToXDR -CommandName Get-SentinelToXDRContext -MockWith {
                [PSCustomObject]@{ CanManageDetections = $null; CanValidateQueries = $null }
            }
            $warnings = @()
            $summary = Invoke-SentinelToXDRMigration -Path $script:RuleRoot -Deploy -Force `
                -WarningVariable warnings -WarningAction SilentlyContinue
            $summary.Deployed | Should -Be 2
            ($warnings -join ' ') | Should -Match 'CustomDetection.ReadWrite.All'
        }
    }

    Context 'Query validation' {

        It 'Should record a validated query and count it' {
            $summary = Invoke-SentinelToXDRMigration -Path $script:RuleRoot -ValidateQuery -WarningAction SilentlyContinue
            $summary.QueriesValidated | Should -Be 3
            $summary.QueriesFailed | Should -Be 0
        }

        It 'Should hold back a rule whose query failed when -RequireQueryValid is set' {
            Mock -ModuleName SentinelToXDR -CommandName Test-XDRDetectionQuery -MockWith {
                $clean = $Detection.RuleName -eq 'Clean Defender Rule'
                [PSCustomObject]@{
                    PSTypeName = 'SentinelToXDR.QueryValidationResult'
                    RuleName = [string]$Detection.RuleName; Id = [string]$Detection.Id
                    QueryValid = $clean
                    FailureKind = if ($clean) { $null } else { 'WatchlistDependency' }
                    Error = $null
                }
            }
            $summary = Invoke-SentinelToXDRMigration -Path $script:RuleRoot -ValidateQuery -RequireQueryValid `
                -Deploy -Force -WarningAction SilentlyContinue
            $summary.QueriesFailed | Should -Be 2
            $summary.Deployed | Should -Be 1
        }

        It 'Should leave QueryValid null when a query was never attempted' {
            # NotAttempted is the circuit-breaker after an auth failure. "We never asked"
            # must not be recorded as "the query is broken".
            Mock -ModuleName SentinelToXDR -CommandName Test-XDRDetectionQuery -MockWith {
                [PSCustomObject]@{
                    PSTypeName = 'SentinelToXDR.QueryValidationResult'
                    RuleName = [string]$Detection.RuleName; Id = [string]$Detection.Id
                    QueryValid = $false; FailureKind = 'NotAttempted'; Error = 'Skipped.'
                }
            }
            $summary = Invoke-SentinelToXDRMigration -Path $script:RuleRoot -ValidateQuery -WarningAction SilentlyContinue
            $summary.QueriesFailed | Should -Be 0
            @($summary.Results | Where-Object { $null -eq $_.QueryValid }).Count | Should -Be 4
        }

        It 'Should skip validation with a warning, not an error, when the scope is missing' {
            Mock -ModuleName SentinelToXDR -CommandName Get-SentinelToXDRContext -MockWith {
                [PSCustomObject]@{ CanManageDetections = $true; CanValidateQueries = $false }
            }
            $summary = Invoke-SentinelToXDRMigration -Path $script:RuleRoot -ValidateQuery -WarningAction SilentlyContinue
            Should -Invoke -ModuleName SentinelToXDR -CommandName Test-XDRDetectionQuery -Times 0 -Exactly
            $summary.Assessed | Should -Be 4
        }
    }

    Context 'Resilience' {

        It 'Should assess the good rules and still report when a file is unparseable' {
            $junk = Join-Path $script:RuleRoot 'broken.json'
            Set-Content -LiteralPath $junk -Value '{ this is not json' -Encoding utf8NoBOM
            try {
                $path = Join-Path (New-OutFolder) 'report.html'
                $summary = Invoke-SentinelToXDRMigration -Path $script:RuleRoot -ReportPath $path `
                    -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
                $summary.Assessed | Should -Be 4
                Test-Path -LiteralPath $path | Should -BeTrue
            } finally {
                Remove-Item -LiteralPath $junk -Force -ErrorAction SilentlyContinue
            }
        }

        It 'Should keep going when one rule fails to deploy' {
            Mock -ModuleName SentinelToXDR -CommandName New-XDRCustomDetection -MockWith {
                $failed = $Detection.RuleName -eq 'Sentinel Tier Rule'
                [PSCustomObject]@{
                    PSTypeName = 'SentinelToXDR.DeploymentResult'
                    Id = [string]$Detection.Rule.id; RuleName = [string]$Detection.RuleName
                    Status = if ($failed) { 'Failed' } else { 'Created' }
                    Method = 'POST'
                    Error = if ($failed) { 'POST failed with HTTP 400. Response body: {"error":{"message":"Unknown function: ''_X''."}}' } else { $null }
                    ServiceMessage = if ($failed) { "Unknown function: '_X'." } else { '' }
                }
            }
            $summary = Invoke-SentinelToXDRMigration -Path $script:RuleRoot -Deploy -Force -WarningAction SilentlyContinue
            $summary.Deployed | Should -Be 1
            $summary.DeployFailed | Should -Be 1

            $row = $summary.Results | Where-Object RuleName -eq 'Sentinel Tier Rule'
            $row.DeployServiceMessage | Should -Be "Unknown function: '_X'." -Because 'a table shows the reason, not the status line'
            $row.DeployError          | Should -Match 'HTTP 400'
            ($summary.Results | Where-Object DeployStatus -eq 'Created').DeployServiceMessage | Should -Be ''
        }

        It 'Should return an empty summary rather than throw when nothing is found' {
            $empty = Join-Path $script:TestRoot 'empty'
            New-Item -ItemType Directory -Path $empty -Force | Out-Null
            $summary = Invoke-SentinelToXDRMigration -Path $empty -WarningAction SilentlyContinue
            $summary.RuleCount | Should -Be 0
            $summary.Assessed | Should -Be 0
        }
    }
}
