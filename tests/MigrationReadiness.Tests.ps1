Describe 'Migration readiness assessment' {

    BeforeAll {
        $ModulePath = Split-Path -Path $PSScriptRoot -Parent
        $ModulePath = Join-Path -Path $ModulePath -ChildPath 'src' | Join-Path -ChildPath 'SentinelToXDR.psd1'
        Import-Module -Name $ModulePath -Force

        $script:TestRoot = Join-Path ([System.IO.Path]::GetTempPath()) "s2x-readiness-$([System.Guid]::NewGuid())"
        New-Item -ItemType Directory -Path $script:TestRoot -Force | Out-Null

        function New-TestFile {
            param([string]$Name, [string]$Content)
            $path = Join-Path $script:TestRoot $Name
            Set-Content -LiteralPath $path -Value $Content -Encoding utf8NoBOM
            return $path
        }

        # Ready: native Defender tables, one tactic, supported entities, nothing dropped.
        $script:ReadyRule = New-TestFile -Name 'ready.yaml' -Content @'
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
'@

        # Review: same, but on Sentinel-tier data (needs Sentinel data in the portal).
        $script:ReviewRule = New-TestFile -Name 'review.yaml' -Content @'
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
'@

        # NeedsWork: suppression dropped, grouping dropped, an unmappable entity.
        $script:NeedsWorkRule = New-TestFile -Name 'needswork.yaml' -Content @'
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
'@

        # Blocked: a rule kind with no query.
        $script:BlockedRule = New-TestFile -Name 'blocked.json' -Content @'
{
  "type": "Microsoft.SecurityInsights/alertRules",
  "kind": "Fusion",
  "properties": { "displayName": "Fusion Rule", "enabled": true }
}
'@
    }

    AfterAll {
        if ($script:TestRoot -and (Test-Path $script:TestRoot)) {
            Remove-Item -Path $script:TestRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    Context 'Every finding says what to change' {

        # The migration question is not only 'what did I lose' but 'what do I change to
        # make this work'. A finding that states the loss and stops leaves the reader with
        # the same problem they started with.
        It 'Should give every actionable classification a remedy' {
            $data = Import-PowerShellDataFile -Path (Join-Path (Split-Path $PSScriptRoot -Parent) 'src/Data/MigrationReadiness.psd1')
            foreach ($rule in ($data.Rules | Where-Object { $_.Impact -in 'Blocking', 'High', 'Medium' })) {
                $rule.Remedy | Should -Not -BeNullOrEmpty -Because "'$($rule.Summary)' must say what to change"
            }
        }

        It 'Should carry the remedy onto the finding, not just the data file' {
            $result = Test-XDRMigrationReadiness -Path $script:NeedsWorkRule -WarningAction SilentlyContinue
            $actionable = @($result.Findings | Where-Object { $_.Impact -in 'Blocking', 'High', 'Medium' })
            $actionable.Count | Should -BeGreaterThan 0
            foreach ($finding in $actionable) {
                $finding.Remedy | Should -Not -BeNullOrEmpty -Because "'$($finding.Summary)' reached a report without a remedy"
            }
        }

        It 'Should tell someone how to replace a dropped trigger threshold' {
            # The single most common finding in the Azure-Sentinel corpus (941 rules). If
            # any remedy has to be right, it is this one.
            $data = Import-PowerShellDataFile -Path (Join-Path (Split-Path $PSScriptRoot -Parent) 'src/Data/MigrationReadiness.psd1')
            $rule = $data.Rules | Where-Object { $_.Summary -match 'Trigger threshold dropped' }
            $rule.Remedy | Should -Match 'summarize'
            $rule.Remedy | Should -Match 'where'
        }
    }

    Context 'Special cases are named, not generalised' {

        It 'Should name the mixed-tier consequence rather than the generic tier note' {
            # The point of the assessment: a rule that mixes Defender and Sentinel tables
            # forfeits custom frequency for the WHOLE rule. Reporting that as "needs
            # Sentinel data in the portal" — the same sentence used for every Sentinel-tier
            # rule in the estate — throws away the finding that actually differs.
            # Its own folder: $script:TestRoot is counted by other tests, and a stray
            # fixture there fails them for reasons that have nothing to do with them.
            $mixedRoot = Join-Path $script:TestRoot 'mixed-tier'
            New-Item -ItemType Directory -Path $mixedRoot -Force | Out-Null
            $mixed = Join-Path $mixedRoot 'mixed.yaml'
            Set-Content -LiteralPath $mixed -Encoding utf8NoBOM -Value @'
id: 44444444-4444-4444-4444-444444444444
name: Mixed Tier Rule
description: Reads a Defender table and a Sentinel table.
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
  | where EventID == 4624
  | join kind=inner DeviceInfo on $left.Computer == $right.DeviceName
entityMappings:
  - entityType: Host
    fieldMappings:
      - identifier: HostName
        columnName: DeviceName
'@
            $result = Test-XDRMigrationReadiness -Path $mixed -WarningAction SilentlyContinue
            $result.DataTier | Should -Be 'Mixed'
            ($result.Headline -join ' ') | Should -Match 'custom run frequency is forfeited'
            $result.Headline | Should -Not -Contain 'Needs Microsoft Sentinel data available in the Defender portal'
        }

        It 'Should flag the estate-wide prerequisite as estate level, and the rule-specific one not' {
            $sentinelOnly = Test-XDRMigrationReadiness -Path $script:ReviewRule -WarningAction SilentlyContinue
            $estate = @($sentinelOnly.Findings | Where-Object { $_.EstateLevel })
            $estate.Count | Should -BeGreaterThan 0
            $estate[0].Summary | Should -Be 'Needs Microsoft Sentinel data available in the Defender portal'

            $needsWork = Test-XDRMigrationReadiness -Path $script:NeedsWorkRule -WarningAction SilentlyContinue
            @($needsWork.Findings | Where-Object { $_.EstateLevel }).Count | Should -Be 0
        }

        It 'Should keep the mixed-tier classification at Medium so no verdict silently moves' {
            # A mixed tier costs nothing when the rule's frequency already fits a supported
            # value. Grading it High would amber a whole estate for a cost it did not pay.
            $data = Import-PowerShellDataFile -Path (Join-Path (Split-Path $PSScriptRoot -Parent) 'src/Data/MigrationReadiness.psd1')
            $mixedRule = $data.Rules | Where-Object { $_.TargetValue -eq 'Mixed' } | Select-Object -First 1
            $mixedRule | Should -Not -BeNullOrEmpty
            $mixedRule.Impact | Should -Be 'Medium'
        }
    }

    Context 'Verdicts' {

        It 'Should call a clean Defender-data rule Ready' {
            $result = Test-XDRMigrationReadiness -Path $script:ReadyRule -WarningAction SilentlyContinue
            $result.Verdict | Should -Be 'Ready'
            $result.DataTier | Should -Be 'DefenderOnly'
        }

        It 'Should call a Sentinel-tier rule Review, not NeedsWork' {
            # Needing Sentinel data in the Defender portal is a tenant prerequisite checked
            # once, not per-rule work. Grading it higher would mark an entire estate amber.
            $result = Test-XDRMigrationReadiness -Path $script:ReviewRule -WarningAction SilentlyContinue
            $result.Verdict | Should -Be 'Review'
            $result.Headline | Should -Contain 'Needs Microsoft Sentinel data available in the Defender portal'
        }

        It 'Should call a rule that loses behaviour NeedsWork' {
            $result = Test-XDRMigrationReadiness -Path $script:NeedsWorkRule -WarningAction SilentlyContinue
            $result.Verdict | Should -Be 'NeedsWork'
            $result.HighCount | Should -BeGreaterThan 0
        }

        It 'Should name what needs a decision' {
            $result = Test-XDRMigrationReadiness -Path $script:NeedsWorkRule -WarningAction SilentlyContinue
            $result.Headline | Should -Contain 'Alert suppression window dropped'
            $result.Headline | Should -Contain 'An entity is missing from the alert: the type has no equivalent in Defender XDR'
        }

        It 'Should call a non-convertible rule Blocked' {
            $result = Test-XDRMigrationReadiness -Path $script:BlockedRule -WarningAction SilentlyContinue
            $result.Verdict | Should -Be 'Blocked'
            $result.BlockingCount | Should -Be 1
        }

        It 'Should score worse as the work grows' {
            $ready     = Test-XDRMigrationReadiness -Path $script:ReadyRule -WarningAction SilentlyContinue
            $review    = Test-XDRMigrationReadiness -Path $script:ReviewRule -WarningAction SilentlyContinue
            $needsWork = Test-XDRMigrationReadiness -Path $script:NeedsWorkRule -WarningAction SilentlyContinue
            $blocked   = Test-XDRMigrationReadiness -Path $script:BlockedRule -WarningAction SilentlyContinue

            $ready.Score  | Should -BeGreaterThan $review.Score
            $review.Score | Should -BeGreaterThan $needsWork.Score
            $blocked.Score | Should -Be 0
        }

        It 'Should NOT let estate-wide informational findings drive a verdict' {
            # 'Reflect custom detections in MITRE ATT&CK page' and 'confirm the technique
            # ids' fire on nearly every rule with MITRE metadata. If either counted, every
            # rule would come out amber and the report would say nothing.
            $result = Test-XDRMigrationReadiness -Path $script:ReadyRule -WarningAction SilentlyContinue
            $result.Verdict | Should -Be 'Ready'
            $noise = @($result.Findings | Where-Object {
                $_.Capability -in @('Reflect custom detections in MITRE ATT&CK page',
                                    'Support full list of MITRE techniques and subtechniques')
            })
            $noise.Count | Should -BeGreaterThan 0 -Because 'the diagnostics are still recorded'
            foreach ($finding in $noise) {
                $finding.Impact | Should -Be 'Low' -Because 'they say nothing about this rule in particular'
            }
        }
    }

    Context 'Pipeline' {

        It 'Should assess a folder of rules' {
            $results = @(Test-XDRMigrationReadiness -Path $script:TestRoot -WarningAction SilentlyContinue)
            $results.Count | Should -Be 4
            @($results | Where-Object Verdict -eq 'Ready').Count     | Should -Be 1
            @($results | Where-Object Verdict -eq 'Review').Count    | Should -Be 1
            @($results | Where-Object Verdict -eq 'NeedsWork').Count | Should -Be 1
            @($results | Where-Object Verdict -eq 'Blocked').Count   | Should -Be 1
        }

        It 'Should accept rules from Get-SentinelAnalyticsRule' {
            $results = @(Get-SentinelAnalyticsRule -Path $script:ReadyRule |
                Test-XDRMigrationReadiness -WarningAction SilentlyContinue)
            $results.Count | Should -Be 1
            $results[0].Verdict | Should -Be 'Ready'
        }

        It 'Should accept detections already converted, without converting twice' {
            $results = @(Get-SentinelAnalyticsRule -Path $script:ReadyRule |
                ConvertTo-XDRCustomDetection -As Object -Force -WarningAction SilentlyContinue |
                Test-XDRMigrationReadiness)
            $results.Count | Should -Be 1
            $results[0].Verdict | Should -Be 'Ready'
        }

        It 'Should carry the detection through with -PassThruDetection, ready to deploy' {
            $results = @(Test-XDRMigrationReadiness -Path $script:ReadyRule -PassThruDetection -WarningAction SilentlyContinue)
            $results[0].Detection | Should -Not -BeNullOrEmpty
            $results[0].Detection.Rule.queryCondition.queryText | Should -Match 'DeviceProcessEvents'

            $deployed = @($results | Where-Object Verdict -in 'Ready', 'Review' |
                ForEach-Object Detection |
                New-XDRCustomDetection -WhatIf -AccessToken 'test-token')
            $deployed.Count | Should -Be 1
            $deployed[0].Status | Should -Be 'WhatIf'
        }

        It 'Should omit the detection by default' {
            $result = Test-XDRMigrationReadiness -Path $script:ReadyRule -WarningAction SilentlyContinue
            $result.PSObject.Properties.Name | Should -Not -Contain 'Detection'
        }
    }

    Context 'Export-XDRMigrationReport' {

        BeforeAll {
            $script:Results = @(Test-XDRMigrationReadiness -Path $script:TestRoot -WarningAction SilentlyContinue)
            $script:ReportDir = Join-Path $script:TestRoot 'reports'
        }

        It 'Should write a CSV with one row per rule' {
            $file = Join-Path $script:ReportDir 'report.csv'
            $script:Results | Export-XDRMigrationReport -Path $file
            $rows = @(Import-Csv -LiteralPath $file)
            $rows.Count | Should -Be 4
            $rows[0].PSObject.Properties.Name | Should -Contain 'Verdict'
            $rows[0].PSObject.Properties.Name | Should -Contain 'Headline'
        }

        It 'Should write Markdown with the summary table' {
            $file = Join-Path $script:ReportDir 'report.md'
            $script:Results | Export-XDRMigrationReport -Path $file
            $content = Get-Content -LiteralPath $file -Raw
            $content | Should -Match '\| Ready \| 1 \|'
            $content | Should -Match '\| Blocked \| 1 \|'
        }

        It 'Should write self-contained HTML' {
            $file = Join-Path $script:ReportDir 'report.html'
            $script:Results | Export-XDRMigrationReport -Path $file
            $content = Get-Content -LiteralPath $file -Raw
            $content | Should -Match '<!DOCTYPE html>'
            # No CDN, no external font, no remote script: it must render from a file share.
            $content | Should -Not -Match '(src|href)\s*=\s*["'']https?://'
        }

        It 'Should encode rule text rather than render it as markup' {
            $file = Join-Path $script:ReportDir 'xss.html'
            $nasty = New-TestFile -Name 'nasty.yaml' -Content @'
id: 44444444-4444-4444-4444-444444444444
name: <script>alert(1)</script>
description: Rule names are not trustworthy input.
severity: Low
kind: Scheduled
queryFrequency: PT1H
queryPeriod: PT1H
tactics:
  - Impact
relevantTechniques:
  - T1486
query: |
  DeviceEvents
  | where ActionType == "x"
entityMappings:
  - entityType: Host
    fieldMappings:
      - identifier: HostName
        columnName: DeviceName
'@
            Test-XDRMigrationReadiness -Path $nasty -WarningAction SilentlyContinue |
                Export-XDRMigrationReport -Path $file
            $content = Get-Content -LiteralPath $file -Raw
            $content | Should -Not -Match '<script>alert\(1\)</script>'
            $content | Should -Match '&lt;script&gt;'
        }

        It 'Should order the report worst first' {
            $file = Join-Path $script:ReportDir 'ordered.md'
            $script:Results | Export-XDRMigrationReport -Path $file
            $lines = @(Get-Content -LiteralPath $file | Where-Object { $_ -match '^\| .+ \| (Ready|Review|NeedsWork|Blocked) \|' })
            $verdicts = @($lines | ForEach-Object { if ($_ -match '\| (Ready|Review|NeedsWork|Blocked) \|') { $Matches[1] } })
            $verdicts[0] | Should -Be 'Blocked'
            $verdicts[-1] | Should -Be 'Ready'
        }

        It 'Should choose the format from the file extension' {
            $csv = Join-Path $script:ReportDir 'implied.csv'
            $script:Results | Export-XDRMigrationReport -Path $csv
            (Get-Content -LiteralPath $csv -Raw) | Should -Match '"RuleName"'
        }

        It 'Should warn and write nothing when there are no results' {
            $file = Join-Path $script:ReportDir 'empty.html'
            $warnings = @()
            @() | Export-XDRMigrationReport -Path $file -WarningVariable +warnings
            $warnings.Count | Should -Be 1
            (Test-Path -LiteralPath $file) | Should -BeFalse
        }
    }

    Context 'Readiness data file' {

        It 'Should classify every impact level the verdicts reference' {
            $data = InModuleScope SentinelToXDR {
                $path = Join-Path $script:ModuleRoot 'Data' | Join-Path -ChildPath 'MigrationReadiness.psd1'
                Import-PowerShellDataFile -Path $path
            }
            $impacts = @($data.Rules.Impact) + @($data.DefaultImpact) | Sort-Object -Unique
            foreach ($impact in $impacts) {
                $impact | Should -BeIn @('Blocking', 'High', 'Medium', 'Low')
            }
            foreach ($verdict in $data.Verdicts) {
                if ($verdict.Trigger) { $verdict.Trigger | Should -BeIn @('Blocking', 'High', 'Medium', 'Low') }
                $verdict.Description | Should -Not -BeNullOrEmpty
            }
        }

        It 'Should give every classification rule a plain-English summary' {
            $data = InModuleScope SentinelToXDR {
                $path = Join-Path $script:ModuleRoot 'Data' | Join-Path -ChildPath 'MigrationReadiness.psd1'
                Import-PowerShellDataFile -Path $path
            }
            foreach ($rule in $data.Rules) {
                $rule.Summary | Should -Not -BeNullOrEmpty -Because 'the summary is what the report shows a human'
            }
        }
    }
}
