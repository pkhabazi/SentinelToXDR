Describe 'Adversarial input - never lose a rule, never emit an unverifiable claim' {

    # The corpus is one shape of data, and every rule in it was written by someone trying
    # to make a working detection. These fixtures were written by someone trying to break
    # the converter: enormous queries, hostile names, duplicate ids, deep nesting, malformed
    # blocks, every feature at once. Two invariants hold for all of them:
    #
    #   1. rules read == rules assessed. A rule that goes in comes out with a verdict.
    #   2. no diagnostic says one thing while the output does another.
    #
    # Each fixture is generated here rather than checked in, so the size and the exact
    # bytes are visible next to the assertion.

    BeforeAll {
        $repoRoot = Split-Path -Path $PSScriptRoot -Parent
        Import-Module -Name (Join-Path $repoRoot 'src/SentinelToXDR.psd1') -Force

        $script:Work = Join-Path ([System.IO.Path]::GetTempPath()) ("s2x-adversarial-" + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $script:Work -Force | Out-Null

        function Get-RuleYaml {
            param([string]$Id, [string]$Name, [string]$Query = "DeviceProcessEvents`n| take 1", [string]$Extra = '')
            @"
id: $Id
name: $Name
severity: Low
kind: Scheduled
queryFrequency: PT1H
queryPeriod: PT1H
tactics: [Execution]
relevantTechniques: [T1059]
query: |
$(($Query -split "`n" | ForEach-Object { "  $_" }) -join "`n")
entityMappings:
  - entityType: Host
    fieldMappings:
      - identifier: HostName
        columnName: DeviceName
$Extra
"@
        }

        function Assess {
            param([string]$Folder)
            $rules = @(Get-SentinelAnalyticsRule -Path $Folder -Recurse -WarningAction SilentlyContinue -ErrorAction SilentlyContinue)
            $assessed = @(Test-XDRMigrationReadiness -Path $Folder -Recurse -PassThruDetection -WarningAction SilentlyContinue -ErrorAction SilentlyContinue)
            [PSCustomObject]@{ Read = $rules.Count; Assessed = $assessed.Count; Results = $assessed }
        }
    }

    AfterAll {
        if ($script:Work -and (Test-Path -LiteralPath $script:Work)) {
            Remove-Item -LiteralPath $script:Work -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    Context 'A rule is never lost' {

        It 'Should assess a rule whose triggerThreshold is an ARM parameter string' {
            $folder = Join-Path $script:Work 'threshold'; New-Item -ItemType Directory -Path $folder | Out-Null
            Set-Content -LiteralPath (Join-Path $folder 'a.yaml') -Value (Get-RuleYaml -Id ([guid]::NewGuid()) -Name 'Threshold' -Extra "triggerOperator: gt`ntriggerThreshold: `"[parameters('threshold')]`"")
            $r = Assess -Folder $folder
            $r.Read | Should -Be 1
            $r.Assessed | Should -Be 1 -Because 'the rule used to vanish on an [int] cast'
            $r.Results[0].Verdict | Should -Be 'NeedsWork'
            $r.Results[0].Headline | Should -Contain 'Trigger threshold dropped: the detection fires on every result row'
        }

        It 'Should emit a Blocked verdict, not nothing, when the converter throws' {
            # Force a throw inside the engine by mocking a private helper it calls.
            InModuleScope SentinelToXDR {
                Mock Resolve-GraphTactic { throw 'synthetic engine failure' }
                $rule = Get-SentinelAnalyticsRule -Path (Join-Path (Split-Path $PSScriptRoot -Parent) 'Samples/01-ready-defender-only.yaml')
                $out = @($rule | ConvertTo-XDRCustomDetection -As Object -Force -WarningAction SilentlyContinue -ErrorAction SilentlyContinue)
                $out.Count | Should -Be 1
                $out[0].Blocked | Should -BeTrue
                @($out[0].Diagnostics | Where-Object { $_.TargetValue -eq 'ConversionFailed' }).Count | Should -Be 1
                $out[0].Diagnostics[0].Reason | Should -Match 'synthetic engine failure'
            }
        }

        It 'Should read a rule nested inside Microsoft.Resources/deployments' {
            $r = Assess -Folder (Join-Path (Split-Path $PSScriptRoot -Parent) 'Samples/32-needswork-arm-threshold-parameter.json')
            $r.Read | Should -Be 1
            $r.Assessed | Should -Be 1
            $r.Results[0].Id | Should -Be '5a1e0032-0000-4000-8000-000000000032'
        }

        It 'Should warn, not crash, on JSON nested beyond the parser depth' {
            $folder = Join-Path $script:Work 'deep'; New-Item -ItemType Directory -Path $folder | Out-Null
            $deep = ('{"a":' * 1200) + '1' + ('}' * 1200)
            Set-Content -LiteralPath (Join-Path $folder 'deep.json') -Value $deep
            $warnings = @()
            $rules = @(Get-SentinelAnalyticsRule -Path $folder -WarningVariable warnings -WarningAction SilentlyContinue -ErrorAction SilentlyContinue)
            $rules.Count | Should -Be 0
            ($warnings -join ' ') | Should -Not -BeNullOrEmpty -Because 'a file that could not be parsed must be named, not skipped'
        }

        It 'Should convert a 1 MB query without truncating it' {
            $folder = Join-Path $script:Work 'big'; New-Item -ItemType Directory -Path $folder | Out-Null
            $lines = 1..12000 | ForEach-Object { "| where ProcessCommandLine !contains 'padding-value-number-$_-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'" }
            $query = "DeviceProcessEvents`n" + ($lines -join "`n")
            $query.Length | Should -BeGreaterThan 1MB
            Set-Content -LiteralPath (Join-Path $folder 'big.yaml') -Value (Get-RuleYaml -Id ([guid]::NewGuid()) -Name 'Big query' -Query $query)
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $r = Assess -Folder $folder
            $sw.Stop()
            $r.Assessed | Should -Be 1
            $r.Results[0].Detection.Rule.queryCondition.queryText.Length | Should -BeGreaterOrEqual $query.Length
            $sw.Elapsed.TotalSeconds | Should -BeLessThan 60 -Because 'the query scanners are regex-based and must stay linear'
        }

        It 'Should assess a rule that has every feature at once' {
            $folder = Join-Path $script:Work 'everything'; New-Item -ItemType Directory -Path $folder | Out-Null
            $entities = (1..12 | ForEach-Object { "  - entityType: Account`n    fieldMappings:`n      - identifier: Name`n        columnName: Account$_" }) -join "`n"
            $yaml = @"
id: $([guid]::NewGuid())
name: Everything at once
severity: High
kind: NRT
queryFrequency: PT0M
queryPeriod: P14D
triggerOperator: gt
triggerThreshold: 5
suppressionEnabled: true
suppressionDuration: PT5H
tactics: [Execution, Persistence, PrivilegeEscalation, DefenseEvasion]
relevantTechniques: [T1059, T1059.001, T1547, T1548.002]
customDetails:
  CommandLine: ProcessCommandLine
alertDetailsOverride:
  alertDisplayNameFormat: 'Alert on {{DeviceName}}'
  alertSeverityColumnName: Sev
  alertTacticsColumnName: Tac
eventGroupingSettings:
  aggregationKind: AlertPerResult
incidentConfiguration:
  createIncident: false
  groupingConfiguration:
    enabled: true
    matchingMethod: Selected
query: |
  let w = _GetWatchlist('HighValue');
  DeviceProcessEvents
  | join kind=inner (DeviceInfo) on DeviceId
  | extend Sev = 'High', Tac = 'Execution'
entityMappings:
$entities
"@
            Set-Content -LiteralPath (Join-Path $folder 'all.yaml') -Value $yaml
            $r = Assess -Folder $folder
            $r.Read | Should -Be 1
            $r.Assessed | Should -Be 1
            $r.Results[0].Verdict | Should -Be 'NeedsWork'
            $r.Results[0].Headline | Should -Contain 'Only one MITRE tactic is carried'
            $r.Results[0].Headline | Should -Contain 'The query depends on something that does not exist in Defender XDR and will not run'
            $r.Results[0].Headline | Should -Contain 'The service will refuse this entity mapping: no sufficient identifier'
        }
    }

    Context 'A folder with no rules says so' {

        It 'Should name the count and the reason when a scanned folder holds only converted detections' {
            $src = Join-Path $script:Work 'export-src'; New-Item -ItemType Directory -Path $src | Out-Null
            Set-Content -LiteralPath (Join-Path $src 'a.yaml') -Value (Get-RuleYaml -Id ([guid]::NewGuid()) -Name 'Exported')
            $exported = Join-Path $script:Work 'export-out'
            Get-SentinelAnalyticsRule -Path $src | ConvertTo-XDRCustomDetection -OutputFolder $exported -UseIdAsFilename -Force -WarningAction SilentlyContinue | Out-Null
            @(Get-ChildItem -LiteralPath $exported -File).Count | Should -Be 1

            # Pointing the reader at its own output used to say only 'nothing to migrate'.
            $warnings = @()
            $rules = @(Get-SentinelAnalyticsRule -Path $exported -WarningVariable warnings -WarningAction SilentlyContinue)
            $rules.Count | Should -Be 0
            ($warnings -join ' ') | Should -Match 'Scanned 1 file'
            ($warnings -join ' ') | Should -Match 'Defender XDR custom detection'
        }
    }

    Context 'Rule ids the service will accept' {

        BeforeAll {
            $script:Policy = (Import-PowerShellDataFile -Path (Join-Path (Split-Path $PSScriptRoot -Parent) 'src/Data/GraphDetectionRule.psd1')).RuleIdPolicy
            $script:AllSamples = Assess -Folder (Join-Path (Split-Path $PSScriptRoot -Parent) 'Samples')
        }

        It 'Should emit an id that begins with a letter for every sample, whatever the source id' {
            # 2026-09-16: the first deploy of a rule with its raw Sentinel GUID was refused with
            # 'Rule ID must ... begin with a letter'. Ten GUIDs in sixteen begin with a digit.
            # Every earlier live run had prefixed its ids for cleanup, which is why none saw it.
            foreach ($row in $script:AllSamples.Results | Where-Object { $_.Detection.Rule }) {
                [string]$row.Detection.Rule.id | Should -Match $script:Policy.Pattern -Because "$($row.RuleName) would be refused"
            }
        }

        It 'Should prefix a digit-leading GUID deterministically and report it' {
            $row = $script:AllSamples.Results | Where-Object RuleName -eq 'Sample - PowerShell spawned by Office'
            $row.Detection.Rule.id | Should -Be "$($script:Policy.Prefix)5a1e0001-0000-4000-8000-000000000001"
            @($row.Detection.Diagnostics | Where-Object { $_.TargetValue -eq $script:Policy.Constraint }).Count | Should -Be 1
        }

        It 'Should leave a letter-leading id unchanged' {
            $folder = Join-Path $script:Work 'letterid'; New-Item -ItemType Directory -Path $folder | Out-Null
            Set-Content -LiteralPath (Join-Path $folder 'a.yaml') -Value (Get-RuleYaml -Id 'a1b2c3d4-0000-4000-8000-000000000001' -Name 'Letter id')
            $r = Assess -Folder $folder
            $r.Results[0].Detection.Rule.id | Should -Be 'a1b2c3d4-0000-4000-8000-000000000001'
            @($r.Results[0].Detection.Diagnostics | Where-Object { $_.TargetValue -eq $script:Policy.Constraint }).Count | Should -Be 0
        }
    }

    Context 'Duplicate ids' {

        It 'Should flag the second rule that reuses an id, and keep the first clean' {
            $folder = Join-Path $script:Work 'dup'; New-Item -ItemType Directory -Path $folder | Out-Null
            $id = [guid]::NewGuid().ToString()
            Set-Content -LiteralPath (Join-Path $folder 'a.yaml') -Value (Get-RuleYaml -Id $id -Name 'First')
            Set-Content -LiteralPath (Join-Path $folder 'b.yaml') -Value (Get-RuleYaml -Id $id -Name 'Second')
            $r = Assess -Folder $folder
            $r.Assessed | Should -Be 2
            @($r.Results | Where-Object { $_.Headline -contains 'Another rule in this batch has the same id' }).Count | Should -Be 1
            ($r.Results | Where-Object RuleName -eq 'First').Verdict | Should -Be 'Ready'
        }

        It 'Should not overwrite one output file with another when names collide' {
            $folder = Join-Path $script:Work 'collide'; New-Item -ItemType Directory -Path $folder | Out-Null
            Set-Content -LiteralPath (Join-Path $folder 'a.yaml') -Value (Get-RuleYaml -Id ([guid]::NewGuid()) -Name 'Same Name')
            Set-Content -LiteralPath (Join-Path $folder 'b.yaml') -Value (Get-RuleYaml -Id ([guid]::NewGuid()) -Name 'same name')
            $out = Join-Path $script:Work 'collide-out'
            Get-SentinelAnalyticsRule -Path $folder | ConvertTo-XDRCustomDetection -OutputFolder $out -UseDisplayNameAsFilename -Force -WarningAction SilentlyContinue | Out-Null
            @(Get-ChildItem -LiteralPath $out -File).Count | Should -Be 2
        }
    }

    Context 'Hostile display names' {

        BeforeAll {
            $script:Hostile = Assess -Folder (Join-Path (Split-Path $PSScriptRoot -Parent) 'Samples/34-review-hostile-display-name.yaml')
            $script:HostileRow = $script:Hostile.Results[0]
        }

        It 'Should strip controls and bidirectional overrides from the detection name and say so' {
            $name = [string]$script:HostileRow.Detection.Rule.displayName
            $name | Should -Not -Match '[\p{Cc}\u202A-\u202E\u2066-\u2069]'
            $name | Should -Be '=Sample <b>reversed</b> name with tabs and a newline'
            $script:HostileRow.Headline | Should -Contain 'The display name contained control or bidirectional-override characters, which were removed'
        }

        It 'Should produce readable file names from awkward display names' {
            InModuleScope SentinelToXDR {
                ConvertTo-SafeFileName -Name '[Entra ID] Devices flapping online/offline' | Should -Be 'EntraIDDevicesFlappingOnlineOffline'
                ConvertTo-SafeFileName -Name "=Sample <b>reversed</b> name`twith`ttabs" | Should -Be 'SampleBReversedBNameWithTabs'
                ConvertTo-SafeFileName -Name 'Sample - PowerShell spawned by Office' | Should -Be 'Sample-PowerShellSpawnedByOffice'
                ConvertTo-SafeFileName -Name 'CON' -Fallback 'abc' | Should -Be 'abc'
                ConvertTo-SafeFileName -Name '???' -Fallback 'abc' | Should -Be 'abc'
                ConvertTo-SafeFileName -Name '' -Fallback '' | Should -Be 'detection'
            }
        }

        It 'Should produce a file name with no control characters' {
            $out = Join-Path $script:Work 'hostile-out'
            Get-SentinelAnalyticsRule -Path (Join-Path (Split-Path $PSScriptRoot -Parent) 'Samples/34-review-hostile-display-name.yaml') |
                ConvertTo-XDRCustomDetection -OutputFolder $out -UseDisplayNameAsFilename -Force -WarningAction SilentlyContinue | Out-Null
            $file = Get-ChildItem -LiteralPath $out -File | Select-Object -First 1
            $file.Name | Should -Not -Match '[\p{Cc}\u202A-\u202E\u2066-\u2069]'
            $file.Name | Should -Match '^[A-Za-z0-9-]+\.yaml$'
        }

        It 'Should neutralise a leading formula character in the CSV report' {
            $csv = Join-Path $script:Work 'hostile.csv'
            $script:HostileRow | Export-XDRMigrationReport -Path $csv -Format Csv
            $row = Import-Csv -LiteralPath $csv | Select-Object -First 1
            $row.RuleName | Should -Match "^'=" -Because 'a cell starting with = is a formula when the CSV is opened in a spreadsheet'
        }

        It 'Should keep every Markdown table row on one line and escape markup' {
            $md = Join-Path $script:Work 'hostile.md'
            $script:HostileRow | Export-XDRMigrationReport -Path $md -Format Markdown
            $lines = Get-Content -LiteralPath $md
            $rows = @($lines | Where-Object { $_ -like '| *Sample*' })
            $rows.Count | Should -Be 1
            $rows[0] | Should -Not -Match '<b>'
            $rows[0] | Should -Match '&lt;b&gt;'
        }

        It 'Should not carry a bidirectional override into the HTML report' {
            $html = Join-Path $script:Work 'hostile.html'
            $script:HostileRow | Export-XDRMigrationReport -Path $html -Format Html
            $text = Get-Content -LiteralPath $html -Raw
            $text | Should -Not -Match '[\u202A-\u202E\u2066-\u2069]'
            $text | Should -Match '&lt;b&gt;reversed&lt;/b&gt;'
        }
    }

    Context 'Malformed blocks are dropped, never invented' {

        It 'Should not fabricate a custom detail from a scalar customDetails' {
            $r = Assess -Folder (Join-Path (Split-Path $PSScriptRoot -Parent) 'Samples/33-review-custom-details-malformed.yaml')
            $r.Results[0].Detection.Rule.detectionAction.alertTemplate.customDetails | Should -BeNullOrEmpty
            $r.Results[0].Headline | Should -Contain 'Custom details block is malformed and was not carried'
        }

        It 'Should report an entity with no fieldMappings instead of skipping it' {
            $folder = Join-Path $script:Work 'emptyentity'; New-Item -ItemType Directory -Path $folder | Out-Null
            $yaml = (Get-RuleYaml -Id ([guid]::NewGuid()) -Name 'Empty entity') + "  - entityType: Account`n    fieldMappings: []`n"
            Set-Content -LiteralPath (Join-Path $folder 'a.yaml') -Value $yaml
            $r = Assess -Folder $folder
            @($r.Results[0].Detection.Diagnostics | Where-Object { $_.Reason -match 'no fieldMappings' }).Count | Should -Be 1
        }

        It 'Should raise a sub-five-minute lookback to the documented minimum and say so' {
            $folder = Join-Path $script:Work 'shortlookback'; New-Item -ItemType Directory -Path $folder | Out-Null
            $yaml = (Get-RuleYaml -Id ([guid]::NewGuid()) -Name 'Short lookback' -Query "SigninLogs`n| take 1") -replace 'queryPeriod: PT1H', 'queryPeriod: PT1M' -replace 'queryFrequency: PT1H', 'queryFrequency: PT5M'
            Set-Content -LiteralPath (Join-Path $folder 'a.yaml') -Value $yaml
            $r = Assess -Folder $folder
            # The Graph schedule carries only a frequency; the lookback decision is reported, not emitted.
            @($r.Results[0].Detection.Diagnostics | Where-Object { $_.Reason -match 'minimum' -and $_.Action -eq 'Constrained' }).Count | Should -Be 1
        }
    }

    Context 'Second-run properties' {

        It 'Should convert the samples to identical bytes twice, except for generated ids' {
            $samples = Join-Path (Split-Path $PSScriptRoot -Parent) 'Samples'
            $a = Join-Path $script:Work 'run-a'; $b = Join-Path $script:Work 'run-b'
            foreach ($dir in @($a, $b)) {
                Get-SentinelAnalyticsRule -Path $samples -WarningAction SilentlyContinue |
                    ConvertTo-XDRCustomDetection -OutputFolder $dir -UseDisplayNameAsFilename -Force -WarningAction SilentlyContinue -ErrorAction SilentlyContinue | Out-Null
            }
            $filesA = @(Get-ChildItem -LiteralPath $a -File | Sort-Object Name)
            $filesB = @(Get-ChildItem -LiteralPath $b -File | Sort-Object Name)
            ($filesA.Name -join ',') | Should -Be ($filesB.Name -join ',')
            $differing = @()
            for ($i = 0; $i -lt $filesA.Count; $i++) {
                $ta = Get-Content -LiteralPath $filesA[$i].FullName -Raw
                $tb = Get-Content -LiteralPath $filesB[$i].FullName -Raw
                if ($ta -ne $tb) { $differing += $filesA[$i].Name }
            }
            # Sample 14 carries no id and gets a fresh GUID each run; that is diagnosed and
            # expected. Anything else differing is non-determinism.
            $differing | Where-Object { $_ -notmatch 'PascalCase|TimeSpan|SerializedSchedule' } | Should -BeNullOrEmpty
        }

        It 'Should render the HTML report to identical bytes when -GeneratedOn is fixed' {
            $rows = @(Test-XDRMigrationReadiness -Path (Join-Path (Split-Path $PSScriptRoot -Parent) 'Samples/01-ready-defender-only.yaml') -WarningAction SilentlyContinue)
            $stamp = [datetime]'2026-01-01T00:00:00'
            $h1 = Join-Path $script:Work 'r1.html'; $h2 = Join-Path $script:Work 'r2.html'
            $rows | Export-XDRMigrationReport -Path $h1 -Format Html -GeneratedOn $stamp
            $rows | Export-XDRMigrationReport -Path $h2 -Format Html -GeneratedOn $stamp
            (Get-FileHash -LiteralPath $h1).Hash | Should -Be (Get-FileHash -LiteralPath $h2).Hash
        }

        It 'Should touch nothing on disk under -WhatIf, the output folder included' {
            $rows = @(Test-XDRMigrationReadiness -Path (Join-Path (Split-Path $PSScriptRoot -Parent) 'Samples/01-ready-defender-only.yaml') -WarningAction SilentlyContinue)
            $reportDir = Join-Path $script:Work 'whatif-report'
            $rows | Export-XDRMigrationReport -Path (Join-Path $reportDir 'r.html') -WhatIf
            Test-Path -LiteralPath $reportDir | Should -BeFalse

            $convertDir = Join-Path $script:Work 'whatif-convert'
            Get-SentinelAnalyticsRule -Path (Join-Path (Split-Path $PSScriptRoot -Parent) 'Samples/01-ready-defender-only.yaml') |
                ConvertTo-XDRCustomDetection -OutputFolder $convertDir -UseIdAsFilename -Force -WhatIf -WarningAction SilentlyContinue | Out-Null
            Test-Path -LiteralPath $convertDir | Should -BeFalse
        }

        It 'Should make no hunting-query request under -WhatIf even with -ValidateQuery' {
            Mock -ModuleName SentinelToXDR -CommandName Test-XDRDetectionQuery -MockWith { throw 'must not be called under -WhatIf' }
            Mock -ModuleName SentinelToXDR -CommandName Get-SentinelToXDRContext -MockWith {
                [PSCustomObject]@{ CanValidateQueries = $true; CanManageDetections = $true; AuthMode = 'Test'; Account = 'test' }
            }
            $summary = Invoke-SentinelToXDRMigration -Path (Join-Path (Split-Path $PSScriptRoot -Parent) 'Samples/01-ready-defender-only.yaml') `
                -ValidateQuery -AccessToken 'test-token' -WhatIf -WarningAction SilentlyContinue
            Should -Invoke -ModuleName SentinelToXDR -CommandName Test-XDRDetectionQuery -Times 0
            $summary.QueryValidationSkipped | Should -Be 'WhatIf'
        }
    }
}
