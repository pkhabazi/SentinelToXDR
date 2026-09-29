Describe 'SentinelToXDR v2 — sources, Graph shape, export and deploy' {

    BeforeAll {
        $ModulePath = Split-Path -Path $PSScriptRoot -Parent
        $ModulePath = Join-Path -Path $ModulePath -ChildPath 'src' | Join-Path -ChildPath 'SentinelToXDR.psd1'
        Import-Module -Name $ModulePath -Force

        $script:TestRoot = Join-Path ([System.IO.Path]::GetTempPath()) "s2x-v2-$([System.Guid]::NewGuid())"
        New-Item -ItemType Directory -Path $script:TestRoot -Force | Out-Null

        function New-TestFile {
            param([string]$Name, [string]$Content)
            $path = Join-Path $script:TestRoot $Name
            Set-Content -Path $path -Value $Content -Encoding utf8NoBOM
            return $path
        }

        # --- Community YAML, multi-tactic, rich entity mappings -------------------
        $script:CommunityYaml = New-TestFile -Name 'community.yaml' -Content @'
id: 81fb771a-c57e-41b8-9905-63dbf267c13f
name: Community Test Rule
description: Detects suspicious sign-in activity.
severity: High
status: Available
queryFrequency: 1h
queryPeriod: 1h
triggerOperator: gt
triggerThreshold: 0
tactics:
  - InitialAccess
  - Persistence
relevantTechniques:
  - T1078
  - T1078.004
query: |
  SigninLogs
  | where ResultType == "0"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: AccountName
      - identifier: NTDomain
        columnName: AccountDomain
      - identifier: Sid
        columnName: AccountSid
  - entityType: Host
    fieldMappings:
      - identifier: HostName
        columnName: Computer
      - identifier: AzureID
        columnName: DeviceId
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: IpAddress
kind: Scheduled
'@

        # --- ARM deployment template with resources[] and a [concat()] name -------
        $script:ArmTemplate = New-TestFile -Name 'template.json' -Content @'
{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "parameters": {
    "workspace": { "type": "string", "defaultValue": "law-soc" },
    "analytic1-id": { "type": "string", "defaultValue": "aaaaaaaa-1111-2222-3333-444444444444" }
  },
  "resources": [
    {
      "type": "Microsoft.OperationalInsights/workspaces/providers/contentTemplates",
      "name": "wrapper",
      "resources": [
        {
          "type": "Microsoft.OperationalInsights/workspaces/providers/alertRules",
          "apiVersion": "2023-02-01",
          "name": "[concat(parameters('workspace'),'/Microsoft.SecurityInsights/',parameters('analytic1-id'))]",
          "kind": "Scheduled",
          "properties": {
            "displayName": "Nested ARM Rule",
            "description": "Rule nested inside a content template.",
            "severity": "Medium",
            "enabled": true,
            "query": "DeviceProcessEvents | where FileName == 'powershell.exe'",
            "queryFrequency": "PT1H",
            "queryPeriod": "PT1H",
            "triggerOperator": "GreaterThan",
            "triggerThreshold": 0,
            "tactics": ["Execution"],
            "techniques": ["T1059"]
          }
        }
      ]
    }
  ]
}
'@

        # --- Non-convertible kinds -------------------------------------------------
        $script:FusionRule = New-TestFile -Name 'fusion.json' -Content @'
{
  "type": "Microsoft.SecurityInsights/alertRules",
  "kind": "Fusion",
  "properties": {
    "displayName": "Advanced Multistage Attack Detection",
    "enabled": true,
    "alertRuleTemplateName": "f71aba3d-28fb-450b-b192-4e76a83015c8"
  }
}
'@

        # A real rule (declares a Sentinel kind and a schedule) that carries no query.
        $script:NoQueryRule = New-TestFile -Name 'noquery.yaml' -Content @'
id: e7b9ea73-1980-4318-96a6-da559486664b
name: Scheduled rule with no query
description: Declares a schedule but has nothing to run.
severity: Medium
kind: Scheduled
queryFrequency: PT1H
queryPeriod: PT1H
tactics:
  - Impact
'@

        # A content pointer: has a name and an id, but nothing that makes it a rule.
        # The Detections folder of the Azure-Sentinel repo is full of these.
        $script:PointerStub = New-TestFile -Name 'stub.yaml' -Content @'
id: 11111111-2222-3333-4444-555555555555
name: Moved content stub
description: This file moved to a new location.
version: 1.0.1
'@

        # --- Serialized TimeSpan durations (the SAP solution shape) ---------------
        $script:TimeSpanRule = New-TestFile -Name 'timespan.json' -Content @'
[
  {
    "DisplayName": "PascalCase TimeSpan Rule",
    "Description": "Uses PascalCase members and serialized TimeSpan durations.",
    "Severity": "Medium",
    "Enabled": true,
    "Query": "SecurityEvent | where EventID == 4625",
    "QueryFrequency": { "Ticks": 216000000000, "TotalHours": 6 },
    "QueryPeriod": { "Ticks": 216000000000, "TotalHours": 6 },
    "Tactics": ["CredentialAccess"]
  }
]
'@

        # --- Multi-rule YAML with an entity type XDR has no home for --------------
        $script:UnsupportedEntity = New-TestFile -Name 'iot.yaml' -Content @'
id: 22222222-3333-4444-5555-666666666666
name: IoT Rule
description: Uses an entity type with no XDR equivalent.
severity: Low
queryFrequency: PT1H
queryPeriod: PT1H
tactics:
  - Impact
query: |
  DeviceEvents
  | where ActionType == "Something"
entityMappings:
  - entityType: IoTDevice
    fieldMappings:
      - identifier: DeviceId
        columnName: DeviceId
  - entityType: URL
    fieldMappings:
      - identifier: Url
        columnName: RemoteUrl
kind: Scheduled
'@
    }

    AfterAll {
        if ($script:TestRoot -and (Test-Path $script:TestRoot)) {
            Remove-Item -Path $script:TestRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    Context 'Get-SentinelAnalyticsRule — sources' {

        It 'Should read a community YAML rule' {
            $rules = @(Get-SentinelAnalyticsRule -Path $script:CommunityYaml)
            $rules.Count | Should -Be 1
            $rules[0].DisplayName | Should -Be 'Community Test Rule'
            $rules[0].Id | Should -Be '81fb771a-c57e-41b8-9905-63dbf267c13f'
            $rules[0].Kind | Should -Be 'Scheduled'
            $rules[0].Tactics.Count | Should -Be 2
        }

        It 'Should find a rule nested inside an ARM deployment template' {
            $rules = @(Get-SentinelAnalyticsRule -Path $script:ArmTemplate)
            $rules.Count | Should -Be 1
            $rules[0].DisplayName | Should -Be 'Nested ARM Rule'
        }

        It 'Should recover the rule GUID from a [concat()] name via template parameters' {
            $rules = @(Get-SentinelAnalyticsRule -Path $script:ArmTemplate)
            $rules[0].Id | Should -Be 'aaaaaaaa-1111-2222-3333-444444444444'
        }

        It 'Should normalize serialized TimeSpan durations to ISO 8601' {
            $rules = @(Get-SentinelAnalyticsRule -Path $script:TimeSpanRule)
            $rules.Count | Should -Be 1
            $rules[0].QueryFrequency | Should -Be 'PT6H'
            $rules[0].QueryPeriod | Should -Be 'PT6H'
        }

        It 'Should read PascalCase members from a bare JSON array' {
            $rules = @(Get-SentinelAnalyticsRule -Path $script:TimeSpanRule)
            $rules[0].DisplayName | Should -Be 'PascalCase TimeSpan Rule'
            $rules[0].Query | Should -Match 'SecurityEvent'
        }

        It 'Should read every supported file in a folder' {
            $rules = @(Get-SentinelAnalyticsRule -Path $script:TestRoot -WarningAction SilentlyContinue)
            $rules.Count | Should -BeGreaterOrEqual 5
        }

        It 'Should bind FileInfo from the pipeline instead of treating it as a rule' {
            $rules = @(Get-ChildItem -Path $script:CommunityYaml | Get-SentinelAnalyticsRule)
            $rules.Count | Should -Be 1
            $rules[0].DisplayName | Should -Be 'Community Test Rule'
        }

        It 'Should stay silent about non-rule files when scanning a folder' {
            # A content repository is mostly workbooks, playbooks, parsers and connectors.
            # Warning about each one buries the real findings.
            $noise = Join-Path $script:TestRoot 'noise'
            New-Item -ItemType Directory -Path $noise -Force | Out-Null
            Set-Content -LiteralPath (Join-Path $noise 'workbook.json') -Value '{"version":"Notebook/1.0","items":[]}'
            Set-Content -LiteralPath (Join-Path $noise 'parser.yaml') -Value "Function: MyParser`nFunctionQuery: union X"
            Copy-Item -LiteralPath $script:CommunityYaml -Destination (Join-Path $noise 'rule.yaml')

            $warnings = @()
            $rules = @(Get-SentinelAnalyticsRule -Path $noise -WarningVariable +warnings)

            $rules.Count | Should -Be 1 -Because 'only the rule is a rule'
            $warnings.Count | Should -Be 0 -Because 'the other files were never claimed to be rules'
        }

        It 'Should warn when a file named explicitly is not a rule' {
            $noise = Join-Path $script:TestRoot 'noise'
            $warnings = @()
            $rules = @(Get-SentinelAnalyticsRule -Path (Join-Path $noise 'workbook.json') -WarningVariable +warnings)

            $rules.Count | Should -Be 0
            $warnings.Count | Should -Be 1 -Because 'the user asked about that file and deserves an answer'
        }

        It 'Should return non-convertible kinds rather than hiding them' {
            $rules = @(Get-SentinelAnalyticsRule -Path $script:FusionRule)
            $rules.Count | Should -Be 1
            $rules[0].Kind | Should -Be 'Fusion'
        }
    }

    Context 'Blocking gates' {

        It 'Should refuse a Fusion rule with a Blocking diagnostic and no rule object' {
            $result = ConvertTo-XDRCustomDetection -InputFile $script:FusionRule -As Object -Force -WarningAction SilentlyContinue
            $result.Blocked | Should -BeTrue
            $result.Rule | Should -BeNullOrEmpty
            $blocking = @($result.Diagnostics | Where-Object { $_.Severity -eq 'Blocking' })
            $blocking.Count | Should -Be 1
            $blocking[0].Reason | Should -Match 'Fusion'
        }

        It 'Should refuse a rule with no query' {
            $result = ConvertTo-XDRCustomDetection -InputFile $script:NoQueryRule -As Object -Force -WarningAction SilentlyContinue
            $result.Blocked | Should -BeTrue
            @($result.Diagnostics | Where-Object { $_.Severity -eq 'Blocking' }).Count | Should -Be 1
        }

        It 'Should not treat a content pointer stub as a rule at all' {
            # Not blocked, not converted: it never was a rule. Reporting these as blocked
            # rules would bury the real findings under hundreds of false entries.
            $rules = @(Get-SentinelAnalyticsRule -Path $script:PointerStub -WarningAction SilentlyContinue)
            $rules.Count | Should -Be 0
        }

        It 'Should emit nothing on the pipeline for a blocked rule when serializing' {
            $result = ConvertTo-XDRCustomDetection -InputFile $script:FusionRule -Force -WarningAction SilentlyContinue
            $result | Should -BeNullOrEmpty
        }

        It 'Should name every non-convertible kind in the data file' {
            $kinds = Get-SentinelAnalyticsRule -Path $script:FusionRule
            $kinds | Should -Not -BeNullOrEmpty
            foreach ($kind in @('Fusion', 'MLBehaviorAnalytics', 'ThreatIntelligence', 'MicrosoftSecurityIncidentCreation', 'Anomaly')) {
                $result = InModuleScope SentinelToXDR -Parameters @{ Kind = $kind } {
                    param($Kind)
                    Get-SentinelRuleKind -Kind $Kind
                }
                $result.Convertible | Should -BeFalse -Because "$kind carries no KQL query"
                $result.Reason | Should -Not -BeNullOrEmpty
            }
        }

        It 'Should treat an unrecognised kind as non-convertible rather than guessing' {
            $result = InModuleScope SentinelToXDR { Get-SentinelRuleKind -Kind 'SomeFutureKind' }
            $result.Convertible | Should -BeFalse
            $result.IsKnown | Should -BeFalse
        }
    }

    Context 'Graph detectionRule shape' {

        BeforeAll {
            $script:GraphResult = ConvertTo-XDRCustomDetection -InputFile $script:CommunityYaml -As Object -Force -WarningAction SilentlyContinue
            $script:GraphRule = $script:GraphResult.Rule
        }

        It 'Should emit the Graph top-level property set' {
            $script:GraphRule.Keys | Should -Contain 'id'
            $script:GraphRule.Keys | Should -Contain 'displayName'
            $script:GraphRule.Keys | Should -Contain 'status'
            $script:GraphRule.Keys | Should -Contain 'queryCondition'
            $script:GraphRule.Keys | Should -Contain 'schedule'
            $script:GraphRule.Keys | Should -Contain 'detectionAction'
        }

        It 'Should NOT emit properties Microsoft removes on 2026-10-01' {
            $script:GraphRule.Keys | Should -Not -Contain 'isEnabled'
            $script:GraphRule.Keys | Should -Not -Contain 'detectorId'
            $script:GraphRule.schedule.Keys | Should -Not -Contain 'period'
            $script:GraphRule.detectionAction.alertTemplate.Keys | Should -Not -Contain 'mitreTechniques'
            $script:GraphRule.detectionAction.alertTemplate.Keys | Should -Not -Contain 'impactedAssets'
            $script:GraphRule.detectionAction.alertTemplate.Keys | Should -Not -Contain 'category'
        }

        It 'Should carry the query in queryCondition.queryText' {
            $script:GraphRule.queryCondition.queryText | Should -Match 'SigninLogs'
        }

        It 'Should express the schedule frequency as an ISO 8601 duration' {
            $script:GraphRule.schedule.frequency | Should -Be 'PT1H'
        }

        It 'Should map status from the source enabled state' {
            $script:GraphRule.status | Should -Be 'enabled'
        }

        It 'Should lower-case the alert severity' {
            $script:GraphRule.detectionAction.alertTemplate.severity | Should -Be 'high'
        }

        It 'Should carry exactly one tactic, because that is all the service accepts' {
            # This test used to assert the opposite, on the strength of the Graph model:
            # mitreTactic is a collection, so surely a multi-tactic rule keeps every
            # tactic. The API models the collection and refuses more than one entry in it
            # ('Only one tactic is currently supported.'), which no document says and only
            # a POST to a live tenant revealed. The module's own capability data had it
            # right all along - 'Link multiple MITRE tactics' is State = Planned.
            # The limit lives in TacticConstraints in GraphDetectionRule.psd1.
            $tactics = @($script:GraphRule.detectionAction.alertTemplate.tactics)
            $tactics.Count | Should -Be 1
            $tactics[0].tactic | Should -Be 'InitialAccess' -Because 'the first tactic in source order is the one kept'
        }

        It 'Should report the tactics it had to drop rather than losing them silently' {
            $finding = @($script:GraphResult.Diagnostics | Where-Object { $_.TargetValue -eq 'TacticsTruncated' })
            $finding.Count | Should -Be 1
            $finding[0].Reason | Should -Match 'Persistence' -Because 'the finding has to name what was lost'
            $finding[0].Reason | Should -Match 'InitialAccess' -Because 'and what was kept'
        }

        It 'Should nest techniques inside a tactic, and subtechniques inside their technique' {
            # mitreTechnique is { technique, subTechniques[] }. This test used to assert that
            # T1078.004 appeared as a technique of its own, which is the shape the service
            # quietly rewrote into this one.
            $techniques = @($script:GraphRule.detectionAction.alertTemplate.tactics[0].techniques)
            @($techniques.technique) | Should -Be @('T1078')
            @($techniques[0].subTechniques) | Should -Be @('T1078.004')
        }

        It 'Should build typed entity mappings keyed by Graph collection' {
            $entities = $script:GraphRule.detectionAction.alertTemplate.entityMappings
            $entities.Keys | Should -Contain 'accounts'
            $entities.Keys | Should -Contain 'hosts'
            $entities.Keys | Should -Contain 'ips'
        }

        It 'Should use the Sentinel identifier to pick the Graph column property' {
            $account = @($script:GraphRule.detectionAction.alertTemplate.entityMappings['accounts'])[0]
            $account['nameColumn']     | Should -Be 'AccountName'
            $account['ntDomainColumn'] | Should -Be 'AccountDomain'
            $account['sidColumn']      | Should -Be 'AccountSid'
        }

        It 'Should collapse all field mappings of one entity into a single entry' {
            @($script:GraphRule.detectionAction.alertTemplate.entityMappings['accounts']).Count | Should -Be 1
            @($script:GraphRule.detectionAction.alertTemplate.entityMappings['hosts']).Count | Should -Be 1
        }

        It 'Should map Host AzureID to the device id column' {
            $hostEntity = @($script:GraphRule.detectionAction.alertTemplate.entityMappings['hosts'])[0]
            $hostEntity['nameColumn']     | Should -Be 'Computer'
            $hostEntity['deviceIdColumn'] | Should -Be 'DeviceId'
        }

        It 'Should drop an entity type with no Graph equivalent, naming it' {
            $result = ConvertTo-XDRCustomDetection -InputFile $script:UnsupportedEntity -As Object -Force -WarningAction SilentlyContinue
            $dropped = @($result.Diagnostics | Where-Object { $_.Action -eq 'Unsupported' -and $_.SourceValue -eq 'IoTDevice' })
            $dropped.Count | Should -Be 1
            # The supported entity in the same rule still comes through.
            $result.Rule.detectionAction.alertTemplate.entityMappings.Keys | Should -Contain 'urls'
        }

        It 'Should serialize a single tactic as a YAML sequence, not a mapping' {
            $yaml = ConvertTo-XDRCustomDetection -InputFile $script:ArmTemplate -Force -WarningAction SilentlyContinue
            $parsed = $yaml | ConvertFrom-Yaml
            # Do not pipe the value into Should: the pipeline unrolls a collection and the
            # assertion would then see the single element rather than the list.
            $isList = $parsed.detectionAction.alertTemplate.tactics -is [System.Collections.IList]
            $isList | Should -BeTrue -Because 'the API expects a collection even with one tactic'
        }

        It 'Should produce valid JSON with the nested structure intact' {
            $json = ConvertTo-XDRCustomDetection -InputFile $script:CommunityYaml -As Json -Force -WarningAction SilentlyContinue
            $parsed = $json | ConvertFrom-Json
            # The service refuses an id that begins with a digit, so the renderer prefixes it (2026-09-16).
            $parsed.id | Should -Be 'r-81fb771a-c57e-41b8-9905-63dbf267c13f'
            $parsed.detectionAction.alertTemplate.entityMappings.accounts[0].nameColumn | Should -Be 'AccountName'
        }

        It 'Should not prompt for a category choice on a multi-tactic rule' {
            # No -Force. The legacy shape asked the user to pick one alertCategory; the
            # Graph path picks the first tactic in source order and REPORTS the loss as a
            # finding instead, so there is still nothing to confirm interactively.
            $result = ConvertTo-XDRCustomDetection -InputFile $script:CommunityYaml -As Object -WarningAction SilentlyContinue
            $result.Blocked | Should -BeFalse
            @($result.Rule.detectionAction.alertTemplate.tactics).Count | Should -Be 1
        }
    }

    Context 'Format switching' {

        It 'Should default to the Graph shape' {
            $result = ConvertTo-XDRCustomDetection -InputFile $script:CommunityYaml -As Object -Force -WarningAction SilentlyContinue
            $result.Format | Should -Be 'Graph'
            $result.Rule.Keys | Should -Contain 'queryCondition'
        }

        It 'Should still produce the legacy shape on request' {
            $result = ConvertTo-XDRCustomDetection -InputFile $script:CommunityYaml -Format XDRConverter -As Object -Force -WarningAction SilentlyContinue
            $result.Rule.Keys | Should -Contain 'ruleName'
            $result.Rule.Keys | Should -Contain 'alertCategory'
            $result.Rule.Keys | Should -Not -Contain 'queryCondition'
        }

        It 'Should share one decision engine across both shapes' {
            $graph  = (ConvertTo-XDRCustomDetection -InputFile $script:CommunityYaml -As Object -Force -WarningAction SilentlyContinue).Rule
            $legacy = (ConvertTo-XDRCustomDetection -InputFile $script:CommunityYaml -Format XDRConverter -As Object -Force -WarningAction SilentlyContinue).Rule
            $graph.id | Should -Be "r-$($legacy['guid'])"
            $graph.displayName | Should -Be $legacy['ruleName']
            $graph.queryCondition.queryText | Should -Be $legacy['queryText']
        }
    }

    Context 'Export-XDRCustomDetection' {

        BeforeAll {
            $script:ExportDir = Join-Path $script:TestRoot 'export'
        }

        It 'Should write both YAML and JSON per rule by default' {
            $out = Join-Path $script:ExportDir 'both'
            Get-SentinelAnalyticsRule -Path $script:CommunityYaml |
                ConvertTo-XDRCustomDetection -As Object -Force -WarningAction SilentlyContinue |
                Export-XDRCustomDetection -Path $out -Force
            (Test-Path (Join-Path $out '81fb771a-c57e-41b8-9905-63dbf267c13f.yaml')) | Should -BeTrue
            (Test-Path (Join-Path $out '81fb771a-c57e-41b8-9905-63dbf267c13f.json')) | Should -BeTrue
        }

        It 'Should write a deploy-ready JSON payload' {
            $out = Join-Path $script:ExportDir 'json'
            Get-SentinelAnalyticsRule -Path $script:CommunityYaml |
                ConvertTo-XDRCustomDetection -As Object -Force -WarningAction SilentlyContinue |
                Export-XDRCustomDetection -Path $out -Format Json -Force
            $payload = Get-Content (Join-Path $out '81fb771a-c57e-41b8-9905-63dbf267c13f.json') -Raw | ConvertFrom-Json
            $payload.queryCondition.queryText | Should -Not -BeNullOrEmpty
            $payload.schedule.frequency | Should -Be 'PT1H'
        }

        It 'Should combine rules into one JSON array' {
            $out = Join-Path $script:ExportDir 'combined'
            Get-SentinelAnalyticsRule -Path $script:TestRoot -WarningAction SilentlyContinue |
                ConvertTo-XDRCustomDetection -As Object -Force -WarningAction SilentlyContinue |
                Export-XDRCustomDetection -Path $out -Format Json -Combine -Force
            $combined = Get-Content (Join-Path $out 'customDetections.json') -Raw | ConvertFrom-Json
            @($combined).Count | Should -BeGreaterOrEqual 3
        }

        It 'Should skip blocked rules rather than writing an empty detection' {
            $out = Join-Path $script:ExportDir 'blocked'
            Get-SentinelAnalyticsRule -Path $script:FusionRule |
                ConvertTo-XDRCustomDetection -As Object -Force -WarningAction SilentlyContinue |
                Export-XDRCustomDetection -Path $out -Force
            @(Get-ChildItem -Path $out -ErrorAction SilentlyContinue).Count | Should -Be 0
        }

        It 'Should report pre-existing files once, not once per file' {
            $out = Join-Path $script:ExportDir 'rerun'
            $detections = @(Get-SentinelAnalyticsRule -Path $script:TestRoot -WarningAction SilentlyContinue |
                ConvertTo-XDRCustomDetection -As Object -Force -WarningAction SilentlyContinue |
                Where-Object { -not $_.Blocked })
            $detections.Count | Should -BeGreaterThan 1

            $detections | Export-XDRCustomDetection -Path $out -Force

            # Second pass over the same folder: several rules, two files each, one warning.
            $warnings = @()
            $detections | Export-XDRCustomDetection -Path $out -WarningVariable +warnings
            $warnings.Count | Should -Be 1 -Because 'a per-file warning would bury everything else in a real run'
            $warnings[0] | Should -Match 'already existed'
            $warnings[0] | Should -Match '-Force'
        }

        It 'Should not warn when -Force is given' {
            $out = Join-Path $script:ExportDir 'rerun-force'
            $detections = @(Get-SentinelAnalyticsRule -Path $script:CommunityYaml |
                ConvertTo-XDRCustomDetection -As Object -Force -WarningAction SilentlyContinue)
            $detections | Export-XDRCustomDetection -Path $out -Force
            $warnings = @()
            $detections | Export-XDRCustomDetection -Path $out -Force -WarningVariable +warnings
            $warnings.Count | Should -Be 0
        }

        It 'Should not overwrite two rules onto one filename' {
            $out = Join-Path $script:ExportDir 'collide'
            $detections = @(
                Get-SentinelAnalyticsRule -Path $script:CommunityYaml | ConvertTo-XDRCustomDetection -As Object -Force -WarningAction SilentlyContinue
                Get-SentinelAnalyticsRule -Path $script:CommunityYaml | ConvertTo-XDRCustomDetection -As Object -Force -WarningAction SilentlyContinue
            )
            $detections | Export-XDRCustomDetection -Path $out -Format Yaml -NameBy DisplayName -Force
            @(Get-ChildItem -Path $out -Filter '*.yaml').Count | Should -Be 2
        }
    }

    Context 'Deployment cmdlets' {

        It 'Should preview a deployment with -WhatIf without calling the API' {
            $results = @(
                Get-SentinelAnalyticsRule -Path $script:CommunityYaml |
                    ConvertTo-XDRCustomDetection -As Object -Force -WarningAction SilentlyContinue |
                    New-XDRCustomDetection -WhatIf -AccessToken 'test-token'
            )
            $results.Count | Should -Be 1
            $results[0].Status | Should -Be 'WhatIf'
            # The deployment result carries the id that would be SENT, which the renderer
            # prefixed because the service refuses an id that begins with a digit.
            $results[0].Id | Should -Be 'r-81fb771a-c57e-41b8-9905-63dbf267c13f'
        }

        It 'Should refuse to deploy a rule that was blocked during conversion' {
            $results = @(
                Get-SentinelAnalyticsRule -Path $script:FusionRule |
                    ConvertTo-XDRCustomDetection -As Object -Force -WarningAction SilentlyContinue |
                    New-XDRCustomDetection -WhatIf -AccessToken 'test-token' -WarningAction SilentlyContinue
            )
            $results.Count | Should -Be 0
        }

        It 'Should refuse to deploy the legacy XDRConverter shape' {
            $results = @(
                Get-SentinelAnalyticsRule -Path $script:CommunityYaml |
                    ConvertTo-XDRCustomDetection -Format XDRConverter -As Object -Force -WarningAction SilentlyContinue |
                    New-XDRCustomDetection -WhatIf -AccessToken 'test-token' -WarningAction SilentlyContinue
            )
            $results.Count | Should -Be 0
        }

        It 'Should require confirmation for deployment (ConfirmImpact High)' {
            $metadata = (Get-Command New-XDRCustomDetection).ScriptBlock.Ast.Body.ParamBlock.Attributes |
                Where-Object { $_.TypeName.Name -eq 'CmdletBinding' }
            $confirmImpact = $metadata.NamedArguments | Where-Object { $_.ArgumentName -eq 'ConfirmImpact' }
            $confirmImpact.Argument.Value | Should -Be 'High'
        }

        It 'Should support -WhatIf on the destructive cmdlets' {
            (Get-Command Remove-XDRCustomDetection).Parameters.Keys | Should -Contain 'WhatIf'
            (Get-Command Set-XDRCustomDetection).Parameters.Keys    | Should -Contain 'WhatIf'
        }

        It 'Should cache tokens through Connect-SentinelToXDR without exposing them' {
            $context = Connect-SentinelToXDR -GraphAccessToken 'test-token'
            $context.GraphToken | Should -Be 'cached'
            ($context.PSObject.Properties.Name) | Should -Not -Contain 'Token'
            InModuleScope SentinelToXDR { $script:S2XTokenCache = @{}; $script:S2XAuthMode = $null }
        }
    }

    Context 'Unresolved ARM parameters must not delete a rule' {

        # Found by running the module over the full Azure-Sentinel corpus, not by the
        # suite: 5,162 rules went in and 5,161 came out. One rule referenced an ARM
        # template parameter with no default value, the hard [int] cast on
        # triggerThreshold threw while the rule was being normalized, and the rule
        # vanished — no verdict, no diagnostic, no line in the report. A rule that
        # silently disappears is the worst outcome this module has, because the report
        # looks complete.

        It 'Should keep a rule whose triggerThreshold is an unresolved ARM parameter' {
            $path = Join-Path $script:TestRoot 'unresolved-threshold.json'
            Set-Content -LiteralPath $path -Encoding utf8NoBOM -Value @'
{
  "type": "Microsoft.OperationalInsights/workspaces/providers/alertRules",
  "kind": "Scheduled",
  "name": "unresolved-threshold-rule",
  "properties": {
    "displayName": "Rule with a parameterized threshold",
    "description": "The threshold comes from a template parameter that has no default.",
    "severity": "Medium",
    "enabled": true,
    "query": "DeviceProcessEvents | where FileName == 'powershell.exe'",
    "queryFrequency": "PT1H",
    "queryPeriod": "PT1H",
    "triggerOperator": "gt",
    "triggerThreshold": "[parameters('triggerThreshold')]",
    "tactics": [ "Execution" ]
  }
}
'@
            $rules = @(Get-SentinelAnalyticsRule -Path $path -WarningAction SilentlyContinue)

            $rules.Count            | Should -Be 1 -Because 'an unreadable threshold must cost the threshold, not the rule'
            $rules[0].DisplayName   | Should -Be 'Rule with a parameterized threshold'
            $rules[0].Query         | Should -Match 'DeviceProcessEvents'
            $rules[0].TriggerThreshold | Should -BeNullOrEmpty
        }

        It 'Should say why the threshold was not read' {
            $path = Join-Path $script:TestRoot 'unresolved-threshold-warn.json'
            Set-Content -LiteralPath $path -Encoding utf8NoBOM -Value @'
{
  "type": "Microsoft.OperationalInsights/workspaces/providers/alertRules",
  "kind": "Scheduled",
  "name": "unresolved-threshold-warn",
  "properties": {
    "displayName": "Threshold warning rule",
    "severity": "Low",
    "query": "DeviceEvents",
    "queryFrequency": "PT1H",
    "queryPeriod": "PT1H",
    "triggerOperator": "gt",
    "triggerThreshold": "[parameters('triggerThreshold')]"
  }
}
'@
            $warnings = @()
            Get-SentinelAnalyticsRule -Path $path -WarningVariable warnings -WarningAction SilentlyContinue | Out-Null

            ($warnings -join ' ') | Should -Match 'triggerThreshold'
            ($warnings -join ' ') | Should -Match 'ARM template parameter'
        }

        It 'Should not read a blank ARM authoring template as a rule' {
            # The second half of the same count discrepancy. Azure-Sentinel ships a template
            # for people to fill in at Tools/ARM-Templates/.../ScheduledRule.json. It
            # declares a kind, a displayName and a query — all of them parameters with no
            # default — so it passed the "a query is decisive" test, was read as a rule, and
            # then produced no converted output. 5,162 in, 5,161 out. Nothing failed to
            # migrate; there was never a detection in the file.
            $path = Join-Path $script:TestRoot 'arm-scaffold.json'
            Set-Content -LiteralPath $path -Encoding utf8NoBOM -Value @'
{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "parameters": {
    "ruleDisplayName": { "type": "string" },
    "query": { "type": "string" },
    "queryFrequency": { "type": "string" }
  },
  "resources": [
    {
      "type": "Microsoft.OperationalInsights/workspaces/providers/alertRules",
      "apiVersion": "2023-02-01",
      "kind": "Scheduled",
      "name": "scaffold",
      "properties": {
        "displayName": "[parameters('ruleDisplayName')]",
        "query": "[parameters('query')]",
        "queryFrequency": "[parameters('queryFrequency')]",
        "severity": "Medium"
      }
    }
  ]
}
'@
            @(Get-SentinelAnalyticsRule -Path $path -WarningAction SilentlyContinue).Count | Should -Be 0
        }

        It 'Should say the file is a template, not report a broken rule' {
            $path = Join-Path $script:TestRoot 'arm-scaffold-msg.json'
            Set-Content -LiteralPath $path -Encoding utf8NoBOM -Value @'
{
  "type": "Microsoft.OperationalInsights/workspaces/providers/alertRules",
  "kind": "Scheduled",
  "name": "scaffold-msg",
  "properties": {
    "displayName": "[parameters('ruleDisplayName')]",
    "query": "[parameters('query')]",
    "severity": "Medium"
  }
}
'@
            $warnings = @()
            Get-SentinelAnalyticsRule -Path $path -WarningVariable warnings -WarningAction SilentlyContinue | Out-Null

            ($warnings -join ' ') | Should -Match 'template'
            ($warnings -join ' ') | Should -Match 'Nothing failed to migrate'
        }

        It 'Should keep a rule whose query is a parameter that HAS a default value' {
            # The trap in the scaffold guard, and a far worse bug than the one it fixes.
            # Content Hub mainTemplate.json routinely writes the query as
            # "[parameters('query')]" with the real KQL sitting in the parameter's
            # defaultValue. Testing the raw text would discard a large share of Content Hub
            # content. Only a parameter that resolves to nothing is a scaffold.
            $path = Join-Path $script:TestRoot 'resolvable-query.json'
            Set-Content -LiteralPath $path -Encoding utf8NoBOM -Value @'
{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "parameters": {
    "ruleName": { "type": "string", "defaultValue": "A real Content Hub rule" },
    "query":    { "type": "string", "defaultValue": "DeviceProcessEvents | where FileName == 'evil.exe'" }
  },
  "resources": [
    {
      "type": "Microsoft.OperationalInsights/workspaces/providers/alertRules",
      "apiVersion": "2023-02-01",
      "kind": "Scheduled",
      "name": "real-rule",
      "properties": {
        "displayName": "[parameters('ruleName')]",
        "query": "[parameters('query')]",
        "queryFrequency": "PT1H",
        "queryPeriod": "PT1H",
        "severity": "High"
      }
    }
  ]
}
'@
            @(Get-SentinelAnalyticsRule -Path $path -WarningAction SilentlyContinue).Count |
                Should -Be 1 -Because 'a parameter with a default resolves to real KQL; this is a rule'
        }

        It 'Should keep a real rule that uses a parameter somewhere other than the query' {
            # The guard keys on the QUERY. A genuine rule can carry an unresolved parameter
            # in a peripheral field and must not be thrown away for it.
            $path = Join-Path $script:TestRoot 'param-elsewhere.json'
            Set-Content -LiteralPath $path -Encoding utf8NoBOM -Value @'
{
  "type": "Microsoft.OperationalInsights/workspaces/providers/alertRules",
  "kind": "Scheduled",
  "name": "param-elsewhere",
  "properties": {
    "displayName": "Real rule with a parameterized threshold",
    "query": "DeviceProcessEvents | where FileName == 'rundll32.exe'",
    "queryFrequency": "PT1H",
    "queryPeriod": "PT1H",
    "triggerOperator": "gt",
    "triggerThreshold": "[parameters('threshold')]",
    "severity": "Medium"
  }
}
'@
            $rules = @(Get-SentinelAnalyticsRule -Path $path -WarningAction SilentlyContinue)
            $rules.Count          | Should -Be 1
            $rules[0].DisplayName | Should -Be 'Real rule with a parameterized threshold'
        }

        It 'Should still read a threshold that is a number written as a string' {
            # ARM and YAML both quote numbers freely. Tightening the parse must not start
            # dropping thresholds that were perfectly readable before.
            $path = Join-Path $script:TestRoot 'string-threshold.json'
            Set-Content -LiteralPath $path -Encoding utf8NoBOM -Value @'
{
  "type": "Microsoft.OperationalInsights/workspaces/providers/alertRules",
  "kind": "Scheduled",
  "name": "string-threshold-rule",
  "properties": {
    "displayName": "Quoted threshold rule",
    "severity": "Low",
    "query": "DeviceEvents",
    "queryFrequency": "PT1H",
    "queryPeriod": "PT1H",
    "triggerOperator": "gt",
    "triggerThreshold": "5"
  }
}
'@
            $rules = @(Get-SentinelAnalyticsRule -Path $path -WarningAction SilentlyContinue)
            $rules[0].TriggerThreshold | Should -Be 5
        }
    }

    Context 'Placeholders are not blocked rules' {

        It 'Should not read a redirect stub as an analytics rule' {
            # A content repository leaves these behind when a rule moves: an id, a name, a
            # kind, no query. Azure-Sentinel has 312. Reporting them as Blocked says 312
            # detections cannot migrate, when there was never a detection in the file.
            $path = Join-Path $script:TestRoot 'placeholder.yaml'
            Set-Content -LiteralPath $path -Encoding utf8NoBOM -Value @'
id: 4cc63b34-61ec-4043-ae2f-c1424bf303da
name: Guest accounts added in Entra ID Groups other than the ones specified
description: |
  'As part of content migration, this file is moved to a new location. You can find it here https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Entra/Rule.yaml'
version: 1.0.4
kind: Scheduled
'@
            @(Get-SentinelAnalyticsRule -Path $path -WarningAction SilentlyContinue).Count | Should -Be 0
        }

        It 'Should say it is a placeholder and where the rule went' {
            # 'No query and no displayName/name' is wrong here — it has a name — and sends
            # the reader hunting for a parsing bug that does not exist.
            $path = Join-Path $script:TestRoot 'placeholder-msg.yaml'
            Set-Content -LiteralPath $path -Encoding utf8NoBOM -Value @'
id: 4cc63b34-61ec-4043-ae2f-c1424bf303db
name: Moved rule
description: |
  'As part of content migration, this file is moved to a new location. You can find it here https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Entra/Moved.yaml'
kind: Scheduled
'@
            $warnings = @()
            Get-SentinelAnalyticsRule -Path $path -WarningVariable warnings -WarningAction SilentlyContinue | Out-Null
            ($warnings -join ' ') | Should -Match 'placeholder'
            ($warnings -join ' ') | Should -Match 'Solutions/Entra/Moved.yaml'
        }

        It 'Should keep a real rule whose description mentions a content migration' {
            # The guard must key on the ABSENCE of a query, not on the words. A rule that
            # mentions its own migration history is still a rule.
            $path = Join-Path $script:TestRoot 'real-with-migration-note.yaml'
            Set-Content -LiteralPath $path -Encoding utf8NoBOM -Value @'
id: 4cc63b34-61ec-4043-ae2f-c1424bf303dc
name: Real rule mentioning migration
description: |
  As part of content migration, this file is moved to a new location - but it still has a query.
kind: Scheduled
severity: Medium
queryFrequency: PT1H
queryPeriod: PT1H
query: |
  DeviceProcessEvents | take 5
'@
            $rules = @(Get-SentinelAnalyticsRule -Path $path -WarningAction SilentlyContinue)
            $rules.Count | Should -Be 1
            $rules[0].DisplayName | Should -Be 'Real rule mentioning migration'
        }

        It 'Should not warn per placeholder when scanning a folder, only once for an empty result' {
            # Scanning a content repo hits hundreds of them; a warning each is noise the
            # user did not ask for. A scan that found NOTHING gets one summary line naming
            # the count and the first reason, because 'nothing to migrate' on its own sent a
            # user looking in the wrong place (2026-09-16).
            $folder = Join-Path $script:TestRoot 'scan-placeholders'
            New-Item -ItemType Directory -Path $folder -Force | Out-Null
            Set-Content -LiteralPath (Join-Path $folder 'stub.yaml') -Encoding utf8NoBOM -Value @'
id: 4cc63b34-61ec-4043-ae2f-c1424bf303dd
name: Stub
description: |
  'As part of content migration, this file is moved to a new location.'
kind: Scheduled
'@
            $warnings = @()
            $rules = @(Get-SentinelAnalyticsRule -Path $folder -Recurse -WarningVariable warnings -WarningAction SilentlyContinue)
            $rules.Count | Should -Be 0
            @($warnings).Count | Should -Be 1
            [string]$warnings[0] | Should -Match '^Scanned 1 file'
            [string]$warnings[0] | Should -Match 'placeholder'
        }
    }

    Context 'Display names that look like something else' {

        It 'Should keep a display name that contains a slash' {
            # Regression: the ARM guard rejected any root name containing '/', because a
            # resource name is a path. Real rules are called 'Devices flapping
            # online/offline' and 'IPS/IDS disabled' — 94 rules in the Azure-Sentinel
            # corpus came back with no name at all, which is an unactionable row in a
            # migration report.
            $path = Join-Path $script:TestRoot 'slash-name.yaml'
            Set-Content -LiteralPath $path -Encoding utf8NoBOM -Value @'
id: 7b1e0000-0000-4000-8000-00000000abcd
name: "Devices flapping online/offline"
kind: Scheduled
severity: Medium
queryFrequency: PT1H
queryPeriod: PT1H
query: |
  DeviceInfo
'@
            (Get-SentinelAnalyticsRule -Path $path).DisplayName | Should -Be 'Devices flapping online/offline'
        }

        It 'Should keep a display name that starts with a bracketed prefix' {
            # '[Entra ID] Privileged Role Assigned to User' is a naming convention, not an
            # ARM template expression.
            $path = Join-Path $script:TestRoot 'bracket-name.yaml'
            Set-Content -LiteralPath $path -Encoding utf8NoBOM -Value @'
id: 7b1e0000-0000-4000-8000-00000000abce
name: "[Entra ID] Privileged Role Assigned to User"
kind: Scheduled
severity: Medium
queryFrequency: PT1H
queryPeriod: PT1H
query: |
  AuditLogs
'@
            (Get-SentinelAnalyticsRule -Path $path).DisplayName | Should -Be '[Entra ID] Privileged Role Assigned to User'
        }

        It 'Should still refuse an ARM resource path as a display name' {
            # The case the guard exists for must keep working: the ARM resource 'name' is
            # a path, and using it as the display name would be gibberish in the report.
            $path = Join-Path $script:TestRoot 'arm-resource-name.json'
            Set-Content -LiteralPath $path -Encoding utf8NoBOM -Value @'
{
  "type": "Microsoft.SecurityInsights/alertRules",
  "name": "law-soc/Microsoft.SecurityInsights/alertRules/7b1e0000-0000-4000-8000-00000000abcf",
  "kind": "Scheduled",
  "properties": {
    "displayName": "Real Display Name",
    "severity": "Medium",
    "queryFrequency": "PT1H",
    "queryPeriod": "PT1H",
    "query": "DeviceInfo"
  }
}
'@
            (Get-SentinelAnalyticsRule -Path $path).DisplayName | Should -Be 'Real Display Name'
        }

        It 'Should still refuse an ARM template expression as a display name' {
            $path = Join-Path $script:TestRoot 'arm-expression-name.json'
            Set-Content -LiteralPath $path -Encoding utf8NoBOM -Value @'
{
  "type": "Microsoft.SecurityInsights/alertRules",
  "name": "[concat(parameters('workspace'),'/Microsoft.SecurityInsights/alertRules/7b1e0000-0000-4000-8000-00000000abd0')]",
  "kind": "Scheduled",
  "properties": {
    "severity": "Medium",
    "queryFrequency": "PT1H",
    "queryPeriod": "PT1H",
    "query": "DeviceInfo"
  }
}
'@
            $rule = Get-SentinelAnalyticsRule -Path $path -WarningAction SilentlyContinue
            $rule.DisplayName | Should -Not -Match 'concat'
        }
    }

    Context 'Query validation pacing' {

        It 'Should pace a batch, sleeping once between each pair of queries' {
            # Regression: the pacing flag used to be a plain variable set from inside a
            # nested function, so the assignment made a local copy, the flag stayed true
            # and Start-Sleep never ran. Every query then fired back to back, tripped the
            # hunting quota, and the throttling circuit-breaker abandoned the batch. The
            # count is what matters: N queries must sleep N-1 times, never 0.
            $script:SleepCount = 0
            Mock -ModuleName SentinelToXDR -CommandName Start-Sleep -MockWith { $script:SleepCount++ }
            Mock -ModuleName SentinelToXDR -CommandName Invoke-S2XRestRequest -MockWith {
                [PSCustomObject]@{ results = @() }
            }

            $detections = 1..3 | ForEach-Object {
                [PSCustomObject]@{
                    PSTypeName = 'SentinelToXDR.CustomDetection'
                    RuleName = "Rule $_"; Id = "id-$_"; Blocked = $false
                    Rule = [ordered]@{ id = "id-$_"; queryCondition = @{ queryText = 'DeviceEvents' } }
                }
            }

            $results = @($detections | Test-XDRDetectionQuery -DelayMilliseconds 50 -AccessToken 'test-token')

            $results.Count | Should -Be 3
            $script:SleepCount | Should -Be 2
        }

        It 'Should not sleep at all when -DelayMilliseconds is zero' {
            $script:SleepCount = 0
            Mock -ModuleName SentinelToXDR -CommandName Start-Sleep -MockWith { $script:SleepCount++ }
            Mock -ModuleName SentinelToXDR -CommandName Invoke-S2XRestRequest -MockWith {
                [PSCustomObject]@{ results = @() }
            }

            $detections = 1..3 | ForEach-Object {
                [PSCustomObject]@{
                    PSTypeName = 'SentinelToXDR.CustomDetection'
                    RuleName = "Rule $_"; Id = "id-$_"; Blocked = $false
                    Rule = [ordered]@{ id = "id-$_"; queryCondition = @{ queryText = 'DeviceEvents' } }
                }
            }

            $detections | Test-XDRDetectionQuery -DelayMilliseconds 0 -AccessToken 'test-token' | Out-Null
            $script:SleepCount | Should -Be 0
        }
    }

    Context 'Azure-Sentinel corpus' {

        BeforeAll {
            # Opt-in: set SENTINELTOXDR_CORPUS to a clone of Azure/Azure-Sentinel to run
            # these against the real content. Skipped everywhere else, including CI.
            $script:CorpusPath = $env:SENTINELTOXDR_CORPUS
            $script:HasCorpus = $script:CorpusPath -and (Test-Path -LiteralPath $script:CorpusPath)
        }

        It 'Should read and convert the Detections tree without throwing' -Skip:(-not $env:SENTINELTOXDR_CORPUS) {
            $detections = Join-Path $script:CorpusPath 'Detections'
            $rules = @(Get-SentinelAnalyticsRule -Path $detections -Recurse -WarningAction SilentlyContinue)
            $rules.Count | Should -BeGreaterThan 100

            $converted = @($rules | ConvertTo-XDRCustomDetection -As Object -Force `
                -WarningAction SilentlyContinue -ErrorAction SilentlyContinue)
            $converted.Count | Should -Be $rules.Count -Because 'every rule must produce a verdict, convertible or blocked'
        }

        It 'Should open rules whose filename contains [ and ]' -Skip:(-not $env:SENTINELTOXDR_CORPUS) {
            # About a dozen community rules are named '[Entra ID] ...'. Those brackets are
            # wildcard character classes to -Path, so anything but -LiteralPath fails.
            $bracketed = @(Get-ChildItem -LiteralPath $script:CorpusPath -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Extension -eq '.yaml' -and $_.Name.Contains('[') } |
                Select-Object -First 3)
            if ($bracketed.Count -eq 0) { Set-ItResult -Skipped -Because 'no bracketed filenames in this clone' }
            foreach ($file in $bracketed) {
                $rules = @(Get-SentinelAnalyticsRule -Path $file.FullName -WarningAction SilentlyContinue)
                $rules.Count | Should -BeGreaterThan 0 -Because "$($file.Name) must be readable"
            }
        }

        It 'Should not mistake data connectors and DCR templates for analytics rules' -Skip:(-not $env:SENTINELTOXDR_CORPUS) {
            $solutions = Join-Path $script:CorpusPath 'Solutions'
            $rules = @(Get-SentinelAnalyticsRule -Path $solutions -Recurse -WarningAction SilentlyContinue -ErrorAction SilentlyContinue)

            # A Content Hub solution folder holds far more non-rule YAML/JSON than rules:
            # data connector definitions, DCR templates, table schemas, solution metadata.
            # None of them carry a query, a schedule or a Sentinel rule kind.
            $connectorKinds = @('RestApiPoller', 'Customizable', 'Push', 'GCP', 'AmazonWebServicesS3',
                                'Direct', 'WebSocket', 'StorageAccountBlobContainer')
            foreach ($kind in $connectorKinds) {
                @($rules | Where-Object { $_.Kind -eq $kind }).Count | Should -Be 0 -Because "$kind is a data connector kind, not a rule kind"
            }
        }

        It 'Should never emit more than one tactic, whatever the source carries' -Skip:(-not $env:SENTINELTOXDR_CORPUS) {
            # The inverse of what this test asserted before 1.0.0. It took real rules with
            # several tactics each and required that every one survived, because that is
            # what the Graph model describes. The service refuses more than one entry
            # ('Only one tactic is currently supported.'), so the old assertion was
            # guarding the bug. Over the corpus, 1,326 rules lose tactics to this limit.
            $solutions = Join-Path $script:CorpusPath 'Solutions'
            $rules = @(Get-SentinelAnalyticsRule -Path $solutions -Recurse -WarningAction SilentlyContinue -ErrorAction SilentlyContinue |
                Where-Object { $_.Tactics.Count -gt 1 } | Select-Object -First 25)
            $rules.Count | Should -BeGreaterThan 0

            $limit = InModuleScope SentinelToXDR { (Get-GraphDetectionRuleMap).TacticConstraints.MaxTactics }
            $converted = @($rules | ConvertTo-XDRCustomDetection -As Object -Force -WarningAction SilentlyContinue)
            foreach ($detection in ($converted | Where-Object { -not $_.Blocked })) {
                $emitted = @($detection.Rule.detectionAction.alertTemplate.tactics)
                $emitted.Count | Should -BeLessOrEqual $limit -Because "'$($detection.RuleName)' must not exceed what the API accepts"

                # And every emitted tactic must carry a technique, or the POST is refused.
                foreach ($tactic in $emitted) {
                    @($tactic.techniques).Count | Should -BeGreaterThan 0 -Because "'$($detection.RuleName)': a tactic with no technique is refused"
                }
            }
        }
    }

    Context 'Lookback values match the product documentation' {

        # These four numbers are quoted from "Create custom detection rules in Microsoft
        # Defender XDR" (#lookback). They were previously INFERRED ("the lookback probably
        # equals the frequency") and all four were wrong, so the converter reported
        # confident, specific, incorrect windows. Pinned here so an edit to the data file
        # has to be a deliberate one.
        It 'Should apply the documented fixed lookback for Defender-tier data: <Frequency> -> <Lookback>' -ForEach @(
            @{ Frequency = '1H';  Lookback = 'PT4H'  }
            @{ Frequency = '3H';  Lookback = 'PT12H' }
            @{ Frequency = '12H'; Lookback = 'PT48H' }
            @{ Frequency = '24H'; Lookback = 'P30D'  }
        ) {
            $rules = InModuleScope SentinelToXDR { Get-FrequencyLookbackRules }
            $rules.FixedLookbackPerFrequency[$Frequency] | Should -Be $Lookback
        }

        It 'Should treat continuous frequency as having no scheduled lookback' {
            $rules = InModuleScope SentinelToXDR { Get-FrequencyLookbackRules }
            $rules.FixedLookbackPerFrequency['0'] | Should -Be '0'
        }

        It 'Should bound the Sentinel-tier lookback more tightly the more often a rule runs' {
            # The documented ladder: sub-hourly < 48h, hourly-to-daily <= 14d, daily+ <= 30d.
            # The previous version had this inverted.
            $rules = InModuleScope SentinelToXDR { Get-FrequencyLookbackRules }
            $tiers = @($rules.Parity.Tiers)
            $tiers[0].MaxLookbackHours | Should -Be 48
            $tiers[1].MaxLookbackHours | Should -Be 336
            $tiers[2].MaxLookbackHours | Should -Be 720
            $rules.Parity.MaxLookbackDays | Should -Be 30
        }

        It 'Should forfeit custom frequency when a query mixes Sentinel and Defender tables' {
            # Custom frequency and a configurable lookback belong to detections that read
            # Microsoft Sentinel data EXCLUSIVELY. One Defender table in the query loses
            # both for the whole rule. A migration tool that quietly kept the five-minute
            # schedule would be describing a detection the product cannot create.
            $mixed = Join-Path $script:TestRoot 'mixed-tier.yaml'
            Set-Content -LiteralPath $mixed -Value @'
id: cccc1111-2222-3333-4444-555555555555
name: Mixed tier rule
description: d
severity: Medium
kind: Scheduled
queryFrequency: PT5M
queryPeriod: P7D
tactics: [Execution]
query: SecurityEvent | join kind=inner DeviceInfo on DeviceName
'@
            $result = ConvertTo-XDRCustomDetection -InputFile $mixed -As Object -Force -WarningAction SilentlyContinue
            $result.Rule.schedule.frequency | Should -Be 'PT1H' -Because 'a mixed-tier query cannot use a custom frequency'

            $rounded = @($result.Diagnostics | Where-Object { $_.Action -eq 'Rounded' })
            $rounded.Count | Should -Be 1
            $rounded[0].Reason | Should -Match 'exclusively' -Because 'the diagnostic has to say WHY the schedule changed'
            $rounded[0].Reason | Should -Match 'DeviceInfo' -Because 'and name the table that caused it'
        }

        It 'Should keep a custom frequency for a Sentinel-only query' {
            $sentinelOnly = Join-Path $script:TestRoot 'sentinel-tier.yaml'
            Set-Content -LiteralPath $sentinelOnly -Value @'
id: dddd1111-2222-3333-4444-555555555555
name: Sentinel only rule
description: d
severity: Medium
kind: Scheduled
queryFrequency: PT5M
queryPeriod: P7D
tactics: [Execution]
query: SigninLogs | where ResultType == 0
'@
            $result = ConvertTo-XDRCustomDetection -InputFile $sentinelOnly -As Object -Force -WarningAction SilentlyContinue
            $result.Rule.schedule.frequency | Should -Be 'PT5M' -Because 'Sentinel-only detections support custom frequency'
            @($result.Diagnostics | Where-Object { $_.Action -eq 'Rounded' }).Count | Should -Be 0
        }

        It 'Should NOT claim a lookback in the Graph payload' {
            # The Graph ruleSchedule carries a frequency and nothing else: for Defender-tier
            # data the lookback is fixed by the product, and the beta API exposes no field
            # to set it. Emitting one would be inventing a value the service ignores.
            $rule = (ConvertTo-XDRCustomDetection -InputFile $script:ArmTemplate -As Object -Force -WarningAction SilentlyContinue).Rule
            $rule.schedule.Keys | Should -Be @('frequency')
            $rule.Keys | Should -Not -Contain 'lookbackPeriod'
        }

        It 'Should warn only when the fixed window is SHORTER than the rule asked for' {
            $shorter = Join-Path $script:TestRoot 'lookback-short.yaml'
            Set-Content -LiteralPath $shorter -Value @'
id: aaaa1111-2222-3333-4444-555555555555
name: Wants two weeks
description: d
severity: Medium
kind: Scheduled
queryFrequency: PT1H
queryPeriod: P14D
tactics: [Execution]
query: |
  DeviceProcessEvents
  | where FileName == "x.exe"
'@
            # Assert on the diagnostic, not the warning text: every diagnostic surfaces as
            # a warning regardless of severity, so matching text cannot tell Info from
            # Warning, and 'fixed at' vs 'FIXED' differ only by case.
            $lost = ConvertTo-XDRCustomDetection -InputFile $shorter -As Object -Force -WarningAction SilentlyContinue
            $lostFinding = @($lost.Diagnostics | Where-Object { $_.Capability -eq 'Lookback support' })
            $lostFinding.Count | Should -Be 1
            $lostFinding[0].Action | Should -Be 'Constrained' -Because 'P14D does not fit in the fixed four-hour window'
            $lostFinding[0].Severity | Should -Be 'Warning'

            $fits = Join-Path $script:TestRoot 'lookback-fits.yaml'
            Set-Content -LiteralPath $fits -Value @'
id: bbbb1111-2222-3333-4444-555555555555
name: Wants one hour
description: d
severity: Medium
kind: Scheduled
queryFrequency: PT1H
queryPeriod: PT1H
tactics: [Execution]
query: |
  DeviceProcessEvents
  | where FileName == "x.exe"
'@
            $kept = ConvertTo-XDRCustomDetection -InputFile $fits -As Object -Force -WarningAction SilentlyContinue
            $keptFinding = @($kept.Diagnostics | Where-Object { $_.Capability -eq 'Lookback support' })
            $keptFinding.Count | Should -Be 1
            $keptFinding[0].Action | Should -Be 'Mapped' -Because 'PT1H fits inside the fixed four-hour window, so nothing is lost'
            $keptFinding[0].Severity | Should -Be 'Info'
        }
    }

    Context 'Data file integrity' {

        It 'Should parse every bundled data file' {
            $dataFiles = Get-ChildItem -Path (Join-Path (Split-Path $PSScriptRoot -Parent) 'src/Data') -Filter '*.psd1'
            $dataFiles.Count | Should -BeGreaterThan 0
            foreach ($file in $dataFiles) {
                { Import-PowerShellDataFile -Path $file.FullName } | Should -Not -Throw -Because "$($file.Name) must be a valid data file"
            }
        }

        It 'Should stamp every data file with source metadata' {
            $dataFiles = Get-ChildItem -Path (Join-Path (Split-Path $PSScriptRoot -Parent) 'src/Data') -Filter '*.psd1'
            foreach ($file in $dataFiles) {
                $data = Import-PowerShellDataFile -Path $file.FullName
                $data.Keys | Should -Contain 'Metadata' -Because "$($file.Name) must record where its content came from"
            }
        }

        It 'Should map every entity type the Azure-Sentinel corpus actually uses' {
            $map = InModuleScope SentinelToXDR { Get-GraphDetectionRuleMap }
            # Entity types observed across the Azure-Sentinel analytics rule corpus.
            foreach ($entityType in @('Account', 'IP', 'Host', 'URL', 'FileHash', 'File',
                                      'AzureResource', 'Process', 'DNS', 'CloudApplication', 'RegistryKey')) {
                $map.EntityMappings.Keys | Should -Contain $entityType
            }
        }

        It 'Should map every Sentinel tactic to a Graph tactic' {
            $map = InModuleScope SentinelToXDR { Get-GraphDetectionRuleMap }
            foreach ($tactic in @('Collection', 'CommandAndControl', 'CredentialAccess', 'DefenseEvasion',
                                  'Discovery', 'Execution', 'Exfiltration', 'Impact', 'InitialAccess',
                                  'LateralMovement', 'Persistence', 'PrivilegeEscalation',
                                  'Reconnaissance', 'ResourceDevelopment', 'PreAttack',
                                  'ImpairProcessControl', 'InhibitResponseFunction')) {
                $map.Tactics.Keys | Should -Contain $tactic
                $map.Tactics[$tactic] | Should -Not -BeNullOrEmpty
            }
        }
    }
}
