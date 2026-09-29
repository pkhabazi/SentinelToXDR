Describe 'Graph payload schema conformance' {

    # The cheapest of the three validation layers, and the only one that runs with no
    # tenant: does every payload we generate actually match the documented contract?
    #
    # It cannot tell you a detection will behave correctly — that needs the product. What it
    # does catch, on every commit and across the whole community corpus, is structural
    # drift: a renamed property, a severity that stopped being lower-case, a frequency that
    # is no longer an ISO 8601 duration, a stray field the API would reject.

    BeforeAll {
        $repoRoot = Split-Path -Path $PSScriptRoot -Parent
        Import-Module -Name (Join-Path $repoRoot 'src/SentinelToXDR.psd1') -Force

        $script:Schema = Get-Content -LiteralPath (Join-Path $repoRoot 'CustomDetection.schema.json') -Raw
        $script:TestRoot = Join-Path ([System.IO.Path]::GetTempPath()) "s2x-schema-$([System.Guid]::NewGuid())"
        New-Item -ItemType Directory -Path $script:TestRoot -Force | Out-Null

        function Test-AgainstSchema {
            param([string]$Json)
            try {
                Test-Json -Json $Json -Schema $script:Schema -ErrorAction Stop | Out-Null
                return [PSCustomObject]@{ Valid = $true; Error = $null }
            } catch {
                return [PSCustomObject]@{ Valid = $false; Error = $_.Exception.Message }
            }
        }

        # A rule exercising as much of the schema as one rule can: multiple tactics,
        # subtechniques, several entity kinds, custom details.
        $script:RichRule = Join-Path $script:TestRoot 'rich.yaml'
        Set-Content -LiteralPath $script:RichRule -Encoding utf8NoBOM -Value @'
id: 11111111-2222-3333-4444-555555555555
name: Rich rule
description: Exercises most of the schema.
severity: High
kind: Scheduled
queryFrequency: PT1H
queryPeriod: PT1H
tactics:
  - InitialAccess
  - Persistence
relevantTechniques:
  - T1078
  - T1078.004
customDetails:
  SourceIp: IpAddress
  Account: AccountName
query: |
  SigninLogs
  | where ResultType == "0"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: AccountName
      - identifier: Sid
        columnName: AccountSid
  - entityType: Host
    fieldMappings:
      - identifier: HostName
        columnName: Computer
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: IpAddress
  - entityType: URL
    fieldMappings:
      - identifier: Url
        columnName: RemoteUrl
'@
    }

    AfterAll {
        if ($script:TestRoot -and (Test-Path $script:TestRoot)) {
            Remove-Item -Path $script:TestRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    Context 'Generated payloads' {

        It 'Should produce a payload that validates against the published schema' {
            $json = ConvertTo-XDRCustomDetection -InputFile $script:RichRule -As Json -Force -WarningAction SilentlyContinue
            $result = Test-AgainstSchema -Json $json
            $result.Valid | Should -BeTrue -Because $result.Error
        }

        It 'Should validate the bundled examples' {
            $repoRoot = Split-Path -Path $PSScriptRoot -Parent
            $examples = @(Get-ChildItem -LiteralPath (Join-Path $repoRoot 'Examples') -File |
                Where-Object { $_.Extension -in '.yaml', '.yml', '.json' })
            $examples.Count | Should -BeGreaterThan 0

            foreach ($example in $examples) {
                $json = ConvertTo-XDRCustomDetection -InputFile $example.FullName -As Json -Force -WarningAction SilentlyContinue
                if (-not $json) { continue }
                $result = Test-AgainstSchema -Json $json
                $result.Valid | Should -BeTrue -Because "$($example.Name): $($result.Error)"
            }
        }

        It 'Should validate a rule that carries no optional structures at all' {
            $minimal = Join-Path $script:TestRoot 'minimal.yaml'
            Set-Content -LiteralPath $minimal -Encoding utf8NoBOM -Value @'
id: 99999999-8888-7777-6666-555555555555
name: Minimal rule
description: No tactics, no entities, no custom details.
severity: Low
kind: Scheduled
queryFrequency: PT1H
queryPeriod: PT1H
query: DeviceEvents | take 1
'@
            $json = ConvertTo-XDRCustomDetection -InputFile $minimal -As Json -Force -WarningAction SilentlyContinue
            $result = Test-AgainstSchema -Json $json
            $result.Valid | Should -BeTrue -Because $result.Error
        }
    }

    Context 'Negative controls' {

        # A validator that never rejects anything proves nothing. Each of these is a
        # mistake the converter could plausibly make; the schema has to catch every one.

        BeforeAll {
            $script:BasePayload = ConvertTo-XDRCustomDetection -InputFile $script:RichRule -As Json -Force -WarningAction SilentlyContinue
        }

        It 'Should reject a payload missing <Property>' -ForEach @(
            @{ Property = 'queryCondition' }
            @{ Property = 'schedule' }
            @{ Property = 'displayName' }
            @{ Property = 'status' }
            @{ Property = 'id' }
        ) {
            $payload = $script:BasePayload | ConvertFrom-Json
            $payload.PSObject.Properties.Remove($Property)
            (Test-AgainstSchema -Json ($payload | ConvertTo-Json -Depth 20)).Valid | Should -BeFalse
        }

        It 'Should reject a Title Case severity (Graph expects lower case)' {
            $payload = $script:BasePayload | ConvertFrom-Json
            $payload.detectionAction.alertTemplate.severity = 'High'
            (Test-AgainstSchema -Json ($payload | ConvertTo-Json -Depth 20)).Valid | Should -BeFalse
        }

        It 'Should reject the deprecated frequency enum in place of a duration' {
            $payload = $script:BasePayload | ConvertFrom-Json
            $payload.schedule.frequency = '1H'
            (Test-AgainstSchema -Json ($payload | ConvertTo-Json -Depth 20)).Valid | Should -BeFalse
        }

        It 'Should reject a deprecated property that Microsoft removes on 2026-10-01' {
            $payload = $script:BasePayload | ConvertFrom-Json
            $payload | Add-Member -NotePropertyName 'isEnabled' -NotePropertyValue $true
            (Test-AgainstSchema -Json ($payload | ConvertTo-Json -Depth 20)).Valid | Should -BeFalse
        }

        It 'Should reject an invented entity column' {
            $payload = $script:BasePayload | ConvertFrom-Json
            $payload.detectionAction.alertTemplate.entityMappings.accounts[0] |
                Add-Member -NotePropertyName 'emailColumn' -NotePropertyValue 'Mail'
            (Test-AgainstSchema -Json ($payload | ConvertTo-Json -Depth 20)).Valid | Should -BeFalse
        }

        It 'Should reject a rule id that begins with a digit' {
            # Observed 2026-09-16: 'Rule ID must ... begin with a letter'. Most GUIDs do not.
            $payload = $script:BasePayload | ConvertFrom-Json
            $payload.id = '5a1e0001-0000-4000-8000-000000000001'
            (Test-AgainstSchema -Json ($payload | ConvertTo-Json -Depth 20)).Valid | Should -BeFalse
        }

        It 'Should reject a malformed technique id' {
            $payload = $script:BasePayload | ConvertFrom-Json
            $payload.detectionAction.alertTemplate.tactics[0].techniques[0].technique = 'TA0001'
            (Test-AgainstSchema -Json ($payload | ConvertTo-Json -Depth 20)).Valid | Should -BeFalse
        }
    }

    Context 'Azure-Sentinel corpus' {

        It 'Should produce a schema-valid payload for every convertible rule in a solution' -Skip:(-not $env:SENTINELTOXDR_CORPUS) {
            $solutions = Join-Path $env:SENTINELTOXDR_CORPUS 'Solutions'
            $rules = @(Get-SentinelAnalyticsRule -Path (Join-Path $solutions 'Microsoft Defender XDR/Analytic Rules') -Recurse -WarningAction SilentlyContinue) +
                     @(Get-SentinelAnalyticsRule -Path (Join-Path $solutions 'Windows Security Events/Analytic Rules') -Recurse -WarningAction SilentlyContinue) +
                     @(Get-SentinelAnalyticsRule -Path (Join-Path $solutions 'Microsoft Entra ID/Analytic Rules') -Recurse -WarningAction SilentlyContinue)
            $rules.Count | Should -BeGreaterThan 50

            $failures = [System.Collections.Generic.List[string]]::new()
            foreach ($detection in ($rules | ConvertTo-XDRCustomDetection -As Object -Force -WarningAction SilentlyContinue)) {
                if ($detection.Blocked) { continue }
                $result = Test-AgainstSchema -Json (($detection.Rule) | ConvertTo-Json -Depth 20)
                if (-not $result.Valid) {
                    $failures.Add("$($detection.RuleName): $($result.Error)")
                }
            }

            # Report every offender, not just the first: one systemic mistake shows up as
            # dozens of rules and the pattern is the useful part.
            $failures -join "`n" | Should -BeNullOrEmpty
        }
    }
}
