Describe 'ConvertTo-XDRCustomDetection' {

    BeforeAll {
        $ModulePath = Split-Path -Path $PSScriptRoot -Parent
        $ModulePath = Join-Path -Path $ModulePath -ChildPath 'src' | Join-Path -ChildPath 'SentinelToXDR.psd1'
        Import-Module -Name $ModulePath -Force

        # Minimal community YAML content
        $script:BasicYaml = @'
id: 81fb771a-c57e-41b8-9905-63dbf267c13f
name: Test Sentinel Rule
description: Detects suspicious sign-in activity.
severity: Medium
status: Available
queryFrequency: 1h
queryPeriod: 1h
triggerOperator: gt
triggerThreshold: 0
tactics:
  - InitialAccess
relevantTechniques:
  - T1078
query: |
  SigninLogs
  | where ResultType == "0"
entityMappings:
  - entityType: Host
    fieldMappings:
      - identifier: FullName
        columnName: HostCustomEntity
  - entityType: Account
    fieldMappings:
      - identifier: FullName
        columnName: AccountCustomEntity
version: 1.0.0
kind: Scheduled
'@

        # ARM template JSON content
        $script:ArmJson = @'
{
  "type": "Microsoft.SecurityInsights/alertRules",
  "kind": "Scheduled",
  "properties": {
    "displayName": "ARM Template Rule",
    "description": "ARM template description.",
    "severity": "High",
    "enabled": true,
    "query": "SecurityEvent | where EventID == 4625",
    "queryFrequency": "PT3H",
    "queryPeriod": "PT3H",
    "triggerOperator": "GreaterThan",
    "triggerThreshold": 0,
    "tactics": ["CredentialAccess"],
    "techniques": ["T1110"],
    "entityMappings": [
      {
        "entityType": "Host",
        "fieldMappings": [
          { "identifier": "FullName", "columnName": "Computer" }
        ]
      }
    ]
  }
}
'@

        # Multi-tactic community YAML
        $script:MultiTacticYaml = @'
id: 81fb771a-c57e-41b8-9905-63dbf267c13f
name: Multi Tactic Rule
description: Multi tactic test.
severity: Low
queryFrequency: PT12H
queryPeriod: PT12H
triggerOperator: gt
triggerThreshold: 0
tactics:
  - InitialAccess
  - Persistence
  - DefenseEvasion
relevantTechniques:
  - T1078
query: SecurityEvent | take 10
kind: Scheduled
'@

        # NRT kind YAML
        $script:NrtYaml = @'
id: 81fb771a-c57e-41b8-9905-63dbf267c13f
name: NRT Rule
description: Near real-time rule.
severity: High
tactics:
  - Execution
relevantTechniques:
  - T1059
query: SecurityEvent | take 5
kind: NRT
'@

        # Rule with unsupported entity types
        $script:UnsupportedEntityYaml = @'
id: 81fb771a-c57e-41b8-9905-63dbf267c13f
name: Unsupported Entity Rule
description: Has unsupported entity types.
severity: Medium
queryFrequency: PT1H
triggerOperator: gt
triggerThreshold: 0
tactics:
  - Exfiltration
query: SecurityEvent | take 1
entityMappings:
  - entityType: AzureResource
    fieldMappings:
      - identifier: ResourceId
        columnName: ResourceId
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: ClientIP
kind: Scheduled
'@
    }

    AfterAll {
        Remove-Module -Name SentinelToXDR -Force -ErrorAction SilentlyContinue
    }

    # -------------------------------------------------------------------------
    Context 'Parameter Validation' {

        It 'Should throw when InputFile does not exist' {
            { ConvertTo-XDRCustomDetection -Format XDRConverter -InputFile 'C:\nonexistent\rule.yaml' } | Should -Throw
        }

        It 'Should reject unsupported file extensions' {
            $tempTxt = Join-Path TestDrive: 'rule.txt'
            Set-Content -Path $tempTxt -Value 'test'
            { ConvertTo-XDRCustomDetection -Format XDRConverter -InputFile $tempTxt } | Should -Throw
        }

        It 'Should reject invalid Severity values' {
            { ConvertTo-XDRCustomDetection -Format XDRConverter -InputFile 'x.yaml' -Severity 'Critical' } | Should -Throw
        }

        It 'Should reject invalid AlertCategory values' {
            { ConvertTo-XDRCustomDetection -Format XDRConverter -InputFile 'x.yaml' -AlertCategory 'Malware' } | Should -Throw
        }

        It 'Should reject a malformed Guid override' {
            { ConvertTo-XDRCustomDetection -Format XDRConverter -InputFile 'x.yaml' -Guid 'not-a-uuid' } | Should -Throw
        }

        It 'Should accept all valid Severity values' {
            $obj = [PSCustomObject]@{ name = 'Test Rule'; query = 'SecurityEvent | take 1' }
            @('Informational', 'Low', 'Medium', 'High') | ForEach-Object {
                { $obj | ConvertTo-XDRCustomDetection -Format XDRConverter -Severity $_ -Force 3>$null } |
                    Should -Not -Throw -Because "Severity '$_' is valid"
            }
        }

        It 'Should be exported from the module' {
            Get-Command -Module SentinelToXDR -Name 'ConvertTo-XDRCustomDetection' |
                Should -Not -BeNullOrEmpty
        }
    }

    # -------------------------------------------------------------------------
    Context 'Community YAML → XDR YAML conversion' {

        It 'Should return a non-empty YAML string from a valid community YAML file' {
            $tempYaml = Join-Path TestDrive: 'basic.yaml'
            Set-Content -Path $tempYaml -Value $script:BasicYaml

            $result = ConvertTo-XDRCustomDetection -Format XDRConverter -InputFile $tempYaml -Force 3>$null
            $result | Should -Not -BeNullOrEmpty
            $result | Should -BeOfType [string]
        }

        It 'Should preserve the rule GUID' {
            $tempYaml = Join-Path TestDrive: 'guid.yaml'
            Set-Content -Path $tempYaml -Value $script:BasicYaml

            $result = ConvertTo-XDRCustomDetection -Format XDRConverter -InputFile $tempYaml -Force 3>$null
            $parsed = $result | ConvertFrom-Yaml
            $parsed.guid | Should -Be '81fb771a-c57e-41b8-9905-63dbf267c13f'
        }

        It 'Should map ruleName from the Sentinel rule name' {
            $tempYaml = Join-Path TestDrive: 'name.yaml'
            Set-Content -Path $tempYaml -Value $script:BasicYaml

            $result = ConvertTo-XDRCustomDetection -Format XDRConverter -InputFile $tempYaml -Force 3>$null
            $parsed = $result | ConvertFrom-Yaml
            $parsed.ruleName | Should -Be 'Test Sentinel Rule'
        }

        It 'Should map severity directly' {
            $tempYaml = Join-Path TestDrive: 'sev.yaml'
            Set-Content -Path $tempYaml -Value $script:BasicYaml

            $result = ConvertTo-XDRCustomDetection -Format XDRConverter -InputFile $tempYaml -Force 3>$null
            $parsed = $result | ConvertFrom-Yaml
            $parsed.alertSeverity | Should -Be 'Medium'
        }

        It 'Should override severity with -Severity parameter' {
            $tempYaml = Join-Path TestDrive: 'sev-override.yaml'
            Set-Content -Path $tempYaml -Value $script:BasicYaml

            $result = ConvertTo-XDRCustomDetection -Format XDRConverter -InputFile $tempYaml -Severity High -Force 3>$null
            $parsed = $result | ConvertFrom-Yaml
            $parsed.alertSeverity | Should -Be 'High'
        }

        It 'Should map tactics to alertCategory' {
            $tempYaml = Join-Path TestDrive: 'tactic.yaml'
            Set-Content -Path $tempYaml -Value $script:BasicYaml

            $result = ConvertTo-XDRCustomDetection -Format XDRConverter -InputFile $tempYaml -Force 3>$null
            $parsed = $result | ConvertFrom-Yaml
            $parsed.alertCategory | Should -Be 'InitialAccess'
        }

        It 'Should carry queryFrequency 1h as flexible PT1H for a SentinelOnly rule' {
            # CHANGED (Stage 2): BasicYaml queries SigninLogs (Sentinel-tier) → SentinelOnly,
            # which now carries the source frequency as a flexible ISO 8601 value instead of
            # the legacy '1H' enum. Rounding to the enum only applies to Defender/Mixed rules.
            $tempYaml = Join-Path TestDrive: 'freq.yaml'
            Set-Content -Path $tempYaml -Value $script:BasicYaml

            $result = ConvertTo-XDRCustomDetection -Format XDRConverter -InputFile $tempYaml -Force 3>$null
            $parsed = $result | ConvertFrom-Yaml
            $parsed.frequency | Should -Be 'PT1H'
        }

        It 'Should map MITRE techniques to mitreTechniques' {
            $tempYaml = Join-Path TestDrive: 'mitre.yaml'
            Set-Content -Path $tempYaml -Value $script:BasicYaml

            $result = ConvertTo-XDRCustomDetection -Format XDRConverter -InputFile $tempYaml -Force 3>$null
            $parsed = $result | ConvertFrom-Yaml
            $parsed.mitreTechniques | Should -Contain 'T1078'
        }

        It 'Should map Host entity to Machine' {
            $tempYaml = Join-Path TestDrive: 'entity.yaml'
            Set-Content -Path $tempYaml -Value $script:BasicYaml

            $result = ConvertTo-XDRCustomDetection -Format XDRConverter -InputFile $tempYaml -Force 3>$null
            $parsed = $result | ConvertFrom-Yaml
            $hostEntity = $parsed.impactedEntities | Where-Object { $_.entityType -eq 'Machine' }
            $hostEntity | Should -Not -BeNullOrEmpty
            $hostEntity.entityIdentifier | Should -Be 'HostCustomEntity'
        }

        It 'Should map Account entity to User' {
            $tempYaml = Join-Path TestDrive: 'account.yaml'
            Set-Content -Path $tempYaml -Value $script:BasicYaml

            $result = ConvertTo-XDRCustomDetection -Format XDRConverter -InputFile $tempYaml -Force 3>$null
            $parsed = $result | ConvertFrom-Yaml
            $userEntity = $parsed.impactedEntities | Where-Object { $_.entityType -eq 'User' }
            $userEntity | Should -Not -BeNullOrEmpty
        }

        It 'Should use -AlertTitle override instead of rule name' {
            $tempYaml = Join-Path TestDrive: 'title.yaml'
            Set-Content -Path $tempYaml -Value $script:BasicYaml

            $result = ConvertTo-XDRCustomDetection -Format XDRConverter -InputFile $tempYaml -AlertTitle 'My Custom Alert Title' -Force 3>$null
            $parsed = $result | ConvertFrom-Yaml
            $parsed.alertTitle | Should -Be 'My Custom Alert Title'
        }

        It 'Should use rule name as alertTitle when -AlertTitle is not specified' {
            $tempYaml = Join-Path TestDrive: 'title-default.yaml'
            Set-Content -Path $tempYaml -Value $script:BasicYaml

            $result = ConvertTo-XDRCustomDetection -Format XDRConverter -InputFile $tempYaml -Force 3>$null
            $parsed = $result | ConvertFrom-Yaml
            $parsed.alertTitle | Should -Be 'Test Sentinel Rule'
        }

        It 'Should write output to a file when -OutputFile is specified' {
            $tempYaml   = Join-Path TestDrive: 'out-file-src.yaml'
            $outputFile = Join-Path TestDrive: 'out-file-dest.yaml'
            Set-Content -Path $tempYaml -Value $script:BasicYaml

            ConvertTo-XDRCustomDetection -Format XDRConverter -InputFile $tempYaml -OutputFile $outputFile -Force 3>$null
            $outputFile | Should -Exist
            (Get-Content $outputFile -Raw) | Should -Not -BeNullOrEmpty
        }

        It 'Should write a file named by GUID when -UseIdAsFilename is used' {
            $outFolder = Join-Path TestDrive: 'GuidOut'

            $sentinelObj = $script:BasicYaml | ConvertFrom-Yaml
            ConvertTo-XDRCustomDetection -Format XDRConverter -InputObject $sentinelObj -UseIdAsFilename -OutputFolder $outFolder -Force 3>$null

            (Join-Path $outFolder '81fb771a-c57e-41b8-9905-63dbf267c13f.yaml') | Should -Exist
        }

        It 'Should write through a PowerShell drive to the folder the drive maps, not the root of the disk' {
            # On Windows a drive-qualified path used to lose its drive between the provider
            # cmdlets and [System.IO.Path], so 'TestDrive:\GuidOut' was written to 'D:\GuidOut'.
            $real = Join-Path $TestDrive 'mapped'
            New-Item -ItemType Directory -Path $real -Force | Out-Null
            New-PSDrive -Name S2XOut -PSProvider FileSystem -Root $real -Scope Global | Out-Null
            try {
                $sentinelObj = $script:BasicYaml | ConvertFrom-Yaml
                ConvertTo-XDRCustomDetection -Format XDRConverter -InputObject $sentinelObj -OutputFile 'S2XOut:\one.yaml' -Force 3>$null
                ConvertTo-XDRCustomDetection -Format XDRConverter -InputObject $sentinelObj -UseIdAsFilename -OutputFolder 'S2XOut:\byid' -Force 3>$null
                $sentinelObj | ConvertTo-XDRCustomDetection -Format XDRConverter -Force -WriteBatchSummary -BatchSummaryPath 'S2XOut:\batch' 3>$null | Out-Null

                Join-Path $real 'one.yaml' | Should -Exist
                Join-Path $real 'byid/81fb771a-c57e-41b8-9905-63dbf267c13f.yaml' | Should -Exist
                Join-Path $real 'batch.summary.json' | Should -Exist
            } finally {
                Remove-PSDrive -Name S2XOut -Scope Global -ErrorAction SilentlyContinue
            }
        }
    }

    # -------------------------------------------------------------------------
    Context 'ARM template JSON format' {

        It 'Should convert an ARM template JSON file' {
            $tempJson = Join-Path TestDrive: 'arm.json'
            Set-Content -Path $tempJson -Value $script:ArmJson

            $result = ConvertTo-XDRCustomDetection -Format XDRConverter -InputFile $tempJson -Force 3>$null
            $result | Should -Not -BeNullOrEmpty
        }

        It 'Should extract displayName from ARM properties' {
            $tempJson = Join-Path TestDrive: 'arm-name.json'
            Set-Content -Path $tempJson -Value $script:ArmJson

            $result = ConvertTo-XDRCustomDetection -Format XDRConverter -InputFile $tempJson -Force 3>$null
            $parsed = $result | ConvertFrom-Yaml
            $parsed.ruleName | Should -Be 'ARM Template Rule'
        }

        It 'Should map ARM severity correctly' {
            $tempJson = Join-Path TestDrive: 'arm-sev.json'
            Set-Content -Path $tempJson -Value $script:ArmJson

            $result = ConvertTo-XDRCustomDetection -Format XDRConverter -InputFile $tempJson -Force 3>$null
            $parsed = $result | ConvertFrom-Yaml
            $parsed.alertSeverity | Should -Be 'High'
        }

        It 'Should use techniques from ARM properties.techniques' {
            $tempJson = Join-Path TestDrive: 'arm-tech.json'
            Set-Content -Path $tempJson -Value $script:ArmJson

            $result = ConvertTo-XDRCustomDetection -Format XDRConverter -InputFile $tempJson -Force 3>$null
            $parsed = $result | ConvertFrom-Yaml
            $parsed.mitreTechniques | Should -Contain 'T1110'
        }

        It 'Should carry ISO 8601 PT3H as flexible PT3H for a SentinelOnly rule' {
            # CHANGED (Stage 2): the ARM fixture queries SecurityEvent (Sentinel-tier) →
            # SentinelOnly, so PT3H is now carried as the flexible value 'PT3H' rather than
            # rounded to the '3H' enum. (PT3H happens to equal a bucket, but the flexible
            # path emits the ISO 8601 form.) Defender/Mixed rules still round to the enum.
            $tempJson = Join-Path TestDrive: 'arm-freq.json'
            Set-Content -Path $tempJson -Value $script:ArmJson

            $result = ConvertTo-XDRCustomDetection -Format XDRConverter -InputFile $tempJson -Force 3>$null
            $parsed = $result | ConvertFrom-Yaml
            $parsed.frequency | Should -Be 'PT3H'
        }
    }

    # -------------------------------------------------------------------------
    Context 'Mapping gaps — frequency rounding (DefenderOnly / constrained path)' {

        # CHANGED (Stage 2): rounding to the legacy enum now only applies to the
        # CONSTRAINED path (DefenderOnly / Mixed rules). All fixtures here therefore
        # query the Defender-only table DeviceProcessEvents so the rounding behavior
        # is still exercised. (Previously these used SecurityEvent, which is now
        # SentinelOnly and carried flexibly — see the flexible-frequency tests.)

        It 'Should round PT30M to 1H with a warning (DefenderOnly)' {
            $yaml = @'
id: 81fb771a-c57e-41b8-9905-63dbf267c13f
name: Fast Rule
description: desc
severity: Medium
queryFrequency: PT30M
triggerOperator: gt
triggerThreshold: 0
tactics:
  - Execution
query: DeviceProcessEvents | take 1
kind: Scheduled
'@
            $tempYaml = Join-Path TestDrive: 'freq-30m.yaml'
            Set-Content -Path $tempYaml -Value $yaml

            $warnings = @()
            $result = ConvertTo-XDRCustomDetection -Format XDRConverter -InputFile $tempYaml -Force -WarningVariable warnings 3>$null
            $parsed = $result | ConvertFrom-Yaml
            $parsed.frequency | Should -Be '1H'
            $warnings | Where-Object { $_ -match 'rounded' } | Should -Not -BeNullOrEmpty
        }

        It 'Should round P7D to 24H with a warning (DefenderOnly)' {
            $yaml = @'
id: 81fb771a-c57e-41b8-9905-63dbf267c13f
name: Weekly Rule
description: desc
severity: High
queryFrequency: P7D
triggerOperator: gt
triggerThreshold: 0
tactics:
  - Discovery
query: DeviceProcessEvents | take 1
kind: Scheduled
'@
            $tempYaml = Join-Path TestDrive: 'freq-7d.yaml'
            Set-Content -Path $tempYaml -Value $yaml

            $warnings = @()
            $result = ConvertTo-XDRCustomDetection -Format XDRConverter -InputFile $tempYaml -Force -WarningVariable warnings 3>$null
            $parsed = $result | ConvertFrom-Yaml
            $parsed.frequency | Should -Be '24H'
            $warnings | Where-Object { $_ -match 'rounded' } | Should -Not -BeNullOrEmpty
        }

        It 'Should map exact 12h shorthand to 12H without rounding warning (DefenderOnly)' {
            $yaml = @'
id: 81fb771a-c57e-41b8-9905-63dbf267c13f
name: 12H Rule
description: desc
severity: Medium
queryFrequency: 12h
triggerOperator: gt
triggerThreshold: 0
tactics:
  - Persistence
query: DeviceProcessEvents | take 1
kind: Scheduled
'@
            $tempYaml = Join-Path TestDrive: 'freq-12h.yaml'
            Set-Content -Path $tempYaml -Value $yaml

            $warnings = @()
            ConvertTo-XDRCustomDetection -Format XDRConverter -InputFile $tempYaml -Force -WarningVariable warnings 3>$null | Out-Null
            $warnings | Where-Object { $_ -match 'rounded' } | Should -BeNullOrEmpty
        }
    }

    # -------------------------------------------------------------------------
    Context 'Stage 2 — Flexible frequency & lookback (SentinelOnly)' {

        It 'Should carry a sub-hour frequency flexibly (PT45M, no rounding warning)' {
            $yaml = @'
id: 81fb771a-c57e-41b8-9905-63dbf267c13f
name: Flexible Fast Rule
description: desc
severity: Medium
queryFrequency: PT45M
queryPeriod: PT45M
triggerOperator: gt
triggerThreshold: 0
tactics:
  - Execution
query: SigninLogs | take 1
kind: Scheduled
'@
            $tempYaml = Join-Path TestDrive: 'flex-45m.yaml'
            Set-Content -Path $tempYaml -Value $yaml

            $warnings = @()
            $result = ConvertTo-XDRCustomDetection -Format XDRConverter -InputFile $tempYaml -Force -WarningVariable warnings 3>$null
            $parsed = $result | ConvertFrom-Yaml
            $parsed.frequency | Should -Be 'PT45M'
            $warnings | Where-Object { $_ -match 'rounded' } | Should -BeNullOrEmpty
        }

        It 'Should carry a 6h frequency flexibly (PT6H, not rounded to 3H/12H)' {
            $yaml = @'
id: 81fb771a-c57e-41b8-9905-63dbf267c13f
name: Flexible 6H Rule
description: desc
severity: Medium
queryFrequency: 6h
queryPeriod: 6h
triggerOperator: gt
triggerThreshold: 0
tactics:
  - Execution
query: SigninLogs | take 1
kind: Scheduled
'@
            $tempYaml = Join-Path TestDrive: 'flex-6h.yaml'
            Set-Content -Path $tempYaml -Value $yaml

            $result = ConvertTo-XDRCustomDetection -Format XDRConverter -InputFile $tempYaml -Force 3>$null
            $parsed = $result | ConvertFrom-Yaml
            $parsed.frequency | Should -Be 'PT6H'
            # 6h > 1h so the 6h lookback (<= 48h) is carried unchanged.
            $parsed.lookbackPeriod | Should -Be 'PT6H'
        }

        It 'Should carry the source lookback within parity limits' {
            $yaml = @'
id: 81fb771a-c57e-41b8-9905-63dbf267c13f
name: Flexible Lookback Rule
description: desc
severity: Medium
queryFrequency: PT1H
queryPeriod: P5D
triggerOperator: gt
triggerThreshold: 0
tactics:
  - Execution
query: SigninLogs | take 1
kind: Scheduled
'@
            $tempYaml = Join-Path TestDrive: 'flex-look.yaml'
            Set-Content -Path $tempYaml -Value $yaml

            $result = ConvertTo-XDRCustomDetection -Format XDRConverter -InputFile $tempYaml -Force 3>$null
            $parsed = $result | ConvertFrom-Yaml
            # freq <= 1h → lookback limit is 14 days; 5 days is within limit.
            $parsed.lookbackPeriod | Should -Be 'P5D'
        }

        It 'Should clamp an over-limit lookback to 14d with a Constrained warning (freq <= 1h)' {
            $yaml = @'
id: 81fb771a-c57e-41b8-9905-63dbf267c13f
name: Over Lookback Rule
description: desc
severity: Medium
queryFrequency: PT1H
queryPeriod: P20D
triggerOperator: gt
triggerThreshold: 0
tactics:
  - Execution
query: SigninLogs | take 1
kind: Scheduled
'@
            $tempYaml = Join-Path TestDrive: 'flex-clamp.yaml'
            Set-Content -Path $tempYaml -Value $yaml

            $warnings = @()
            $result = ConvertTo-XDRCustomDetection -Format XDRConverter -InputFile $tempYaml -Force -WarningVariable warnings 3>$null
            $parsed = $result | ConvertFrom-Yaml
            $parsed.lookbackPeriod | Should -Be 'P14D'
            $warnings | Where-Object { $_ -match 'clamped' } | Should -Not -BeNullOrEmpty
        }

        It 'Should allow up to 14 days for an hourly-to-daily frequency (documented tier)' {
            $yaml = @'
id: 81fb771a-c57e-41b8-9905-63dbf267c13f
name: Over Lookback High Freq Rule
description: desc
severity: Medium
queryFrequency: PT3H
queryPeriod: P5D
triggerOperator: gt
triggerThreshold: 0
tactics:
  - Execution
query: SigninLogs | take 1
kind: Scheduled
'@
            $tempYaml = Join-Path TestDrive: 'flex-clamp48.yaml'
            Set-Content -Path $tempYaml -Value $yaml

            $warnings = @()
            $result = ConvertTo-XDRCustomDetection -Format XDRConverter -InputFile $tempYaml -Force -WarningVariable warnings 3>$null
            $parsed = $result | ConvertFrom-Yaml
            # Documented ladder: a frequency of 1 hour up to (not including) 1 day may look
            # back up to 14 days. P5D is well inside that, so it is carried, not clamped.
            $parsed.lookbackPeriod | Should -Be 'P5D'
            $warnings | Where-Object { $_ -match 'clamped' } | Should -BeNullOrEmpty
        }
    }

    # -------------------------------------------------------------------------
    Context 'Stage 2 — Constrained lookback (DefenderOnly / Mixed)' {

        It 'Should drop a custom lookback and set the default for a DefenderOnly rule' {
            $yaml = @'
id: 81fb771a-c57e-41b8-9905-63dbf267c13f
name: Defender Lookback Rule
description: desc
severity: Medium
queryFrequency: PT3H
queryPeriod: P5D
triggerOperator: gt
triggerThreshold: 0
tactics:
  - Execution
query: DeviceProcessEvents | take 1
kind: Scheduled
'@
            $tempYaml = Join-Path TestDrive: 'def-look.yaml'
            Set-Content -Path $tempYaml -Value $yaml

            $warnings = @()
            $result = ConvertTo-XDRCustomDetection -Format XDRConverter -InputFile $tempYaml -Force -WarningVariable warnings 3>$null
            $parsed = $result | ConvertFrom-Yaml
            $parsed.frequency | Should -Be '3H'
            # Defender-tier data applies a FIXED lookback of 12 hours to a 3H frequency
            # (product documentation), and the source asked for P5D, so the detection will
            # evaluate a shorter window than the Sentinel rule did.
            $parsed.lookbackPeriod | Should -Be 'PT12H'
            $warnings | Where-Object { $_ -match 'FIXED|shorter window' } |
                Should -Not -BeNullOrEmpty
        }

        It 'Should treat a Mixed rule like Defender (rounded freq + default lookback)' {
            $yaml = @'
id: 81fb771a-c57e-41b8-9905-63dbf267c13f
name: Mixed Lookback Rule
description: desc
severity: Medium
queryFrequency: 6h
queryPeriod: P5D
triggerOperator: gt
triggerThreshold: 0
tactics:
  - LateralMovement
query: SecurityEvent | join kind=inner DeviceInfo on DeviceName
kind: Scheduled
'@
            $tempYaml = Join-Path TestDrive: 'mixed-look.yaml'
            Set-Content -Path $tempYaml -Value $yaml

            $warnings = @()
            $result = ConvertTo-XDRCustomDetection -Format XDRConverter -InputFile $tempYaml -Force -WarningVariable warnings 3>$null
            $parsed = $result | ConvertFrom-Yaml
            # 6h rounds to the 3H bucket, whose fixed Defender lookback is 12 hours.
            $parsed.frequency | Should -Be '3H'
            $parsed.lookbackPeriod | Should -Be 'PT12H'
            $warnings | Where-Object { $_ -match 'rounded' } | Should -Not -BeNullOrEmpty
        }
    }

    # -------------------------------------------------------------------------
    Context 'Stage 2 — Constrained path is data-driven (FrequencyLookbackRules.psd1)' {

        BeforeAll {
            # Load the data file the converter reads, so the assertions are tied to the
            # psd1 (the single source of truth) rather than to literals duplicated here.
            $src = Split-Path -Path $PSScriptRoot -Parent | Join-Path -ChildPath 'src'
            $script:FlRules = Import-PowerShellDataFile `
                -Path (Join-Path $src 'Data' | Join-Path -ChildPath 'FrequencyLookbackRules.psd1')
        }

        It 'Should drive the emitted lookbackPeriod from FixedLookbackPerFrequency for the chosen bucket' {
            # A DefenderOnly rule at PT3H is constrained to the 3H bucket; its lookback
            # must equal whatever FixedLookbackPerFrequency['3H'] says in the data file.
            $yaml = @'
id: 81fb771a-c57e-41b8-9905-63dbf267c13f
name: Data Driven Lookback Rule
description: desc
severity: Medium
queryFrequency: PT3H
queryPeriod: P5D
triggerOperator: gt
triggerThreshold: 0
tactics:
  - Execution
query: DeviceProcessEvents | take 1
kind: Scheduled
'@
            $tempYaml = Join-Path TestDrive: 'data-driven-look.yaml'
            Set-Content -Path $tempYaml -Value $yaml

            $result = ConvertTo-XDRCustomDetection -Format XDRConverter -InputFile $tempYaml -Force 3>$null
            $parsed = $result | ConvertFrom-Yaml

            $parsed.frequency | Should -Be '3H'
            $expectedLookback = $script:FlRules.FixedLookbackPerFrequency['3H']
            $expectedLookback | Should -Not -BeNullOrEmpty
            $parsed.lookbackPeriod | Should -Be $expectedLookback
        }

        It 'Should round to the shortest data-defined bucket for a tiny frequency' {
            # The fallback / smallest bucket is the smallest non-zero key in the data file.
            $shortest = @($script:FlRules.FixedLookbackPerFrequency.Keys |
                Where-Object { $_ -ne '0' } |
                Sort-Object { [double]($_ -replace '[Hh]','') })[0]

            $yaml = @'
id: 81fb771a-c57e-41b8-9905-63dbf267c13f
name: Tiny Freq Rule
description: desc
severity: Medium
queryFrequency: PT10M
triggerOperator: gt
triggerThreshold: 0
tactics:
  - Execution
query: DeviceProcessEvents | take 1
kind: Scheduled
'@
            $tempYaml = Join-Path TestDrive: 'tiny-freq.yaml'
            Set-Content -Path $tempYaml -Value $yaml

            $result = ConvertTo-XDRCustomDetection -Format XDRConverter -InputFile $tempYaml -Force 3>$null
            $parsed = $result | ConvertFrom-Yaml
            $parsed.frequency | Should -Be $shortest
        }
    }

    # -------------------------------------------------------------------------
    Context 'Stage 2 — Zero / invalid scheduled frequency fallback (not NRT)' {

        It 'Should NOT coerce a zero scheduled frequency to NRT (constrained path)' {
            # PT0S on a scheduled DefenderOnly rule must fall back to the shortest
            # supported frequency, NOT become continuous '0'.
            $yaml = @'
id: 81fb771a-c57e-41b8-9905-63dbf267c13f
name: Zero Freq Defender Rule
description: desc
severity: Medium
queryFrequency: PT0S
triggerOperator: gt
triggerThreshold: 0
tactics:
  - Execution
query: DeviceProcessEvents | take 1
kind: Scheduled
'@
            $tempYaml = Join-Path TestDrive: 'zero-freq-def.yaml'
            Set-Content -Path $tempYaml -Value $yaml

            $warnings = @()
            $result = ConvertTo-XDRCustomDetection -Format XDRConverter -InputFile $tempYaml -Force -WarningVariable warnings 3>$null
            $parsed = $result | ConvertFrom-Yaml
            $parsed.frequency | Should -Be '1H'
            $parsed.frequency | Should -Not -Be '0'
            $warnings | Where-Object { $_ -match 'zero/non-positive' } | Should -Not -BeNullOrEmpty
        }

        It 'Should NOT coerce a zero scheduled frequency to NRT (flexible path)' {
            # PT0S on a scheduled SentinelOnly rule must also fall back, not become '0'.
            $yaml = @'
id: 81fb771a-c57e-41b8-9905-63dbf267c13f
name: Zero Freq Sentinel Rule
description: desc
severity: Medium
queryFrequency: PT0S
triggerOperator: gt
triggerThreshold: 0
tactics:
  - Execution
query: SigninLogs | take 1
kind: Scheduled
'@
            $tempYaml = Join-Path TestDrive: 'zero-freq-sentinel.yaml'
            Set-Content -Path $tempYaml -Value $yaml

            $warnings = @()
            $result = ConvertTo-XDRCustomDetection -Format XDRConverter -InputFile $tempYaml -Force -WarningVariable warnings 3>$null
            $parsed = $result | ConvertFrom-Yaml
            $parsed.frequency | Should -Not -Be '0'
            $warnings | Where-Object { $_ -match 'zero/non-positive' } | Should -Not -BeNullOrEmpty
        }

        It 'Should still emit 0 for a genuine NRT rule' {
            # Guardrail: the zero-frequency fallback must NOT affect kind=NRT rules.
            $tempYaml = Join-Path TestDrive: 'nrt-still-zero.yaml'
            Set-Content -Path $tempYaml -Value $script:NrtYaml

            $result = ConvertTo-XDRCustomDetection -Format XDRConverter -InputFile $tempYaml -Force 3>$null
            $parsed = $result | ConvertFrom-Yaml
            $parsed.frequency | Should -Be '0'
        }
    }

    # -------------------------------------------------------------------------
    Context 'Mapping gaps — NRT kind (Stage 3 decisioning)' {

        It 'Should map an NRT-compatible rule to frequency 0' {
            # $script:NrtYaml uses 'SecurityEvent | take 5' — single table, no
            # join/union/externaldata, no comments => genuinely NRT-compatible.
            $tempYaml = Join-Path TestDrive: 'nrt.yaml'
            Set-Content -Path $tempYaml -Value $script:NrtYaml

            $warnings = @()
            $result = ConvertTo-XDRCustomDetection -Format XDRConverter -InputFile $tempYaml -Force -WarningVariable warnings 3>$null
            $parsed = $result | ConvertFrom-Yaml
            $parsed.frequency | Should -Be '0'
            # NRT has no scheduled lookback window.
            $parsed.lookbackPeriod | Should -Be '0'
            # Stage 3: a confirming continuous diagnostic should fire (Info, not a downgrade).
            $warnings | Where-Object { $_ -match 'compatible with Defender XDR Continuous' } |
                Should -Not -BeNullOrEmpty
            $warnings | Where-Object { $_ -match 'DOWNGRADED' } | Should -BeNullOrEmpty
        }

        It 'Should map an NRT rule with a // URL string to frequency 0 (no false comment downgrade)' {
            $yaml = @'
id: 81fb771a-c57e-41b8-9905-63dbf267c13f
name: NRT URL Rule
description: NRT single table with a URL string containing slashes.
severity: High
tactics:
  - CommandAndControl
query: DeviceNetworkEvents | where RemoteUrl == "http://evil.com/x"
kind: NRT
'@
            $tempYaml = Join-Path TestDrive: 'nrt-url.yaml'
            Set-Content -Path $tempYaml -Value $yaml

            $warnings = @()
            $result = ConvertTo-XDRCustomDetection -Format XDRConverter -InputFile $tempYaml -Force -WarningVariable warnings 3>$null
            $parsed = $result | ConvertFrom-Yaml
            $parsed.frequency | Should -Be '0'
            $warnings | Where-Object { $_ -match 'DOWNGRADED' } | Should -BeNullOrEmpty
        }

        It 'Should map an NRT rule with has "join" in a string to frequency 0 (no false join downgrade)' {
            $yaml = @'
id: 81fb771a-c57e-41b8-9905-63dbf267c13f
name: NRT Has-Join Rule
description: NRT single table with the word join inside a string literal.
severity: High
tactics:
  - Execution
query: DeviceProcessEvents | where ProcessCommandLine has "join"
kind: NRT
'@
            $tempYaml = Join-Path TestDrive: 'nrt-hasjoin.yaml'
            Set-Content -Path $tempYaml -Value $yaml

            $warnings = @()
            $result = ConvertTo-XDRCustomDetection -Format XDRConverter -InputFile $tempYaml -Force -WarningVariable warnings 3>$null
            $parsed = $result | ConvertFrom-Yaml
            $parsed.frequency | Should -Be '0'
            $warnings | Where-Object { $_ -match 'DOWNGRADED' } | Should -BeNullOrEmpty
        }

        It 'Should DOWNGRADE an NRT rule whose query uses join to the shortest scheduled frequency' {
            $yaml = @'
id: 81fb771a-c57e-41b8-9905-63dbf267c13f
name: NRT Join Rule
description: NRT with a join.
severity: High
tactics:
  - Execution
query: SecurityEvent | join kind=inner DeviceInfo on DeviceName
kind: NRT
'@
            $tempYaml = Join-Path TestDrive: 'nrt-join.yaml'
            Set-Content -Path $tempYaml -Value $yaml

            $warnings = @()
            $result = ConvertTo-XDRCustomDetection -Format XDRConverter -InputFile $tempYaml -Force -WarningVariable warnings 3>$null
            $parsed = $result | ConvertFrom-Yaml
            # Must NOT be continuous; falls back to shortest scheduled bucket (1H).
            $parsed.frequency | Should -Not -Be '0'
            $parsed.frequency | Should -Be '1H'
            # An hourly Defender-tier detection evaluates a fixed four-hour window.
            $parsed.lookbackPeriod | Should -Be 'PT4H'
            # Diagnostic must explain the downgrade and name the violating operator.
            $warnings | Where-Object { $_ -match 'DOWNGRADED from continuous' } |
                Should -Not -BeNullOrEmpty
            $warnings | Where-Object { $_ -match 'join' } | Should -Not -BeNullOrEmpty
        }

        It 'Should DOWNGRADE an NRT rule whose query uses externaldata' {
            $yaml = @'
id: 81fb771a-c57e-41b8-9905-63dbf267c13f
name: NRT Externaldata Rule
description: NRT with externaldata.
severity: High
tactics:
  - Execution
query: |
  let watchlist = externaldata(ip:string)["https://example.com/list.csv"];
  SecurityEvent | where SourceIP in (watchlist)
kind: NRT
'@
            $tempYaml = Join-Path TestDrive: 'nrt-extdata.yaml'
            Set-Content -Path $tempYaml -Value $yaml

            $warnings = @()
            $result = ConvertTo-XDRCustomDetection -Format XDRConverter -InputFile $tempYaml -Force -WarningVariable warnings 3>$null
            $parsed = $result | ConvertFrom-Yaml
            $parsed.frequency | Should -Not -Be '0'
            $parsed.frequency | Should -Be '1H'
            $warnings | Where-Object { $_ -match 'DOWNGRADED from continuous' } |
                Should -Not -BeNullOrEmpty
            $warnings | Where-Object { $_ -match 'externaldata' } | Should -Not -BeNullOrEmpty
        }

        It 'Should NOT run the NRT validator on a SCHEDULED rule with a join (unaffected)' {
            # A scheduled rule with a join must go through the Stage 2 scheduled path
            # (Mixed -> constrained rounding), NOT the NRT downgrade path.
            $yaml = @'
id: 81fb771a-c57e-41b8-9905-63dbf267c13f
name: Scheduled Join Rule
description: Scheduled with a join.
severity: Medium
queryFrequency: PT3H
queryPeriod: PT3H
triggerOperator: gt
triggerThreshold: 0
tactics:
  - LateralMovement
query: SecurityEvent | join kind=inner DeviceInfo on DeviceName
kind: Scheduled
'@
            $tempYaml = Join-Path TestDrive: 'sched-join.yaml'
            Set-Content -Path $tempYaml -Value $yaml

            $warnings = @()
            $result = ConvertTo-XDRCustomDetection -Format XDRConverter -InputFile $tempYaml -Force -WarningVariable warnings 3>$null
            $parsed = $result | ConvertFrom-Yaml
            # Stage 2 constrained path: rounded enum frequency, not continuous, not downgraded-by-NRT.
            $parsed.frequency | Should -Be '3H'
            $warnings | Where-Object { $_ -match 'DOWNGRADED from continuous' } | Should -BeNullOrEmpty
            $warnings | Where-Object { $_ -match 'Continuous \(NRT\)' } | Should -BeNullOrEmpty
        }
    }

    # -------------------------------------------------------------------------
    Context 'Stage 3 — Test-NrtQueryCompatibility unit' {

        BeforeAll {
            # Dot-source the private functions directly for unit testing.
            $src = Split-Path -Path $PSScriptRoot -Parent | Join-Path -ChildPath 'src'
            . (Join-Path $src 'Private' | Join-Path -ChildPath 'Remove-KqlStringLiteral.ps1')
            . (Join-Path $src 'Private' | Join-Path -ChildPath 'Get-QueryTableClassification.ps1')
            . (Join-Path $src 'Private' | Join-Path -ChildPath 'Test-NrtQueryCompatibility.ps1')
        }

        It 'Should report a simple single-table query as compatible' {
            $r = Test-NrtQueryCompatibility -Query 'DeviceProcessEvents | where FileName == "x" | summarize count() by DeviceId'
            $r.IsCompatible | Should -BeTrue
            $r.Violations | Should -BeNullOrEmpty
        }

        It 'Should flag a join query as incompatible with join in Violations' {
            $r = Test-NrtQueryCompatibility -Query 'SecurityEvent | join kind=inner DeviceInfo on DeviceName'
            $r.IsCompatible | Should -BeFalse
            $r.Violations | Should -Contain 'join'
        }

        It 'Should flag an externaldata query as incompatible' {
            $r = Test-NrtQueryCompatibility -Query 'externaldata(x:string)["https://example.com/a.csv"]'
            $r.IsCompatible | Should -BeFalse
            $r.Violations | Should -Contain 'externaldata'
        }

        It 'Should flag a union query as incompatible' {
            $r = Test-NrtQueryCompatibility -Query 'union DeviceProcessEvents, DeviceNetworkEvents | take 5'
            $r.IsCompatible | Should -BeFalse
            $r.Violations | Should -Contain 'union'
        }

        It 'Should flag a multi-table query (single-table rule)' {
            $r = Test-NrtQueryCompatibility -Query 'SecurityEvent | join DeviceInfo on DeviceName'
            $r.IsCompatible | Should -BeFalse
            ($r.Violations -join ' ') | Should -Match 'multiple tables'
        }

        It 'Should flag a query containing comments' {
            $r = Test-NrtQueryCompatibility -Query "SecurityEvent // pick logons`n| take 5"
            $r.IsCompatible | Should -BeFalse
            $r.Violations | Should -Contain 'comments'
        }

        It 'Should NOT flag // inside a URL string literal as a comment' {
            $r = Test-NrtQueryCompatibility -Query 'DeviceNetworkEvents | where RemoteUrl == "http://evil.com/x"'
            $r.Violations | Should -Not -Contain 'comments'
            $r.IsCompatible | Should -BeTrue
        }

        It 'Should NOT flag an operator keyword inside a string literal (has "join")' {
            $r = Test-NrtQueryCompatibility -Query 'DeviceProcessEvents | where ProcessCommandLine has "join"'
            $r.Violations | Should -Not -Contain 'join'
            $r.IsCompatible | Should -BeTrue
        }

        It 'Should STILL flag a genuine // comment line outside any string' {
            $r = Test-NrtQueryCompatibility -Query "DeviceProcessEvents | where RemoteUrl == `"http://x`" // note`n| take 5"
            $r.IsCompatible | Should -BeFalse
            $r.Violations | Should -Contain 'comments'
        }

        It 'Should STILL flag a genuine | join operator even when a string contains //' {
            $r = Test-NrtQueryCompatibility -Query 'DeviceProcessEvents | where RemoteUrl == "http://x" | join SecurityEvent on DeviceName'
            $r.IsCompatible | Should -BeFalse
            $r.Violations | Should -Contain 'join'
        }
    }

    # -------------------------------------------------------------------------
    Context 'Mapping gaps — multiple tactics' {

        It 'Should emit a warning when multiple tactics are present' {
            $tempYaml = Join-Path TestDrive: 'multi.yaml'
            Set-Content -Path $tempYaml -Value $script:MultiTacticYaml

            $warnings = @()
            ConvertTo-XDRCustomDetection -Format XDRConverter -InputFile $tempYaml -Force `
                -WarningVariable warnings -WarningAction SilentlyContinue | Out-Null
            $warnings | Where-Object { $_ -match 'tactics' } |
                Should -Not -BeNullOrEmpty
        }

        It 'Should use the first tactic as alertCategory when -Force is set' {
            $tempYaml = Join-Path TestDrive: 'multi-force.yaml'
            Set-Content -Path $tempYaml -Value $script:MultiTacticYaml

            $result = ConvertTo-XDRCustomDetection -Format XDRConverter -InputFile $tempYaml -Force 3>$null
            $parsed = $result | ConvertFrom-Yaml
            $parsed.alertCategory | Should -Be 'InitialAccess'
        }

        It 'Should use -AlertCategory override instead of first tactic' {
            $tempYaml = Join-Path TestDrive: 'multi-override.yaml'
            Set-Content -Path $tempYaml -Value $script:MultiTacticYaml

            $result = ConvertTo-XDRCustomDetection -Format XDRConverter -InputFile $tempYaml -AlertCategory DefenseEvasion -Force 3>$null
            $parsed = $result | ConvertFrom-Yaml
            $parsed.alertCategory | Should -Be 'DefenseEvasion'
        }
    }

    # -------------------------------------------------------------------------
    Context 'Stage 4 — MITRE tactics drop accounting' {

        It 'Should record the chosen tactic, the dropped list, and an N-of-M count' {
            # MultiTacticYaml: [InitialAccess, Persistence, DefenseEvasion].
            # Chosen = InitialAccess (first mappable); dropped = the other 2.
            $tempYaml = Join-Path TestDrive: 'mitre-drop.yaml'
            Set-Content -Path $tempYaml -Value $script:MultiTacticYaml

            $warnings = @()
            $result = ConvertTo-XDRCustomDetection -Format XDRConverter -InputFile $tempYaml -Force `
                -WarningVariable warnings -WarningAction SilentlyContinue
            $parsed = $result | ConvertFrom-Yaml
            $parsed.alertCategory | Should -Be 'InitialAccess'

            $dropWarn = $warnings | Where-Object { $_ -match '2 of 3 tactic' }
            $dropWarn | Should -Not -BeNullOrEmpty
            # Names the chosen tactic and the explicit dropped list.
            ($dropWarn -join ' ') | Should -Match "Kept 'InitialAccess'"
            ($dropWarn -join ' ') | Should -Match 'Persistence'
            ($dropWarn -join ' ') | Should -Match 'DefenseEvasion'
        }

        It 'Should reference the (Planned) capability State of multiple tactics (matrix-gated)' {
            $tempYaml = Join-Path TestDrive: 'mitre-state.yaml'
            Set-Content -Path $tempYaml -Value $script:MultiTacticYaml

            $warnings = @()
            ConvertTo-XDRCustomDetection -Format XDRConverter -InputFile $tempYaml -Force `
                -WarningVariable warnings -WarningAction SilentlyContinue | Out-Null
            # The diagnostic surfaces the State read from CustomDetectionCapabilities.psd1.
            $warnings | Where-Object { $_ -match "Link multiple MITRE tactics' is Planned" } |
                Should -Not -BeNullOrEmpty
        }

        It 'Should NOT emit a drop diagnostic for a single-tactic rule' {
            # BasicYaml has a single tactic (InitialAccess).
            $tempYaml = Join-Path TestDrive: 'mitre-single.yaml'
            Set-Content -Path $tempYaml -Value $script:BasicYaml

            $warnings = @()
            ConvertTo-XDRCustomDetection -Format XDRConverter -InputFile $tempYaml -Force `
                -WarningVariable warnings -WarningAction SilentlyContinue | Out-Null
            $warnings | Where-Object { $_ -match 'tactic\(s\) were NOT migrated' } |
                Should -BeNullOrEmpty
        }

        It 'Should still map Sentinel-only and unknown tactics' {
            $yaml = @'
id: 81fb771a-c57e-41b8-9905-63dbf267c13f
name: Odd Tactics Rule
description: desc
severity: Medium
queryFrequency: PT1H
triggerOperator: gt
triggerThreshold: 0
tactics:
  - Reconnaissance
  - BogusTactic
query: SecurityEvent | take 1
kind: Scheduled
'@
            $tempYaml = Join-Path TestDrive: 'mitre-odd.yaml'
            Set-Content -Path $tempYaml -Value $yaml

            $warnings = @()
            $result = ConvertTo-XDRCustomDetection -Format XDRConverter -InputFile $tempYaml -Force `
                -WarningVariable warnings -WarningAction SilentlyContinue
            $parsed = $result | ConvertFrom-Yaml
            # Reconnaissance is a Sentinel-only tactic → SuspiciousActivity.
            $parsed.alertCategory | Should -Be 'SuspiciousActivity'
            $warnings | Where-Object { $_ -match 'Reconnaissance' -and $_ -match 'SuspiciousActivity' } |
                Should -Not -BeNullOrEmpty
            $warnings | Where-Object { $_ -match 'Unknown tactic' -and $_ -match 'BogusTactic' } |
                Should -Not -BeNullOrEmpty
        }
    }

    # -------------------------------------------------------------------------
    Context 'Stage 4 — MITRE techniques & subtechniques' {

        It 'Should drop invalid technique IDs (named + counted) and keep valid ones' {
            $yaml = @'
id: 81fb771a-c57e-41b8-9905-63dbf267c13f
name: Tech Mix Rule
description: desc
severity: Medium
queryFrequency: PT1H
triggerOperator: gt
triggerThreshold: 0
tactics:
  - Execution
relevantTechniques:
  - T1059
  - T1059.001
  - T9999999
  - garbage
query: SecurityEvent | take 1
kind: Scheduled
'@
            $tempYaml = Join-Path TestDrive: 'tech-mix.yaml'
            Set-Content -Path $tempYaml -Value $yaml

            $warnings = @()
            $result = ConvertTo-XDRCustomDetection -Format XDRConverter -InputFile $tempYaml -Force `
                -WarningVariable warnings -WarningAction SilentlyContinue
            $parsed = $result | ConvertFrom-Yaml

            # Valid parent + subtechnique carried; invalid excluded.
            $parsed.mitreTechniques | Should -Contain 'T1059'
            $parsed.mitreTechniques | Should -Contain 'T1059.001'
            $parsed.mitreTechniques | Should -Not -Contain 'T9999999'
            $parsed.mitreTechniques | Should -Not -Contain 'garbage'

            # Invalid drop diagnostic names + counts the bad IDs.
            $dropWarn = $warnings | Where-Object { $_ -match 'not.*valid ATT&CK' }
            $dropWarn | Should -Not -BeNullOrEmpty
            ($dropWarn -join ' ') | Should -Match '2 MITRE technique'
            ($dropWarn -join ' ') | Should -Match 'T9999999'
        }

        It 'Should separate + count subtechniques and emit the Planned RequiresReview diagnostic' {
            $yaml = @'
id: 81fb771a-c57e-41b8-9905-63dbf267c13f
name: Subtech Rule
description: desc
severity: Medium
queryFrequency: PT1H
triggerOperator: gt
triggerThreshold: 0
tactics:
  - Execution
relevantTechniques:
  - T1078
  - T1078.004
  - T1110.001
query: SecurityEvent | take 1
kind: Scheduled
'@
            $tempYaml = Join-Path TestDrive: 'subtech.yaml'
            Set-Content -Path $tempYaml -Value $yaml

            $warnings = @()
            ConvertTo-XDRCustomDetection -Format XDRConverter -InputFile $tempYaml -Force `
                -WarningVariable warnings -WarningAction SilentlyContinue | Out-Null

            $review = $warnings | Where-Object { $_ -match 'full MITRE technique/subtechnique support' }
            $review | Should -Not -BeNullOrEmpty
            # Planned state is surfaced, and subtechniques are counted (2 of them).
            ($review -join ' ') | Should -Match 'is Planned'
            ($review -join ' ') | Should -Match '2 is/are subtechniques'
        }

        It 'Should deduplicate techniques, preserving order' {
            $yaml = @'
id: 81fb771a-c57e-41b8-9905-63dbf267c13f
name: Dup Tech Rule
description: desc
severity: Medium
queryFrequency: PT1H
triggerOperator: gt
triggerThreshold: 0
tactics:
  - Execution
relevantTechniques:
  - T1059
  - T1059
  - T1078
query: SecurityEvent | take 1
kind: Scheduled
'@
            $tempYaml = Join-Path TestDrive: 'dup-tech.yaml'
            Set-Content -Path $tempYaml -Value $yaml

            $result = ConvertTo-XDRCustomDetection -Format XDRConverter -InputFile $tempYaml -Force 3>$null
            $parsed = $result | ConvertFrom-Yaml
            @($parsed.mitreTechniques) | Should -HaveCount 2
            $parsed.mitreTechniques[0] | Should -Be 'T1059'
            $parsed.mitreTechniques[1] | Should -Be 'T1078'
        }

        It 'Should emit the ATT&CK-page reflection diagnostic (Planned) when MITRE metadata is present' {
            $tempYaml = Join-Path TestDrive: 'attack-page.yaml'
            Set-Content -Path $tempYaml -Value $script:BasicYaml

            $warnings = @()
            ConvertTo-XDRCustomDetection -Format XDRConverter -InputFile $tempYaml -Force `
                -WarningVariable warnings -WarningAction SilentlyContinue | Out-Null
            $warnings | Where-Object { $_ -match 'MITRE ATT&CK coverage page' } |
                Should -Not -BeNullOrEmpty
        }
    }

    # -------------------------------------------------------------------------
    Context 'Mapping gaps — unsupported entity types' {

        It 'Should skip AzureResource entity with a warning' {
            $tempYaml = Join-Path TestDrive: 'entity-unsupported.yaml'
            Set-Content -Path $tempYaml -Value $script:UnsupportedEntityYaml

            $warnings = @()
            $result = ConvertTo-XDRCustomDetection -Format XDRConverter -InputFile $tempYaml -Force -WarningVariable warnings 3>$null
            $parsed = $result | ConvertFrom-Yaml
            $parsed.impactedEntities | Where-Object { $_.entityType -eq 'AzureResource' } |
                Should -BeNullOrEmpty
            $warnings | Where-Object { $_ -match 'AzureResource' } | Should -Not -BeNullOrEmpty
        }

        It 'Should still map supported entities alongside unsupported ones' {
            $tempYaml = Join-Path TestDrive: 'entity-mixed.yaml'
            Set-Content -Path $tempYaml -Value $script:UnsupportedEntityYaml

            $result = ConvertTo-XDRCustomDetection -Format XDRConverter -InputFile $tempYaml -Force 3>$null
            $parsed = $result | ConvertFrom-Yaml
            $ipEntity = $parsed.impactedEntities | Where-Object { $_.entityType -eq 'IP' }
            $ipEntity | Should -Not -BeNullOrEmpty
            $ipEntity.entityIdentifier | Should -Be 'ClientIP'
        }
    }

    # -------------------------------------------------------------------------
    Context 'Mapping gaps — trigger threshold warning' {

        It 'Should warn when triggerThreshold is greater than 0' {
            $yaml = @'
id: 81fb771a-c57e-41b8-9905-63dbf267c13f
name: Threshold Rule
description: desc
severity: Medium
queryFrequency: 1h
triggerOperator: gt
triggerThreshold: 5
tactics:
  - Discovery
query: SecurityEvent | summarize count() by Computer | where count_ > 5
kind: Scheduled
'@
            $tempYaml = Join-Path TestDrive: 'threshold.yaml'
            Set-Content -Path $tempYaml -Value $yaml

            $warnings = @()
            ConvertTo-XDRCustomDetection -Format XDRConverter -InputFile $tempYaml -Force `
                -WarningVariable warnings -WarningAction SilentlyContinue | Out-Null
            $warnings | Where-Object { $_ -match 'trigger' } | Should -Not -BeNullOrEmpty
        }
    }

    # -------------------------------------------------------------------------
    Context 'Stage 1 — KQL table classification diagnostic' {

        # Replaces the former universal "may reference Sentinel-specific tables"
        # warning with a precise, classification-driven diagnostic. The Unified SOC
        # guidance is preserved for Sentinel-tier and Mixed queries.

        It 'Should emit a Sentinel-tier classification warning for a SigninLogs query' {
            # BasicYaml queries SigninLogs (a Sentinel-tier table) → SentinelOnly.
            $tempYaml = Join-Path TestDrive: 'kql-sentinel.yaml'
            Set-Content -Path $tempYaml -Value $script:BasicYaml

            $warnings = @()
            ConvertTo-XDRCustomDetection -Format XDRConverter -InputFile $tempYaml -Force -WarningVariable warnings 3>$null | Out-Null
            $warnings | Where-Object { $_ -match 'only Sentinel-tier tables' } |
                Should -Not -BeNullOrEmpty
            # Unified SOC guidance must still be present.
            $warnings | Where-Object { $_ -match 'Unified SOC' } |
                Should -Not -BeNullOrEmpty
        }

        It 'Should emit a Defender-data info diagnostic (no Sentinel-tier warning) for a Defender-only query' {
            $yaml = @'
id: 81fb771a-c57e-41b8-9905-63dbf267c13f
name: Defender Only Rule
description: desc
severity: Medium
queryFrequency: 1h
triggerOperator: gt
triggerThreshold: 0
tactics:
  - Execution
query: DeviceProcessEvents | where FileName == "powershell.exe"
kind: Scheduled
'@
            $tempYaml = Join-Path TestDrive: 'kql-defender.yaml'
            Set-Content -Path $tempYaml -Value $yaml

            $warnings = @()
            ConvertTo-XDRCustomDetection -Format XDRConverter -InputFile $tempYaml -Force -WarningVariable warnings 3>$null | Out-Null
            # No Sentinel-tier table warning should fire for a Defender-only query.
            $warnings | Where-Object { $_ -match 'Sentinel-tier tables' } |
                Should -BeNullOrEmpty
        }

        It 'Should emit a Mixed-classification warning naming both tiers for a join query' {
            $yaml = @'
id: 81fb771a-c57e-41b8-9905-63dbf267c13f
name: Mixed Rule
description: desc
severity: Medium
queryFrequency: 1h
triggerOperator: gt
triggerThreshold: 0
tactics:
  - LateralMovement
query: SecurityEvent | join kind=inner DeviceInfo on DeviceName
kind: Scheduled
'@
            $tempYaml = Join-Path TestDrive: 'kql-mixed.yaml'
            Set-Content -Path $tempYaml -Value $yaml

            $warnings = @()
            ConvertTo-XDRCustomDetection -Format XDRConverter -InputFile $tempYaml -Force -WarningVariable warnings 3>$null | Out-Null
            $warnings | Where-Object { $_ -match 'references both Defender XDR tables' } |
                Should -Not -BeNullOrEmpty
        }
    }

    # -------------------------------------------------------------------------
    Context 'Stage 1 — Get-QueryTableClassification unit' {

        BeforeAll {
            # Dot-source the private function directly for unit testing.
            $src = Split-Path -Path $PSScriptRoot -Parent | Join-Path -ChildPath 'src'
            . (Join-Path $src 'Private' | Join-Path -ChildPath 'Remove-KqlStringLiteral.ps1')
            . (Join-Path $src 'Private' | Join-Path -ChildPath 'Get-QueryTableClassification.ps1')
        }

        It 'Should classify a single Sentinel table as SentinelOnly' {
            $r = Get-QueryTableClassification -Query 'SecurityEvent | where EventID == 4625'
            $r.Classification | Should -Be 'SentinelOnly'
            $r.ReferencedTables | Should -Contain 'SecurityEvent'
            $r.SentinelTables | Should -Contain 'SecurityEvent'
            $r.DefenderTables | Should -BeNullOrEmpty
        }

        It 'Should classify a single Defender table as DefenderOnly' {
            $r = Get-QueryTableClassification -Query 'DeviceProcessEvents | take 10'
            $r.Classification | Should -Be 'DefenderOnly'
            $r.ReferencedTables | Should -Contain 'DeviceProcessEvents'
            $r.DefenderTables | Should -Contain 'DeviceProcessEvents'
            $r.SentinelTables | Should -BeNullOrEmpty
        }

        It 'Should classify a join of a Defender and a Sentinel table as Mixed' {
            $r = Get-QueryTableClassification -Query 'SigninLogs | join kind=inner IdentityInfo on AccountUpn'
            $r.Classification | Should -Be 'Mixed'
            $r.DefenderTables | Should -Contain 'IdentityInfo'
            $r.SentinelTables | Should -Contain 'SigninLogs'
        }

        It 'Should classify a union of Defender tables as DefenderOnly' {
            $r = Get-QueryTableClassification -Query 'union DeviceProcessEvents, DeviceNetworkEvents | take 5'
            $r.Classification | Should -Be 'DefenderOnly'
            $r.ReferencedTables | Should -Contain 'DeviceProcessEvents'
            $r.ReferencedTables | Should -Contain 'DeviceNetworkEvents'
        }

        It 'Should default an empty query to SentinelOnly with no tables' {
            $r = Get-QueryTableClassification -Query ''
            $r.Classification | Should -Be 'SentinelOnly'
            $r.ReferencedTables | Should -BeNullOrEmpty
        }

        It 'Should exclude let-bound names from referenced tables' {
            $q = "let suspicious = DeviceProcessEvents | where FileName == 'x';`nsuspicious | take 5"
            $r = Get-QueryTableClassification -Query $q
            $r.ReferencedTables | Should -Not -Contain 'suspicious'
            $r.ReferencedTables | Should -Contain 'DeviceProcessEvents'
            $r.Classification | Should -Be 'DefenderOnly'
        }
    }

    # -------------------------------------------------------------------------
    # Build-for-change invariant guard: diagnostics meant to map to a capability
    # matrix row MUST use a Feature/Capability pair that actually resolves in
    # CustomDetectionCapabilities.psd1. A previously-shipped bug used the
    # non-existent lookback Capability 'Support rule lookback on Sentinel data'
    # (the real row is Feature 'Rule lookback' / Capability 'Lookback support'),
    # which would silently fail any future matrix lookup. This guard converts
    # rules that exercise BOTH the constrained and flexible lookback paths plus
    # the frequency paths, then asserts every emitted 'Rule lookback' and
    # 'Rule frequency' diagnostic resolves to a real matrix row.
    Context 'Build-for-change — diagnostics map to capability matrix rows' {

        BeforeAll {
            # Load the matrix directly from the data file (single source of truth).
            $src = Split-Path -Path $PSScriptRoot -Parent | Join-Path -ChildPath 'src'
            $matrixPath = Join-Path $src 'Data' | Join-Path -ChildPath 'CustomDetectionCapabilities.psd1'
            $script:Matrix = Import-PowerShellDataFile -Path $matrixPath

            $script:MatrixHasRow = {
                param([string]$Feature, [string]$Capability)
                [bool]($script:Matrix.Capabilities | Where-Object {
                    $_.Feature -eq $Feature -and $_.Capability -eq $Capability
                })
            }

            # Helper: convert a Sentinel object and return the structured
            # diagnostics via the JSON report the public function writes.
            $script:GetDiagnostics = {
                param([object]$SentinelObject)
                $outFile = Join-Path ([System.IO.Path]::GetTempPath()) "stx-guard-$([guid]::NewGuid()).yaml"
                try {
                    $SentinelObject | ConvertTo-XDRCustomDetection -Format XDRConverter -OutputFile $outFile -Force -WriteReport 3>$null | Out-Null
                    $reportPath = ($outFile -replace '\.yaml$', '') + '.report.json'
                    @(Get-Content -Path $reportPath -Raw | ConvertFrom-Json)
                } finally {
                    foreach ($p in @($outFile, (($outFile -replace '\.yaml$', '') + '.report.json'), (($outFile -replace '\.yaml$', '') + '.report.md'))) {
                        if (Test-Path $p) { Remove-Item $p -Force -ErrorAction SilentlyContinue }
                    }
                }
            }

            # Constrained path: Defender XDR table + a source queryPeriod -> emits
            # the 'Rule lookback' constrained-drop diagnostic.
            $script:ConstrainedRule = @'
id: 81fb771a-c57e-41b8-9905-63dbf267c13f
name: Guard Constrained Rule
description: Defender-only rule with a custom lookback.
severity: Medium
queryFrequency: PT3H
queryPeriod: PT3H
triggerOperator: gt
triggerThreshold: 0
query: DeviceProcessEvents | take 10
kind: Scheduled
'@ | ConvertFrom-Yaml

            # Flexible path: Sentinel-tier table + an over-limit queryPeriod ->
            # emits 'Rule frequency' (mapped) + 'Rule lookback' (clamped) diagnostics.
            $script:FlexibleRule = @'
id: 81fb771a-c57e-41b8-9905-63dbf267c13f
name: Guard Flexible Rule
description: Sentinel-tier rule with an over-limit lookback.
severity: Medium
queryFrequency: PT6H
queryPeriod: P30D
triggerOperator: gt
triggerThreshold: 0
query: SigninLogs | where ResultType == "0"
kind: Scheduled
'@ | ConvertFrom-Yaml
        }

        It 'Emits at least one Rule lookback and one Rule frequency diagnostic across the paths' {
            $diags = @()
            $diags += & $script:GetDiagnostics $script:ConstrainedRule
            $diags += & $script:GetDiagnostics $script:FlexibleRule
            ($diags | Where-Object { $_.Feature -eq 'Rule lookback' }).Count | Should -BeGreaterThan 0
            ($diags | Where-Object { $_.Feature -eq 'Rule frequency' }).Count | Should -BeGreaterThan 0
        }

        It 'Every Rule lookback diagnostic uses a Feature/Capability pair that exists in the matrix' {
            $diags = @()
            $diags += & $script:GetDiagnostics $script:ConstrainedRule
            $diags += & $script:GetDiagnostics $script:FlexibleRule
            foreach ($d in ($diags | Where-Object { $_.Feature -eq 'Rule lookback' })) {
                (& $script:MatrixHasRow $d.Feature $d.Capability) |
                    Should -BeTrue -Because "lookback diagnostic Capability '$($d.Capability)' must be a real matrix row"
            }
        }

        It 'Every Rule frequency diagnostic uses a Feature/Capability pair that exists in the matrix' {
            $diags = @()
            $diags += & $script:GetDiagnostics $script:ConstrainedRule
            $diags += & $script:GetDiagnostics $script:FlexibleRule
            foreach ($d in ($diags | Where-Object { $_.Feature -eq 'Rule frequency' })) {
                (& $script:MatrixHasRow $d.Feature $d.Capability) |
                    Should -BeTrue -Because "frequency diagnostic Capability '$($d.Capability)' must be a real matrix row"
            }
        }

        It 'The corrected lookback row (Rule lookback / Lookback support) exists in the matrix' {
            (& $script:MatrixHasRow 'Rule lookback' 'Lookback support') | Should -BeTrue
        }

        It 'The previously-mismatched lookback Capability is NOT a matrix row (regression guard)' {
            (& $script:MatrixHasRow 'Rule lookback' 'Support rule lookback on Sentinel data') | Should -BeFalse
        }
    }

    # -------------------------------------------------------------------------
    Context 'Stage 5 — Remaining feature gaps (matrix-driven drop + diagnose)' {

        BeforeAll {
            $src = Split-Path -Path $PSScriptRoot -Parent | Join-Path -ChildPath 'src'
            $matrixPath = Join-Path $src 'Data' | Join-Path -ChildPath 'CustomDetectionCapabilities.psd1'
            $script:Matrix = Import-PowerShellDataFile -Path $matrixPath
            $script:MatrixHasRow = {
                param([string]$Feature, [string]$Capability)
                [bool]($script:Matrix.Capabilities | Where-Object {
                    $_.Feature -eq $Feature -and $_.Capability -eq $Capability
                })
            }

            # Collect structured diagnostics via the JSON report.
            $script:GetDiags = {
                param([object]$SentinelObject, [hashtable]$ExtraArgs = @{})
                $outFile = Join-Path ([System.IO.Path]::GetTempPath()) "stx-s5-$([guid]::NewGuid()).yaml"
                $reportPath = ($outFile -replace '\.yaml$', '') + '.report.json'
                try {
                    $SentinelObject | ConvertTo-XDRCustomDetection -Format XDRConverter -OutputFile $outFile -Force -WriteReport @ExtraArgs 3>$null | Out-Null
                    [PSCustomObject]@{
                        Diagnostics = @(Get-Content -Path $reportPath -Raw | ConvertFrom-Json)
                        Output      = (Get-Content -Path $outFile -Raw | ConvertFrom-Yaml)
                    }
                } finally {
                    foreach ($p in @($outFile, $reportPath, (($outFile -replace '\.yaml$', '') + '.report.md'))) {
                        if (Test-Path $p) { Remove-Item $p -Force -ErrorAction SilentlyContinue }
                    }
                }
            }
        }

        # ---- A. alertDetailsOverride (dynamic title/description) -------------
        It 'A: Should map a dynamic alert title/description format and diagnose Planned sub-properties' {
            $obj = [PSCustomObject]@{
                id    = '81fb771a-c57e-41b8-9905-63dbf267c13f'
                name  = 'Dynamic Override Rule'
                query = 'SecurityEvent | take 1'
                kind  = 'Scheduled'
                alertDetailsOverride = [PSCustomObject]@{
                    alertDisplayNameFormat   = 'Suspicious sign-in from {{IPAddress}}'
                    alertDescriptionFormat   = 'User {{Account}} signed in.'
                    alertSeverityColumnName  = 'SevColumn'
                    alertDynamicProperties   = @('p1')
                }
            }
            $r = & $script:GetDiags $obj

            # Dynamic title/description (Supported) mapped into output.
            $r.Output.alertTitle | Should -Be 'Suspicious sign-in from {{IPAddress}}'
            $r.Output.alertDescription | Should -Be 'User {{Account}} signed in.'

            # The dynamic-title MAP diagnostic carries the format string as SourceValue
            # (distinguishing it from the default "use rule name" diagnostic, which has
            # a $null SourceValue but the same Feature/Capability).
            $titleDiag = @($r.Diagnostics | Where-Object {
                $_.Capability -eq 'Define alert title and description dynamically - Integrate query results in runtime' -and
                $_.Action -eq 'Mapped' -and $_.SourceValue -eq 'Suspicious sign-in from {{IPAddress}}'
            })[0]
            $titleDiag | Should -Not -BeNullOrEmpty

            # Fix 2: exactly ONE alertTitle-related diagnostic fires (the dynamic
            # Mapped one). The default "using the rule name" diagnostic ($null
            # SourceValue, same Feature/Capability) must NOT fire.
            $defaultTitleDiag = @($r.Diagnostics | Where-Object {
                $_.Capability -eq 'Define alert title and description dynamically - Integrate query results in runtime' -and
                $_.Action -eq 'Mapped' -and $null -eq $_.SourceValue -and $_.Reason -match 'do not have a dedicated alert title'
            })
            $defaultTitleDiag | Should -BeNullOrEmpty -Because 'the default-title diagnostic is superseded by the dynamic-title one'

            # Planned "all properties dynamic" sub-props -> RequiresReview, NOT migrated.
            $allPropsDiag = $r.Diagnostics | Where-Object {
                $_.Capability -eq 'Define all alerts properties dynamically - Integrate query results in runtime'
            }
            $allPropsDiag | Should -Not -BeNullOrEmpty
            $allPropsDiag.Action | Should -Be 'RequiresReview'
            $allPropsDiag.Reason | Should -Match 'alertSeverityColumnName'
            # Matrix-gated: both rows are real.
            (& $script:MatrixHasRow $titleDiag.Feature $titleDiag.Capability) | Should -BeTrue
            (& $script:MatrixHasRow $allPropsDiag.Feature $allPropsDiag.Capability) | Should -BeTrue
        }

        It 'A: Should NOT overwrite an explicit -AlertTitle override with the dynamic title' {
            $obj = [PSCustomObject]@{
                id    = '81fb771a-c57e-41b8-9905-63dbf267c13f'
                name  = 'Dynamic Title Override'
                query = 'SecurityEvent | take 1'
                kind  = 'Scheduled'
                alertDetailsOverride = [PSCustomObject]@{ alertDisplayNameFormat = 'Dynamic {{X}}' }
            }
            $r = & $script:GetDiags $obj @{ AlertTitle = 'Explicit Title' }
            $r.Output.alertTitle | Should -Be 'Explicit Title'

            # Explicit -AlertTitle wins: neither the default-title nor a dynamic
            # Mapped title diagnostic should fire (a RequiresReview note is emitted
            # explaining the dynamic format was NOT applied, but no title was mapped).
            $titleMapped = @($r.Diagnostics | Where-Object {
                $_.Capability -eq 'Define alert title and description dynamically - Integrate query results in runtime' -and
                $_.Action -eq 'Mapped'
            })
            $titleMapped | Should -BeNullOrEmpty -Because 'explicit -AlertTitle suppresses both default and dynamic title diagnostics'
        }

        It 'A: Plain rule (no alertDetailsOverride) still fires the default-title diagnostic' {
            $obj = [PSCustomObject]@{
                id    = '81fb771a-c57e-41b8-9905-63dbf267c13f'
                name  = 'Plain Rule'
                query = 'SecurityEvent | take 1'
                kind  = 'Scheduled'
            }
            $r = & $script:GetDiags $obj
            $defaultTitleDiag = @($r.Diagnostics | Where-Object {
                $_.Capability -eq 'Define alert title and description dynamically - Integrate query results in runtime' -and
                $_.Action -eq 'Mapped' -and $null -eq $_.SourceValue -and $_.Reason -match 'do not have a dedicated alert title'
            })
            $defaultTitleDiag.Count | Should -Be 1
            $r.Output.alertTitle | Should -Be 'Plain Rule'
        }

        # ---- B. customDetails ----------------------------------------------
        It 'B: Should map customDetails into the output (Supported) and record a count' {
            $obj = [PSCustomObject]@{
                id    = '81fb771a-c57e-41b8-9905-63dbf267c13f'
                name  = 'Custom Details Rule'
                query = 'SecurityEvent | take 1'
                kind  = 'Scheduled'
                customDetails = [PSCustomObject]@{ SourceIp = 'ClientIP'; UserName = 'Account' }
            }
            $r = & $script:GetDiags $obj
            $r.Output.customDetails.SourceIp | Should -Be 'ClientIP'
            $r.Output.customDetails.UserName | Should -Be 'Account'

            $cdDiag = $r.Diagnostics | Where-Object { $_.Capability -eq 'Enrich alerts with custom details' }
            $cdDiag | Should -Not -BeNullOrEmpty
            $cdDiag.Action | Should -Be 'Mapped'
            $cdDiag.Reason | Should -Match '2 custom detail'
            (& $script:MatrixHasRow $cdDiag.Feature $cdDiag.Capability) | Should -BeTrue
        }

        # ---- C. eventGroupingSettings --------------------------------------
        It 'C: Should DROP eventGroupingSettings with an Unsupported Warning (NotSupported)' {
            $obj = [PSCustomObject]@{
                id    = '81fb771a-c57e-41b8-9905-63dbf267c13f'
                name  = 'Grouping Rule'
                query = 'SecurityEvent | take 1'
                kind  = 'Scheduled'
                eventGroupingSettings = [PSCustomObject]@{ aggregationKind = 'AlertPerResult' }
            }
            $r = & $script:GetDiags $obj
            $diag = $r.Diagnostics | Where-Object { $_.Capability -eq 'Choose between all events under one alert and one alert per event' }
            $diag | Should -Not -BeNullOrEmpty
            $diag.Action | Should -Be 'Unsupported'
            $diag.Severity | Should -Be 'Warning'
            $diag.Reason | Should -Match 'AlertPerResult'
            # Field is NOT in output.
            $r.Output.PSObject.Properties.Name | Should -Not -Contain 'eventGroupingSettings'
            (& $script:MatrixHasRow $diag.Feature $diag.Capability) | Should -BeTrue
        }

        # ---- D. incidentConfiguration --------------------------------------
        It 'D: Should DROP createIncident=false (alerts without incidents) with an Unsupported Warning' {
            $obj = [PSCustomObject]@{
                id    = '81fb771a-c57e-41b8-9905-63dbf267c13f'
                name  = 'No Incident Rule'
                query = 'SecurityEvent | take 1'
                kind  = 'Scheduled'
                incidentConfiguration = [PSCustomObject]@{
                    createIncident = $false
                    groupingConfiguration = [PSCustomObject]@{ enabled = $true }
                }
            }
            $r = & $script:GetDiags $obj
            $awDiag = $r.Diagnostics | Where-Object { $_.Capability -eq 'Create alerts without incidents' }
            $awDiag | Should -Not -BeNullOrEmpty
            $awDiag.Action | Should -Be 'Unsupported'

            $cgDiag = $r.Diagnostics | Where-Object { $_.Capability -eq 'Customize alert grouping logic' }
            $cgDiag | Should -Not -BeNullOrEmpty
            $cgDiag.Action | Should -Be 'Unsupported'
            (& $script:MatrixHasRow $awDiag.Feature $awDiag.Capability) | Should -BeTrue
            (& $script:MatrixHasRow $cgDiag.Feature $cgDiag.Capability) | Should -BeTrue
        }

        # ---- E. Alert suppression ------------------------------------------
        It 'E: Should DROP alert suppression naming the window (NotSupported)' {
            $obj = [PSCustomObject]@{
                id    = '81fb771a-c57e-41b8-9905-63dbf267c13f'
                name  = 'Suppression Rule'
                query = 'SecurityEvent | take 1'
                kind  = 'Scheduled'
                suppressionEnabled  = $true
                suppressionDuration = 'PT5H'
            }
            $r = & $script:GetDiags $obj
            $diag = $r.Diagnostics | Where-Object { $_.Capability -eq 'Alerts suppression - Define alert suppression after the rule runs' }
            $diag | Should -Not -BeNullOrEmpty
            $diag.Action | Should -Be 'Unsupported'
            $diag.Reason | Should -Match 'PT5H'
            (& $script:MatrixHasRow $diag.Feature $diag.Capability) | Should -BeTrue
        }

        # ---- F. Native remediation actions ---------------------------------
        It 'F: Should NOT emit the native-actions enrichment-opportunity diagnostic by default (opt-in)' {
            $obj = [PSCustomObject]@{
                id    = '81fb771a-c57e-41b8-9905-63dbf267c13f'
                name  = 'Actions Opportunity Rule'
                query = 'SecurityEvent | take 1'
                kind  = 'Scheduled'
            }
            $r = & $script:GetDiags $obj
            @($r.Diagnostics | Where-Object { $_.Capability -eq 'Native Defender XDR remediation actions' }) |
                Should -BeNullOrEmpty -Because 'the native-actions note is opt-in via -SuggestRemediationActions'
            # No actions fabricated.
            $r.Output.PSObject.Properties.Name | Should -Not -Contain 'actions'
        }

        It 'F: With -SuggestRemediationActions should emit ONE Info enrichment-opportunity diagnostic (Supported), no actions in output' {
            $obj = [PSCustomObject]@{
                id    = '81fb771a-c57e-41b8-9905-63dbf267c13f'
                name  = 'Actions Opportunity Rule'
                query = 'SecurityEvent | take 1'
                kind  = 'Scheduled'
            }
            $r = & $script:GetDiags $obj @{ SuggestRemediationActions = $true }
            $diag = @($r.Diagnostics | Where-Object { $_.Capability -eq 'Native Defender XDR remediation actions' })
            $diag.Count | Should -Be 1
            $diag[0].Severity | Should -Be 'Info'
            $diag[0].Reason | Should -Match 'IsolateMachine'
            # No actions fabricated.
            $r.Output.PSObject.Properties.Name | Should -Not -Contain 'actions'
            (& $script:MatrixHasRow $diag[0].Feature $diag[0].Capability) | Should -BeTrue
        }

        # ---- G. Automation rules -------------------------------------------
        It 'G: Should emit ONE low-noise RequiresReview automation diagnostic when incidentConfiguration is present' {
            $obj = [PSCustomObject]@{
                id    = '81fb771a-c57e-41b8-9905-63dbf267c13f'
                name  = 'Automation Rule'
                query = 'SecurityEvent | take 1'
                kind  = 'Scheduled'
                incidentConfiguration = [PSCustomObject]@{ createIncident = $true }
            }
            $r = & $script:GetDiags $obj
            $diag = @($r.Diagnostics | Where-Object { $_.Capability -eq 'Sentinel automation rules with incident trigger' })
            $diag.Count | Should -Be 1
            $diag[0].Action | Should -Be 'RequiresReview'
            (& $script:MatrixHasRow $diag[0].Feature $diag[0].Capability) | Should -BeTrue
        }

        # ---- No-noise guard -------------------------------------------------
        It 'Should NOT fire C/D/E/G drop diagnostics for a rule with none of those fields' {
            $obj = [PSCustomObject]@{
                id    = '81fb771a-c57e-41b8-9905-63dbf267c13f'
                name  = 'Clean Rule'
                query = 'SecurityEvent | take 1'
                kind  = 'Scheduled'
            }
            $r = & $script:GetDiags $obj
            $noiseCaps = @(
                'Choose between all events under one alert and one alert per event',
                'Customize alert grouping logic',
                'Create alerts without incidents',
                'Alerts suppression - Define alert suppression after the rule runs',
                'Sentinel automation rules with incident trigger',
                'Enrich alerts with custom details',
                'Define all alerts properties dynamically - Integrate query results in runtime'
            )
            foreach ($cap in $noiseCaps) {
                @($r.Diagnostics | Where-Object { $_.Capability -eq $cap }) |
                    Should -BeNullOrEmpty -Because "no '$cap' diagnostic should fire on a clean rule"
            }
            # customDetails must not appear in output.
            $r.Output.PSObject.Properties.Name | Should -Not -Contain 'customDetails'
        }

        It 'Every Stage 5 feature-gap row in FeatureGapRules.psd1 resolves to a real matrix row' {
            $src = Split-Path -Path $PSScriptRoot -Parent | Join-Path -ChildPath 'src'
            $gapPath = Join-Path $src 'Data' | Join-Path -ChildPath 'FeatureGapRules.psd1'
            $gap = Import-PowerShellDataFile -Path $gapPath
            foreach ($key in $gap.Capabilities.Keys) {
                $row = $gap.Capabilities[$key]
                (& $script:MatrixHasRow $row.Feature $row.Capability) |
                    Should -BeTrue -Because "FeatureGapRules row '$key' ($($row.Feature) / $($row.Capability)) must exist in the matrix"
            }
        }
    }

    # -------------------------------------------------------------------------
    Context 'Pipeline / object input' {

        It 'Should accept a PSObject via pipeline' {
            $sentinelObj = $script:BasicYaml | ConvertFrom-Yaml
            $result = $sentinelObj | ConvertTo-XDRCustomDetection -Format XDRConverter -Force 3>$null
            $result | Should -Not -BeNullOrEmpty
        }

        It 'Should process multiple objects from the pipeline' {
            $sentinelObjs = @(
                ($script:BasicYaml | ConvertFrom-Yaml),
                ($script:BasicYaml | ConvertFrom-Yaml)
            )
            $results = $sentinelObjs | ConvertTo-XDRCustomDetection -Format XDRConverter -Force 3>$null
            $results | Should -HaveCount 2
        }
    }

    # -------------------------------------------------------------------------
    Context 'Stage 6 — Batch summary report' {

        BeforeAll {
            # A rule with many gaps: multi-tactic (drops 2 tactics), invalid technique
            # (dropped), trigger threshold (unsupported), Sentinel-tier table (review).
            $script:GappyYaml = @'
id: 11111111-1111-1111-1111-111111111111
name: Gappy Rule
description: A rule with many conversion gaps.
severity: Medium
queryFrequency: PT1H
queryPeriod: PT1H
triggerOperator: gt
triggerThreshold: 5
tactics:
  - InitialAccess
  - Persistence
  - DefenseEvasion
relevantTechniques:
  - T1078
  - T9999999
query: SigninLogs | take 1
kind: Scheduled
'@

            # A clean DefenderOnly rule: single tactic, valid technique, default
            # trigger — minimal gaps, and importantly no Dropped/Unsupported.
            $script:CleanYaml = @'
id: 22222222-2222-2222-2222-222222222222
name: Clean Rule
description: A clean rule.
severity: Low
queryFrequency: PT1H
queryPeriod: PT1H
triggerOperator: gt
triggerThreshold: 0
tactics:
  - Execution
relevantTechniques:
  - T1059
query: DeviceProcessEvents | take 1
kind: Scheduled
'@
        }

        It 'Should write summary.json + summary.md with correct totals for a multi-rule batch' {
            $base = Join-Path TestDrive: 'batch-multi'
            $objs = @(
                ($script:BasicYaml | ConvertFrom-Yaml),
                ($script:GappyYaml | ConvertFrom-Yaml),
                ($script:CleanYaml | ConvertFrom-Yaml)
            )
            $objs | ConvertTo-XDRCustomDetection -Format XDRConverter -Force `
                -WriteBatchSummary -BatchSummaryPath $base 3>$null | Out-Null

            $jsonPath = "$base.summary.json"
            $mdPath   = "$base.summary.md"
            $jsonPath | Should -Exist
            $mdPath   | Should -Exist

            $summary = Get-Content $jsonPath -Raw | ConvertFrom-Json
            $summary.metadata.totalRules | Should -Be 3
            # All three rules emit at least the table-classification diagnostic.
            $summary.metadata.rulesWithGaps | Should -Be 3
            # The gappy rule emits a multi-tactic Dropped diagnostic + an invalid-technique
            # Dropped diagnostic => Dropped >= 2 total across the batch.
            $summary.byAction.Dropped | Should -BeGreaterOrEqual 2
            # The gappy rule's threshold is unsupported.
            $summary.byAction.Unsupported | Should -BeGreaterOrEqual 1

            # Markdown headline + tables.
            $md = Get-Content $mdPath -Raw
            $md | Should -Match '3 rule\(s\) converted'
            $md | Should -Match '## Diagnostics by action'
            $md | Should -Match '## Per-rule breakdown'
        }

        It 'Should reflect gaps per-rule and flag rules needing attention (RequiresReview counts)' {
            $base = Join-Path TestDrive: 'batch-attention'
            $objs = @(
                ($script:GappyYaml | ConvertFrom-Yaml),
                ($script:CleanYaml | ConvertFrom-Yaml)
            )
            $objs | ConvertTo-XDRCustomDetection -Format XDRConverter -Force `
                -WriteBatchSummary -BatchSummaryPath $base 3>$null | Out-Null

            $summary = Get-Content "$base.summary.json" -Raw | ConvertFrom-Json
            $summary.perRule | Should -HaveCount 2

            $gappy = $summary.perRule | Where-Object { $_.RuleName -eq 'Gappy Rule' }
            $clean = $summary.perRule | Where-Object { $_.RuleName -eq 'Clean Rule' }

            $gappy.NeedsAttention | Should -BeTrue
            $gappy.Dropped        | Should -BeGreaterOrEqual 2
            $gappy.Unsupported    | Should -BeGreaterOrEqual 1

            # The clean DefenderOnly rule has no Dropped/Unsupported gaps (the gappy
            # rule does) — the per-rule index differentiates them. BUT it still carries
            # ATT&CK-page RequiresReview notes, and per the documented rule
            # NeedsAttention = (Dropped + Unsupported + RequiresReview) > 0, so the
            # clean rule's NeedsAttention is TRUE (driven solely by RequiresReview).
            $clean.Dropped        | Should -Be 0
            $clean.Unsupported    | Should -Be 0
            $clean.RequiresReview | Should -BeGreaterThan 0
            $clean.NeedsAttention | Should -BeTrue
            # A genuinely attention-free case (NeedsAttention = $false) is asserted with
            # synthetic data in the Get-ConversionBatchAggregate unit context below.
        }

        It 'Should NOT write any summary files by default (no behavior change)' {
            $base = Join-Path TestDrive: 'batch-default'
            $objs = @(
                ($script:BasicYaml | ConvertFrom-Yaml),
                ($script:BasicYaml | ConvertFrom-Yaml)
            )
            $objs | ConvertTo-XDRCustomDetection -Format XDRConverter -Force 3>$null | Out-Null

            "$base.summary.json" | Should -Not -Exist
            "$base.summary.md"   | Should -Not -Exist
        }

        It 'Should produce a one-row summary for a single rule when opted in' {
            $base = Join-Path TestDrive: 'batch-single'
            ($script:BasicYaml | ConvertFrom-Yaml) | ConvertTo-XDRCustomDetection -Format XDRConverter -Force `
                -WriteBatchSummary -BatchSummaryPath $base 3>$null | Out-Null

            $summary = Get-Content "$base.summary.json" -Raw | ConvertFrom-Json
            $summary.metadata.totalRules | Should -Be 1
            $summary.perRule | Should -HaveCount 1
            $summary.perRule[0].RuleName | Should -Be 'Test Sentinel Rule'
        }

        It 'Should warn and write nothing when -WriteBatchSummary lacks -BatchSummaryPath' {
            $warnings = @()
            ($script:BasicYaml | ConvertFrom-Yaml) | ConvertTo-XDRCustomDetection -Format XDRConverter -Force `
                -WriteBatchSummary -WarningVariable warnings -WarningAction SilentlyContinue 3>$null | Out-Null
            $warnings | Where-Object { $_ -match 'without -BatchSummaryPath' } | Should -Not -BeNullOrEmpty
        }
    }

    # -------------------------------------------------------------------------
    Context 'Stage 6 — Get-ConversionBatchAggregate unit' {

        BeforeAll {
            $src = Split-Path -Path $PSScriptRoot -Parent | Join-Path -ChildPath 'src'
            . (Join-Path $src 'Private' | Join-Path -ChildPath 'Write-ConversionBatchSummary.ps1')

            $script:MakeDiag = {
                param($Feature, $Capability, $Severity, $Action)
                [PSCustomObject]@{
                    Feature = $Feature; Capability = $Capability
                    Severity = $Severity; Action = $Action
                }
            }
        }

        It 'Should count by Action, Severity and Feature::Capability correctly' {
            $results = @(
                [PSCustomObject]@{
                    RuleName = 'R1'; Guid = 'g1'
                    Diagnostics = @(
                        (& $script:MakeDiag 'Rule frequency' 'Freq' 'Warning' 'Rounded'),
                        (& $script:MakeDiag 'MITRE' 'Tactics' 'Warning' 'Dropped'),
                        (& $script:MakeDiag 'MITRE' 'Tactics' 'Warning' 'Dropped')
                    )
                },
                [PSCustomObject]@{
                    RuleName = 'R2'; Guid = 'g2'
                    Diagnostics = @(
                        (& $script:MakeDiag 'Trigger' 'Grouping' 'Warning' 'Unsupported')
                    )
                },
                [PSCustomObject]@{ RuleName = 'R3'; Guid = 'g3'; Diagnostics = @() }
            )

            $agg = Get-ConversionBatchAggregate -Results $results
            $agg.TotalRules       | Should -Be 3
            $agg.RulesWithGaps    | Should -Be 2
            $agg.TotalDiagnostics | Should -Be 4
            $agg.ByAction.Dropped     | Should -Be 2
            $agg.ByAction.Rounded     | Should -Be 1
            $agg.ByAction.Unsupported | Should -Be 1
            $agg.BySeverity.Warning   | Should -Be 4
            $agg.ByCapability.'MITRE :: Tactics' | Should -Be 2

            $r1 = $agg.PerRule | Where-Object { $_.RuleName -eq 'R1' }
            $r1.Dropped        | Should -Be 2
            $r1.NeedsAttention | Should -BeTrue
            $r3 = $agg.PerRule | Where-Object { $_.RuleName -eq 'R3' }
            $r3.NeedsAttention | Should -BeFalse
        }

        It 'Should set NeedsAttention only when Dropped/Unsupported/RequiresReview present' {
            $results = @(
                # No diagnostics at all -> attention free.
                [PSCustomObject]@{ RuleName = 'Empty'; Guid = 'g0'; Diagnostics = @() },
                # Only benign Mapped/Info diagnostics -> attention free.
                [PSCustomObject]@{
                    RuleName = 'Benign'; Guid = 'g1'
                    Diagnostics = @(
                        (& $script:MakeDiag 'F' 'C' 'Info' 'Mapped')
                    )
                },
                # A RequiresReview note alone (no Dropped/Unsupported) -> needs attention.
                [PSCustomObject]@{
                    RuleName = 'ReviewOnly'; Guid = 'g2'
                    Diagnostics = @(
                        (& $script:MakeDiag 'MITRE' 'ATT&CK page' 'Info' 'RequiresReview')
                    )
                }
            )
            $agg = Get-ConversionBatchAggregate -Results $results

            $empty = $agg.PerRule | Where-Object { $_.RuleName -eq 'Empty' }
            $empty.NeedsAttention | Should -BeFalse

            $benign = $agg.PerRule | Where-Object { $_.RuleName -eq 'Benign' }
            $benign.NeedsAttention | Should -BeFalse

            $review = $agg.PerRule | Where-Object { $_.RuleName -eq 'ReviewOnly' }
            $review.RequiresReview | Should -Be 1
            $review.Dropped        | Should -Be 0
            $review.Unsupported    | Should -Be 0
            $review.NeedsAttention | Should -BeTrue
        }

        It 'Should key ByCapability without a leading/trailing separator for empty parts' {
            $results = @(
                [PSCustomObject]@{
                    RuleName = 'R1'; Guid = 'g1'
                    Diagnostics = @(
                        # Both present -> normal 'Feature :: Capability' key (unchanged).
                        (& $script:MakeDiag 'MITRE' 'Tactics' 'Warning' 'Dropped'),
                        # Empty Capability -> Feature only, no trailing ' :: '.
                        (& $script:MakeDiag 'Trigger' '' 'Warning' 'Unsupported'),
                        # Empty Feature -> Capability only, no leading ' :: '.
                        (& $script:MakeDiag '' 'Grouping' 'Warning' 'Rounded')
                    )
                }
            )
            $agg = Get-ConversionBatchAggregate -Results $results
            $keys = @($agg.ByCapability.Keys)
            $keys | Should -Contain 'MITRE :: Tactics'
            $keys | Should -Contain 'Trigger'
            $keys | Should -Contain 'Grouping'
            ($keys | Where-Object { $_ -match '(^ :: | :: $)' }) | Should -BeNullOrEmpty
        }

        It 'Should sort ByAction deterministically (count desc, then name asc)' {
            $results = @(
                [PSCustomObject]@{
                    RuleName = 'R1'; Guid = 'g1'
                    Diagnostics = @(
                        (& $script:MakeDiag 'F' 'C' 'Warning' 'Mapped'),
                        (& $script:MakeDiag 'F' 'C' 'Warning' 'Mapped'),
                        (& $script:MakeDiag 'F' 'C' 'Warning' 'Dropped'),
                        (& $script:MakeDiag 'F' 'C' 'Warning' 'Constrained')
                    )
                }
            )
            $agg = Get-ConversionBatchAggregate -Results $results
            $keys = @($agg.ByAction.Keys)
            # Mapped (2) first; then Constrained vs Dropped (1 each) by name asc.
            $keys[0] | Should -Be 'Mapped'
            $keys[1] | Should -Be 'Constrained'
            $keys[2] | Should -Be 'Dropped'
        }
    }
}
