Describe 'The five undocumented custom detection API constraints' {

    # Every constraint here was found by POSTing a rule to a live Defender XDR tenant and
    # reading the 400. None appears in the Graph reference or the product documentation,
    # and each one refuses a rule that converts cleanly, validates against
    # CustomDetection.schema.json and runs fine in advanced hunting.
    #
    # That combination - correct by every offline check, refused by the service - is the
    # most expensive answer this module can give, and until 1.0.0 it gave it silently on
    # roughly half of any real estate. These tests are the regression guard.
    #
    # See docs/API-Constraints.md for the evidence, and TacticConstraints /
    # RequiredAlertTemplateFields / EntityIdentifierRequirements in
    # src/Data/GraphDetectionRule.psd1 for the constraints as data.

    BeforeAll {
        $ModulePath = Split-Path -Path $PSScriptRoot -Parent
        $ModulePath = Join-Path -Path $ModulePath -ChildPath 'src' | Join-Path -ChildPath 'SentinelToXDR.psd1'
        Import-Module -Name $ModulePath -Force

        $script:TestRoot = Join-Path ([System.IO.Path]::GetTempPath()) "s2x-apiconstraints-$([System.Guid]::NewGuid())"
        New-Item -ItemType Directory -Path $script:TestRoot -Force | Out-Null

        # One fixture builder, so each test differs from the next in exactly the field
        # under test - the same discipline the live probes needed. Two probes in the
        # original round failed on an unrelated constraint and looked like evidence
        # against the hypothesis being tested.
        function New-ConstraintRule {
            param(
                [string]$Name,
                [string]$Mitre = "tactics:`n  - Execution`nrelevantTechniques:`n  - T1059",
                [string]$Entities = "entityMappings:`n  - entityType: Host`n    fieldMappings:`n      - identifier: HostName`n        columnName: DeviceName"
            )
            $path = Join-Path $script:TestRoot "$Name.yaml"
            Set-Content -LiteralPath $path -Encoding utf8NoBOM -Value @"
id: $([System.Guid]::NewGuid())
name: Rule $Name
description: Fixture.
severity: Medium
kind: Scheduled
queryFrequency: PT1H
queryPeriod: PT1H
$Mitre
query: |
  DeviceProcessEvents
  | where FileName == "powershell.exe"
$Entities
"@
            return $path
        }

        function Get-Constraints {
            param([string]$Path)
            $result = Get-SentinelAnalyticsRule -Path $Path |
                ConvertTo-XDRCustomDetection -As Object -Force -WarningAction SilentlyContinue
            return [PSCustomObject]@{
                Rule        = $result.Rule
                Constraints = @($result.Diagnostics |
                        Where-Object { $_.Capability -eq 'Custom detection API requirements' })
            }
        }
    }

    AfterAll {
        if ($script:TestRoot -and (Test-Path $script:TestRoot)) {
            Remove-Item -Path $script:TestRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    Context 'A rule that satisfies all five' {

        It 'Should emit a deployable payload and raise no constraint finding at all' {
            $r = Get-Constraints -Path (New-ConstraintRule -Name 'clean')
            $r.Constraints.Count | Should -Be 0
            $at = $r.Rule.detectionAction.alertTemplate
            @($at.tactics).Count | Should -Be 1
            @($at.tactics[0].techniques).Count | Should -BeGreaterThan 0
            $at.Contains('entityMappings') | Should -BeTrue
        }
    }

    Context 'Constraint 1 - one tactic, and the technique rule that went away' {

        It 'Should keep one tactic and report the rest, rather than emitting a payload the service refuses' {
            $path = New-ConstraintRule -Name 'many-tactics' `
                -Mitre "tactics:`n  - Execution`n  - Persistence`n  - Impact`nrelevantTechniques:`n  - T1059"
            $r = Get-Constraints -Path $path

            @($r.Rule.detectionAction.alertTemplate.tactics).Count | Should -Be 1
            $r.Rule.detectionAction.alertTemplate.tactics[0].tactic | Should -Be 'Execution'

            $finding = @($r.Constraints | Where-Object { $_.TargetValue -eq 'TacticsTruncated' })
            $finding.Count | Should -Be 1
            $finding[0].Reason | Should -Match 'Persistence'
            $finding[0].Reason | Should -Match 'Impact'
        }

        It 'Should carry a tactic that has no techniques, rather than discarding it' {
            # Inverted on 2026-09-15. This asserted the opposite - that no tactics were
            # emitted and the rule was told to add a relevantTechniques entry - because on
            # 2026-08-19 a bare tactic was refused. A fresh-id probe showed the service now
            # accepts it and stores {"tactic":"Execution","techniques":[]}. Dropping the
            # tactic would throw away ATT&CK data the service would have taken, and the
            # finding would announce a rejection that does not happen.
            $path = New-ConstraintRule -Name 'no-technique' -Mitre "tactics:`n  - Execution"
            $r = Get-Constraints -Path $path

            $tactics = @($r.Rule.detectionAction.alertTemplate.tactics)
            $tactics.Count | Should -Be 1
            $tactics[0].tactic | Should -Be 'Execution'
            @($tactics[0].techniques).Count | Should -Be 0
            $r.Constraints.Count | Should -Be 0 -Because 'nothing here will be refused'
        }

        It 'Should take the technique requirement from data, so lifting it stays a data edit' {
            $constraints = InModuleScope SentinelToXDR { (Get-GraphDetectionRuleMap).TacticConstraints }
            $constraints.TechniqueRequiredPerTactic | Should -BeFalse
            @($constraints.History).Count | Should -BeGreaterThan 1 -Because 'the requirement existed once and that record has to survive'
        }
    }

    Context 'Constraint 4 - entity mappings are mandatory' {

        It 'Should say nothing about a rule with no MITRE data at all' {
            # Until 2026-09-15 this asserted a TacticsMissing finding naming category and its
            # 2026-10-01 removal. The service accepted a no-tactics rule on a fresh id that
            # day, so that finding would now be a false rejection - and over the corpus the
            # requirement had been condemning 795 rules.
            $r = Get-Constraints -Path (New-ConstraintRule -Name 'no-mitre' -Mitre 'description2: unused')
            $r.Rule.detectionAction.alertTemplate.Contains('tactics') | Should -BeFalse
            $r.Constraints.Count | Should -Be 0
        }

        It 'Should report a rule with no entity mappings, naming the deprecated fallback and its date' {
            $r = Get-Constraints -Path (New-ConstraintRule -Name 'no-entities' -Entities 'description3: unused')
            $finding = @($r.Constraints | Where-Object { $_.TargetValue -eq 'EntityMappingsMissing' })
            $finding.Count | Should -Be 1
            $finding[0].Reason | Should -Match 'impactedAssets'
            $finding[0].Reason | Should -Match '2026-10-01'
        }

        It 'Should treat an entity whose type has no Graph equivalent as no entity mappings' {
            # The entity is dropped upstream, so the rule reaches the API with nothing.
            # Reporting only 'an entity was dropped' would understate it: the rule does
            # not deploy at all.
            $path = New-ConstraintRule -Name 'iot-only' `
                -Entities "entityMappings:`n  - entityType: IoTDevice`n    fieldMappings:`n      - identifier: DeviceId`n        columnName: DeviceId"
            $r = Get-Constraints -Path $path
            @($r.Constraints | Where-Object { $_.TargetValue -eq 'EntityMappingsMissing' }).Count | Should -Be 1
        }
    }

    Context 'Constraint 5 - entity identifiers are validated per type' {

        It 'Should report an Account mapped on a name alone, and name the columns that would work' {
            $path = New-ConstraintRule -Name 'weak-account' `
                -Entities "entityMappings:`n  - entityType: Account`n    fieldMappings:`n      - identifier: Name`n        columnName: AccountName"
            $r = Get-Constraints -Path $path

            $finding = @($r.Constraints | Where-Object { $_.TargetValue -eq 'EntityIdentifierWeak' })
            $finding.Count | Should -Be 1
            $finding[0].Reason | Should -Match 'sidColumn'
        }

        It 'Should accept an Account carrying a strong identifier alongside the name' {
            $path = New-ConstraintRule -Name 'strong-account' `
                -Entities ("entityMappings:`n  - entityType: Account`n    fieldMappings:" +
                    "`n      - identifier: Name`n        columnName: AccountName" +
                    "`n      - identifier: Sid`n        columnName: AccountSid")
            $r = Get-Constraints -Path $path
            @($r.Constraints | Where-Object { $_.TargetValue -eq 'EntityIdentifierWeak' }).Count | Should -Be 0
        }

        It 'Should accept a Host on a name alone, because the service does' {
            # The asymmetry IS the constraint. A test that treated every entity the same
            # would pass while the module was wrong about both.
            $r = Get-Constraints -Path (New-ConstraintRule -Name 'host-name')
            @($r.Constraints | Where-Object { $_.TargetValue -eq 'EntityIdentifierWeak' }).Count | Should -Be 0
        }

        It 'Should say nothing about an entity type whose accepted combinations are not known' {
            # The most important guard in this file. Where the service has enumerated its
            # sufficient combinations (Complete = $true) a refusal is a statement from the
            # service. Everywhere else the table is what has been probed, and grading a rule
            # down on an unprobed combination would be the same class of error as the silent
            # acceptance this release exists to fix - a verdict asserted rather than measured.
            #
            # This test used Account/NTDomain until 2026-09-15, when the service began
            # listing the full account table in its own error and that case stopped being
            # unknown. It moved rather than being deleted; if azureResources ever gains an
            # entry, move it again.
            $confirmed = InModuleScope SentinelToXDR {
                (Get-GraphDetectionRuleMap).EntityIdentifierRequirements.Confirmed
            }
            $confirmed.ContainsKey('azureResources') | Should -BeFalse -Because 'this test needs an entity type nobody has probed'

            $path = New-ConstraintRule -Name 'unknown-type' `
                -Entities ("entityMappings:`n  - entityType: Host`n    fieldMappings:" +
                    "`n      - identifier: HostName`n        columnName: DeviceName" +
                    "`n  - entityType: AzureResource`n    fieldMappings:" +
                    "`n      - identifier: ResourceId`n        columnName: ResourceId")
            $r = Get-Constraints -Path $path
            @($r.Constraints | Where-Object { $_.TargetValue -eq 'EntityIdentifierWeak' }).Count |
                Should -Be 0 -Because 'an unprobed entity type is unknown, not invalid'
        }

        It 'Should treat a combination the service did not list as refused, where it listed them all' {
            $complete = InModuleScope SentinelToXDR {
                (Get-GraphDetectionRuleMap).EntityIdentifierRequirements.Confirmed.accounts.Complete
            }
            $complete | Should -BeTrue

            $path = New-ConstraintRule -Name 'unlisted-account' `
                -Entities "entityMappings:`n  - entityType: Account`n    fieldMappings:`n      - identifier: NTDomain`n        columnName: AccountDomain"
            $r = Get-Constraints -Path $path
            @($r.Constraints | Where-Object { $_.TargetValue -eq 'EntityIdentifierWeak' }).Count |
                Should -Be 1 -Because 'the service enumerated every accepted account combination and a domain alone is not one'
        }
    }

    Context 'Techniques are emitted in the documented mitreTechnique shape' {

        # This context replaced one called 'Constraint 6 - subtechniques collapse into their
        # parent, silently'. That constraint never existed. The round trip on 2026-08-24
        # reported 'sent 2, stored 1', it was written up as the service discarding a
        # technique, and three tests asserted the module reported the loss. Once the drift
        # report named values instead of counting them, the stored form was
        # { technique: T1059, subTechniques: [T1059.001] } - the documented Graph model,
        # into which the service had normalised our malformed input. Nothing was lost.
        # A count-only diff made a renderer bug look like an undocumented constraint.

        It 'Should nest a subtechnique under its parent rather than listing it as a technique' {
            $path = New-ConstraintRule -Name 'subtechnique' `
                -Mitre "tactics:`n  - Execution`nrelevantTechniques:`n  - T1059`n  - T1059.001"
            $r = Get-Constraints -Path $path

            $techniques = @($r.Rule.detectionAction.alertTemplate.tactics[0].techniques)
            $techniques.Count | Should -Be 1
            $techniques[0].technique | Should -Be 'T1059'
            @($techniques[0].subTechniques) | Should -Be @('T1059.001')
        }

        It 'Should give a lone subtechnique its parent entry, because the model has nowhere else to put it' {
            $path = New-ConstraintRule -Name 'lone-subtechnique' `
                -Mitre "tactics:`n  - Execution`nrelevantTechniques:`n  - T1059.001"
            $r = Get-Constraints -Path $path

            $techniques = @($r.Rule.detectionAction.alertTemplate.tactics[0].techniques)
            $techniques.Count | Should -Be 1
            $techniques[0].technique | Should -Be 'T1059'
            @($techniques[0].subTechniques) | Should -Be @('T1059.001')
        }

        It 'Should emit an empty subTechniques collection, matching what the service stores' {
            # The service read-back shows T1547 with subTechniques present and empty. Emitting
            # it the same way is what lets a sent-versus-stored comparison come back clean.
            $path = New-ConstraintRule -Name 'no-subtechnique' `
                -Mitre "tactics:`n  - Execution`nrelevantTechniques:`n  - T1547"
            $r = Get-Constraints -Path $path

            $technique = @($r.Rule.detectionAction.alertTemplate.tactics[0].techniques)[0]
            $technique.Contains('subTechniques') | Should -BeTrue
            @($technique.subTechniques).Count | Should -Be 0
        }

        It 'Should raise no finding for subtechniques, because nothing is lost' {
            $path = New-ConstraintRule -Name 'subtechnique-quiet' `
                -Mitre "tactics:`n  - Execution`nrelevantTechniques:`n  - T1059`n  - T1059.001`n  - T1059.003"
            $r = Get-Constraints -Path $path
            $r.Constraints.Count | Should -Be 0
        }
    }

    Context 'Constraint 7 - an asset entity or an IP must be present' {

        It 'Should report a rule that maps only non-asset entities' {
            $path = New-ConstraintRule -Name 'no-asset' `
                -Entities ("entityMappings:`n  - entityType: URL`n    fieldMappings:" +
                    "`n      - identifier: Url`n        columnName: RemoteUrl")
            $r = Get-Constraints -Path $path

            $finding = @($r.Constraints | Where-Object { $_.TargetValue -eq 'AssetEntityMissing' })
            $finding.Count | Should -Be 1
            $finding[0].Reason | Should -Match 'asset entity'
        }

        It 'Should accept the same rule once an asset entity is added alongside' {
            $path = New-ConstraintRule -Name 'asset-added' `
                -Entities ("entityMappings:`n  - entityType: URL`n    fieldMappings:" +
                    "`n      - identifier: Url`n        columnName: RemoteUrl" +
                    "`n  - entityType: Host`n    fieldMappings:" +
                    "`n      - identifier: HostName`n        columnName: DeviceName")
            $r = Get-Constraints -Path $path
            @($r.Constraints | Where-Object { $_.TargetValue -eq 'AssetEntityMissing' }).Count | Should -Be 0
        }

        It 'Should not also claim the entity mappings are missing when they are merely wrong' {
            # Two findings for one cause is how a report stops being read.
            $path = New-ConstraintRule -Name 'asset-not-missing' `
                -Entities ("entityMappings:`n  - entityType: URL`n    fieldMappings:" +
                    "`n      - identifier: Url`n        columnName: RemoteUrl")
            $r = Get-Constraints -Path $path
            @($r.Constraints | Where-Object { $_.TargetValue -eq 'EntityMappingsMissing' }).Count | Should -Be 0
        }
    }

    Context 'Entity identifier sufficiency is a property of column SETS' {

        It 'Should accept a name plus a domain while refusing the name alone' {
            # The distinction the 2026-08-24 probe established, and the reason the table
            # holds combinations rather than columns: accounts {nameColumn} is refused and
            # accounts {nameColumn, ntDomainColumn} is accepted, so a domain that is not
            # sufficient by itself makes a name sufficient. Reading the table as a flat
            # column list would turn 'name AND domain' into 'name OR domain'.
            $weak = Get-Constraints -Path (New-ConstraintRule -Name 'set-weak' `
                -Entities ("entityMappings:`n  - entityType: Account`n    fieldMappings:" +
                    "`n      - identifier: Name`n        columnName: AccountName"))
            @($weak.Constraints | Where-Object { $_.TargetValue -eq 'EntityIdentifierWeak' }).Count | Should -Be 1

            $strong = Get-Constraints -Path (New-ConstraintRule -Name 'set-strong' `
                -Entities ("entityMappings:`n  - entityType: Account`n    fieldMappings:" +
                    "`n      - identifier: Name`n        columnName: AccountName" +
                    "`n      - identifier: NTDomain`n        columnName: AccountDomain"))
            @($strong.Constraints | Where-Object { $_.TargetValue -eq 'EntityIdentifierWeak' }).Count | Should -Be 0
        }

        It 'Should accept a name plus a DNS domain, which the service lists as sufficient' {
            # Until 2026-09-15 this asserted silence because dnsDomainColumn was untested.
            # The service has since listed 'nameColumn + dnsDomainColumn' among the accepted
            # account combinations, so the same assertion now holds for a better reason.
            $r = Get-Constraints -Path (New-ConstraintRule -Name 'set-unknown' `
                -Entities ("entityMappings:`n  - entityType: Account`n    fieldMappings:" +
                    "`n      - identifier: Name`n        columnName: AccountName" +
                    "`n      - identifier: DnsDomain`n        columnName: AccountDnsDomain"))
            @($r.Constraints | Where-Object { $_.TargetValue -eq 'EntityIdentifierWeak' }).Count | Should -Be 0
        }

        It 'Should keep every sufficient combination intact through the data file import' {
            # PowerShell flattens @(@('a'),@('b','c')) on import, which would silently
            # widen every multi-column combination into a set of single columns. The
            # combinations are strings for exactly that reason; this asserts one survived.
            $accounts = InModuleScope SentinelToXDR {
                (Get-GraphDetectionRuleMap).EntityIdentifierRequirements.Confirmed.accounts
            }
            @($accounts.Sufficient) | Should -Contain 'nameColumn + ntDomainColumn'
            @($accounts.Sufficient) | Should -Not -Contain 'ntDomainColumn' -Because 'a domain alone is untested, not sufficient'
        }
    }

    Context 'The update path does not echo the service back to itself' {

        It 'Should strip a deprecated property nested inside an updatable one' {
            # The service sets schedule.period to 'Custom' for an ISO 8601 frequency it has
            # no enum value for, and then refuses that value on PATCH. So a read-back
            # re-applied verbatim fails on a value the service produced. UpdatableProperties
            # filters the top level; this is one level in, and only the update leg sees it.
            $readBack = [pscustomobject]@{
                id             = 'x'
                displayName    = 'X'
                description    = 'd'
                status         = 'enabled'
                createdBy      = 'someone'
                queryCondition = [ordered]@{ queryText = 'DeviceProcessEvents | take 1' }
                schedule       = [ordered]@{ frequency = 'PT1H'; period = 'Custom'; nextRunDateTime = '2026-01-01' }
            }
            $body = InModuleScope SentinelToXDR -Parameters @{ Rule = $readBack } {
                param($Rule) ConvertTo-DetectionPatchBody -Rule $Rule
            }

            $body.schedule.Contains('period') | Should -BeFalse -Because 'the service refuses the value it set itself'
            $body.schedule.Contains('nextRunDateTime') | Should -BeFalse -Because 'it is server-owned'
            $body.schedule.frequency | Should -Be 'PT1H' -Because 'stripping must not take the property that matters'
            $body.Keys | Should -Not -Contain 'id'
            $body.Keys | Should -Not -Contain 'createdBy'
        }

        It 'Should take every nested name it strips from the deprecation data' {
            $nested = InModuleScope SentinelToXDR {
                @((Get-GraphDetectionRuleMap).DeprecatedProperties |
                    Where-Object { @([string]$_.Path -split '\.').Count -eq 2 } |
                    ForEach-Object { @([string]$_.Path -split '\.')[1] })
            }
            $nested | Should -Contain 'period' -Because 'the fix is a data edit when Microsoft removes the property'
            $nested | Should -Contain 'category'
            $nested | Should -Contain 'impactedAssets'
        }
    }

    Context 'The constraint data and the readiness classification stay in step' {

        It 'Should classify every constraint the converter can raise' {
            # A constraint name with no matching entry in MigrationReadiness.psd1 falls
            # through to DefaultImpact = Low and never reaches a verdict - the finding
            # would exist and change nothing, which is worse than not raising it.
            $readiness = InModuleScope SentinelToXDR { Get-MigrationReadinessData }
            $classified = @($readiness.Rules |
                    Where-Object { $_.Capability -eq 'Custom detection API requirements' } |
                    ForEach-Object { [string]$_.TargetValue })

            foreach ($constraint in @('TacticsTruncated', 'EntityMappingsMissing',
                    'EntityIdentifierWeak', 'AssetEntityMissing')) {
                $classified | Should -Contain $constraint
            }
        }

        It 'Should name a required-field constraint for every field the service requires' {
            $required = InModuleScope SentinelToXDR { (Get-GraphDetectionRuleMap).RequiredAlertTemplateFields }
            foreach ($field in $required) {
                [string]$field.Constraint | Should -Not -BeNullOrEmpty -Because "'$($field.Field)' needs a finding name to raise"
                [string]$field.AlternativeRemovalDate | Should -Not -BeNullOrEmpty
            }
        }

        It 'Should keep the two views of the deprecation window the same size' {
            # The readiness report matches classified findings by Summary; the conversion
            # batch summary matches raw diagnostics by TargetValue. Same three findings,
            # two vocabularies, and nothing but this test stops them drifting apart.
            $window = InModuleScope SentinelToXDR { (Get-MigrationReadinessData).DeprecationWindow }
            @($window.AppliesToSummaries).Count | Should -Be @($window.AppliesToConstraints).Count
        }

        It 'Should put the dated window in front of the reader when a rule depends on it' {
            $reportDir = Join-Path $script:TestRoot 'report'
            New-Item -ItemType Directory -Path $reportDir -Force | Out-Null

            $affected = New-ConstraintRule -Name 'window-affected' -Entities 'description3: unused'
            $md = Join-Path $reportDir 'affected.md'
            Test-XDRMigrationReadiness -Path $affected -WarningAction SilentlyContinue |
                Export-XDRMigrationReport -Path $md
            $text = Get-Content -LiteralPath $md -Raw
            $text | Should -Match '2026-10-01'
            $text | Should -Match 'Deadline'

            # And absent when nothing in the run depends on it - a banner that is always
            # there is a banner nobody reads.
            $clean = New-ConstraintRule -Name 'window-clean'
            $md2 = Join-Path $reportDir 'clean.md'
            Test-XDRMigrationReadiness -Path $clean -WarningAction SilentlyContinue |
                Export-XDRMigrationReport -Path $md2
            (Get-Content -LiteralPath $md2 -Raw) | Should -Not -Match 'Deadline'
        }

        It 'Should only list deprecation-window summaries that a classification actually produces' {
            $readiness = InModuleScope SentinelToXDR { Get-MigrationReadinessData }
            $all = @($readiness.Rules | ForEach-Object { [string]$_.Summary })
            foreach ($summary in @($readiness.DeprecationWindow.AppliesToSummaries)) {
                $all | Should -Contain $summary
            }
        }
    }
}
