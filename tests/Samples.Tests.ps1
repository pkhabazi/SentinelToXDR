Describe 'Sample rules' {

    # The Samples folder is the demo, the fixture corpus, and the payload for the
    # round-trip validation. It is only worth any of that if the claims in its README and
    # in each file's header are still true, so every claim is asserted here.
    #
    # A converter change that silently reclassifies a sample fails the build, rather than
    # quietly making the documentation and the demo wrong.

    BeforeAll {
        $repoRoot = Split-Path -Path $PSScriptRoot -Parent
        Import-Module -Name (Join-Path $repoRoot 'src/SentinelToXDR.psd1') -Force

        $script:SamplesPath = Join-Path $repoRoot 'Samples'
        $script:Expected = Import-PowerShellDataFile -Path (Join-Path $script:SamplesPath 'expected.psd1')

        # Assess the whole folder once; the per-sample tests slice this.
        $script:Results = @(Test-XDRMigrationReadiness -Path $script:SamplesPath -PassThruDetection -WarningAction SilentlyContinue)

        function Get-ResultsFor {
            param([string]$File)
            @($script:Results | Where-Object { (Split-Path $_.SourcePath -Leaf) -eq $File })
        }
    }

    Context 'Folder integrity' {

        It 'Should have an expectation for every sample file, and a file for every expectation' {
            $onDisk = @(Get-ChildItem -LiteralPath $script:SamplesPath -File |
                Where-Object { $_.Extension -in '.yaml', '.yml', '.json' -and $_.Name -ne 'expected.psd1' } |
                Select-Object -ExpandProperty Name | Sort-Object)
            $declared = @($script:Expected.Samples.File | Sort-Object)

            ($onDisk -join ', ') | Should -Be ($declared -join ', ') -Because 'an undocumented sample is a sample nobody trusts'
        }

        It 'Should describe the use case for every sample' {
            foreach ($sample in $script:Expected.Samples) {
                $sample.UseCase | Should -Not -BeNullOrEmpty -Because "$($sample.File) has to say what it demonstrates"
            }
        }

        It 'Should give every deployable sample a recognisable 5a1e id' {
            # Makes them obvious in a tenant after a round-trip validation run. Blocked
            # samples are exempt: they are never deployed, and the Fusion one deliberately
            # carries a real Microsoft alertRuleTemplateName because that is what the
            # source content actually looks like.
            $generated = @($script:Expected.Samples | Where-Object { $_.GeneratesId } | ForEach-Object { $_.File })

            foreach ($result in $script:Results) {
                if ($result.Verdict -eq 'Blocked' -or -not $result.Id) { continue }
                if ((Split-Path $result.SourcePath -Leaf) -in $generated) { continue }
                $result.Id | Should -Match '^5a1e' -Because "$($result.RuleName) will be created in a real tenant"
            }
        }

        It 'Should cover every verdict the assessment can produce' {
            $verdicts = @($script:Results.Verdict | Sort-Object -Unique)
            foreach ($verdict in @('Ready', 'Review', 'NeedsWork', 'Blocked')) {
                $verdicts | Should -Contain $verdict -Because 'the demo needs one of each'
            }
        }
    }

    Context 'Documented behaviour' {

        It '<File> should be <ExpectedVerdict>' -ForEach @(
            $expectedPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Samples/expected.psd1'
            (Import-PowerShellDataFile -Path $expectedPath).Samples | Where-Object { $_.ExpectedVerdict }
        ) {
            $results = Get-ResultsFor -File $File
            $results.Count | Should -BeGreaterThan 0 -Because "$File must produce at least one rule"
            $results[0].Verdict | Should -Be $ExpectedVerdict
        }

        It '<File> should classify as <ExpectedTier>' -ForEach @(
            $expectedPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Samples/expected.psd1'
            (Import-PowerShellDataFile -Path $expectedPath).Samples | Where-Object { $_.ExpectedTier }
        ) {
            (Get-ResultsFor -File $File)[0].DataTier | Should -Be $ExpectedTier
        }

        It '<File> should report: <MustContain>' -ForEach @(
            $expectedPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Samples/expected.psd1'
            (Import-PowerShellDataFile -Path $expectedPath).Samples | Where-Object { $_.MustContain }
        ) {
            # MustContain may list several findings; every one has to be in the headline.
            $headline = @((Get-ResultsFor -File $File)[0].Headline)
            foreach ($expected in @($MustContain)) {
                $headline | Should -Contain $expected
            }
        }

        It '<File> should yield <ExpectedRuleCount> rule(s)' -ForEach @(
            $expectedPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Samples/expected.psd1'
            (Import-PowerShellDataFile -Path $expectedPath).Samples | Where-Object { $null -ne $_.ExpectedRuleCount }
        ) {
            (Get-ResultsFor -File $File).Count | Should -Be $ExpectedRuleCount
        }

        It '<File> should schedule at <ExpectedFrequency>' -ForEach @(
            $expectedPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Samples/expected.psd1'
            (Import-PowerShellDataFile -Path $expectedPath).Samples | Where-Object { $_.ExpectedFrequency }
        ) {
            (Get-ResultsFor -File $File)[0].Detection.Rule.schedule.frequency | Should -Be $ExpectedFrequency
        }

        It '<File> should recover the id <ExpectedId> from the source' -ForEach @(
            $expectedPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Samples/expected.psd1'
            (Import-PowerShellDataFile -Path $expectedPath).Samples | Where-Object { $_.ExpectedId }
        ) {
            (Get-ResultsFor -File $File)[0].Id | Should -Be $ExpectedId
        }

        # These two fixture fields existed in expected.psd1 (samples 23 and 26) with nothing
        # asserting them - a claim in the fixture that the suite never checked.
        It '<File> should be named <ExpectedDisplayName>' -ForEach @(
            $expectedPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Samples/expected.psd1'
            (Import-PowerShellDataFile -Path $expectedPath).Samples | Where-Object { $_.ExpectedDisplayName }
        ) {
            (Get-ResultsFor -File $File)[0].Detection.Rule.displayName | Should -Be $ExpectedDisplayName
        }

        It '<File> should carry exactly the expected custom details' -ForEach @(
            $expectedPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Samples/expected.psd1'
            (Import-PowerShellDataFile -Path $expectedPath).Samples | Where-Object { $null -ne $_.ExpectedCustomDetails }
        ) {
            $actual = (Get-ResultsFor -File $File)[0].Detection.Rule.detectionAction.alertTemplate.customDetails
            $actualMap = [ordered]@{}
            if ($null -ne $actual) { foreach ($k in $actual.Keys) { $actualMap[[string]$k] = [string]$actual[$k] } }
            $expectedKeys = @($ExpectedCustomDetails.Keys | Sort-Object)
            @($actualMap.Keys | Sort-Object) -join ',' | Should -Be ($expectedKeys -join ',')
            foreach ($k in $expectedKeys) { $actualMap[$k] | Should -Be ([string]$ExpectedCustomDetails[$k]) }
        }

        It '<File> should carry <ExpectedTacticCount> tactics' -ForEach @(
            $expectedPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Samples/expected.psd1'
            (Import-PowerShellDataFile -Path $expectedPath).Samples | Where-Object { $_.ExpectedTacticCount }
        ) {
            $rule = (Get-ResultsFor -File $File)[0].Detection.Rule
            @($rule.detectionAction.alertTemplate.tactics).Count | Should -Be $ExpectedTacticCount
        }
    }

    Context 'The samples are deployable' {

        It 'Should produce a schema-valid payload for every convertible sample' {
            $schema = Get-Content -LiteralPath (Join-Path (Split-Path $PSScriptRoot -Parent) 'CustomDetection.schema.json') -Raw
            $failures = [System.Collections.Generic.List[string]]::new()

            foreach ($result in $script:Results) {
                if ($result.Verdict -eq 'Blocked') { continue }
                try {
                    Test-Json -Json ($result.Detection.Rule | ConvertTo-Json -Depth 20) -Schema $schema -ErrorAction Stop | Out-Null
                } catch {
                    $failures.Add("$($result.RuleName): $($_.Exception.Message)")
                }
            }

            $failures -join "`n" | Should -BeNullOrEmpty
        }

        It 'Should preview a deployment for every convertible sample' {
            $planned = @($script:Results |
                Where-Object { $_.Verdict -ne 'Blocked' } |
                ForEach-Object Detection |
                New-XDRCustomDetection -WhatIf -AccessToken 'test-token')

            $planned.Count | Should -Be @($script:Results | Where-Object Verdict -ne 'Blocked').Count
            @($planned | Where-Object Status -ne 'WhatIf').Count | Should -Be 0
        }

        It 'Should refuse to deploy the blocked samples' {
            $planned = @($script:Results |
                Where-Object { $_.Verdict -eq 'Blocked' } |
                ForEach-Object Detection |
                New-XDRCustomDetection -WhatIf -AccessToken 'test-token' -WarningAction SilentlyContinue)
            $planned.Count | Should -Be 0
        }
    }
}

Describe 'Sample coverage of every migration scenario' {

    BeforeAll {
        $Root = Split-Path -Path $PSScriptRoot -Parent
        Import-Module -Name (Join-Path $Root 'src/SentinelToXDR.psd1') -Force
        $script:Readiness = Import-PowerShellDataFile -Path (Join-Path $Root 'src/Data/MigrationReadiness.psd1')
        $script:Kinds     = Import-PowerShellDataFile -Path (Join-Path $Root 'src/Data/SentinelRuleKinds.psd1')
        $script:Deps      = Import-PowerShellDataFile -Path (Join-Path $Root 'src/Data/QueryDependencyRules.psd1')

        # One pass over the folder; every assertion below reads from this.
        $script:Assessed = @(Test-XDRMigrationReadiness -Path (Join-Path $Root 'Samples') -WarningAction SilentlyContinue)
        $script:Seen = @($script:Assessed |
            ForEach-Object { $_.Findings } |
            Where-Object { $_.Impact -in 'Blocking', 'High', 'Medium' } |
            ForEach-Object { [string]$_.Summary } |
            Select-Object -Unique)

        # Two classifications cannot be reached by any sample in the current configuration.
        # They are listed with the condition that makes them unreachable, and a test below
        # CHECKS that condition — so the exemption expires by itself the moment the
        # condition stops holding, rather than quietly excusing a real coverage gap.
        $script:Dormant = @{
            'Custom details not migrated' =
                "only fires when 'Enrich alerts with custom details' is not Supported"
            'A MITRE tactic could not be carried' =
                'only fires for the legacy -Format XDRConverter shape, which the readiness assessment never uses'
        }
    }

    # This is the test that answers "have we captured every scenario". Adding a new
    # limitation to MigrationReadiness.psd1 without a sample that triggers it fails here,
    # which is the only way the sample folder stays a real stress test rather than a
    # snapshot of whatever was interesting the day it was written.
    It 'Should have a sample that triggers every reachable classification' {
        $expected = @($script:Readiness.Rules |
            Where-Object { $_.Impact -in 'Blocking', 'High', 'Medium' } |
            ForEach-Object { [string]$_.Summary } |
            Select-Object -Unique |
            Where-Object { -not $script:Dormant.ContainsKey($_) })

        $missing = @($expected | Where-Object { $_ -notin $script:Seen })
        $missing -join ' | ' | Should -BeNullOrEmpty -Because 'each of these needs a sample rule in ./Samples that produces it'
    }

    It 'Should still be true that the exempted classifications are unreachable' {
        # 'Custom details not migrated' is unreachable only while the capability is
        # Supported. If Microsoft withdraws it, this fails and the exemption has to go.
        $state = InModuleScope SentinelToXDR {
            Get-CustomDetectionCapabilities -Feature 'Alert enrichment' -Capability 'Enrich alerts with custom details'
        }
        $state | Should -Be 'Supported' -Because "'Custom details not migrated' is exempted on the grounds that it cannot fire"

        # The MITRE drop is legacy-shape only. Prove it still fires there, so the
        # exemption covers an untested path rather than a dead one.
        $root = Split-Path -Path $PSScriptRoot -Parent
        $legacy = Get-SentinelAnalyticsRule -Path (Join-Path $root 'Samples/02-review-multi-tactic.yaml') |
            ConvertTo-XDRCustomDetection -Format XDRConverter -As Object -Force -WarningAction SilentlyContinue
        @($legacy.Diagnostics | Where-Object {
            $_.Capability -eq 'Link multiple MITRE tactics' -and $_.Action -eq 'Dropped'
        }).Count | Should -BeGreaterThan 0 -Because 'the legacy shape still drops tactics, it is just not what the assessment converts to'
    }

    It 'Should exercise every verdict' {
        foreach ($verdict in @('Ready', 'Review', 'NeedsWork', 'Blocked')) {
            @($script:Assessed | Where-Object { $_.Verdict -eq $verdict }).Count |
                Should -BeGreaterThan 0 -Because "the folder must demonstrate a $verdict rule"
        }
    }

    It 'Should exercise every data tier' {
        foreach ($tier in @('DefenderOnly', 'SentinelOnly', 'Mixed')) {
            @($script:Assessed | Where-Object { $_.DataTier -eq $tier }).Count |
                Should -BeGreaterThan 0 -Because "the folder must demonstrate a $tier rule"
        }
    }

    It 'Should have a sample for every workspace-only query dependency' {
        # The dependency scan is the check that closed the false-green gap. Every pattern
        # in it needs a rule that trips it, or a regex can rot without anything noticing.
        $root = Split-Path -Path $PSScriptRoot -Parent
        foreach ($dependency in $script:Deps.Dependencies) {
            $hit = $false
            foreach ($file in (Get-ChildItem -Path (Join-Path $root 'Samples') -Filter '*.yaml')) {
                $query = (Get-SentinelAnalyticsRule -Path $file.FullName -WarningAction SilentlyContinue).Query
                foreach ($text in @($query)) {
                    if ($text -and [regex]::IsMatch($text, $dependency.Pattern)) { $hit = $true; break }
                }
                if ($hit) { break }
            }
            $hit | Should -BeTrue -Because "no sample query trips the '$($dependency.Name)' dependency"
        }
    }

    It 'Should keep a Hashtable-sourced custom detail map intact' {
        # Community YAML gives a Hashtable; reading it as a PSCustomObject produced one
        # garbage key and shipped it to the tenant. 863 rules in Azure-Sentinel use custom
        # details, so this is worth its own assertion rather than a verdict check.
        $root = Split-Path -Path $PSScriptRoot -Parent
        $detection = Get-SentinelAnalyticsRule -Path (Join-Path $root 'Samples/23-ready-custom-details.yaml') |
            ConvertTo-XDRCustomDetection -As Object -Force -WarningAction SilentlyContinue
        $details = $detection.Rule.detectionAction.alertTemplate.customDetails

        @($details.Keys).Count | Should -Be 2
        $details['CommandLine'] | Should -Be 'ProcessCommandLine'
        $details['Initiator']   | Should -Be 'InitiatingProcessFileName'
    }

    It 'Should skip the placeholder and the non-rule file entirely' {
        $root = Split-Path -Path $PSScriptRoot -Parent
        foreach ($file in @('24-notarule-placeholder.yaml', '17-not-a-rule.json')) {
            @(Get-SentinelAnalyticsRule -Path (Join-Path $root "Samples/$file") -WarningAction SilentlyContinue).Count |
                Should -Be 0 -Because "$file is not an analytics rule"
        }
    }
}
