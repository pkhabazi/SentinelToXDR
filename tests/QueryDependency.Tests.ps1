Describe 'Workspace-only query dependencies' {

    BeforeAll {
        $ModulePath = Split-Path -Path $PSScriptRoot -Parent
        $ModulePath = Join-Path -Path $ModulePath -ChildPath 'src' | Join-Path -ChildPath 'SentinelToXDR.psd1'
        Import-Module -Name $ModulePath -Force

        $script:TestRoot = Join-Path ([System.IO.Path]::GetTempPath()) "s2x-querydep-$([System.Guid]::NewGuid())"
        New-Item -ItemType Directory -Path $script:TestRoot -Force | Out-Null

        function New-RuleWithQuery {
            param([string]$Name, [string]$Kql)
            $path = Join-Path $script:TestRoot "$Name.yaml"
            $indented = ($Kql -split "`n" | ForEach-Object { "  $_" }) -join "`n"
            Set-Content -LiteralPath $path -Encoding utf8NoBOM -Value @"
id: $([System.Guid]::NewGuid())
name: Rule $Name
description: Fixture.
severity: Medium
kind: Scheduled
queryFrequency: PT1H
queryPeriod: PT1H
tactics:
  - Execution
relevantTechniques:
  - T1059
query: |
$indented
entityMappings:
  - entityType: Host
    fieldMappings:
      - identifier: HostName
        columnName: DeviceName
"@
            return $path
        }
    }

    AfterAll {
        if ($script:TestRoot -and (Test-Path $script:TestRoot)) {
            Remove-Item -Path $script:TestRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    Context 'Detection' {

        # Each of these converts perfectly and then fails on its first run in the tenant.
        # That combination is the most expensive answer this module can give, so every one
        # of them has to be caught.
        It 'Should detect <Name>' -ForEach @(
            @{ Name = 'a watchlist';        Kql = 'SigninLogs | where IPAddress in (_GetWatchlist("bad"))' }
            @{ Name = 'a watchlist alias';  Kql = 'SigninLogs | where IPAddress in (_GetWatchlistAlias("bad"))' }
            @{ Name = 'an ASIM parser';     Kql = '_Im_Dns(domain_has_any=dynamic(["evil.com"])) | take 10' }
            @{ Name = 'an ASIM table';      Kql = 'ASimDnsActivityLogs | take 10' }
            @{ Name = 'externaldata';       Kql = 'externaldata(url:string)[@"https://x/y.csv"] with(format="csv")' }
            @{ Name = 'a cross-workspace reference'; Kql = 'workspace("other").SecurityEvent | take 5' }
            @{ Name = 'a cross-cluster reference';   Kql = 'cluster("other").database("db").Events | take 5' }
        ) {
            $path = New-RuleWithQuery -Name ([System.Guid]::NewGuid().ToString('N')) -Kql $Kql
            $result = Test-XDRMigrationReadiness -Path $path -WarningAction SilentlyContinue
            ($result.Headline -join ' ') | Should -Match 'will not run'
            $result.Verdict | Should -Be 'NeedsWork'
        }

        It 'Should say which construct it found and what to do instead' {
            $path = New-RuleWithQuery -Name 'watchlist-reason' -Kql 'SigninLogs | where X in (_GetWatchlist("bad"))'
            $result = Test-XDRMigrationReadiness -Path $path -WarningAction SilentlyContinue
            $reason = ($result.Findings | Where-Object { $_.Summary -match 'will not run' }).Reason
            $reason | Should -Match 'watchlist'
            $reason | Should -Match 'datatable'          # what to do instead
            $reason | Should -Match 'Test-XDRDetectionQuery'  # what settles it for certain
        }
    }

    Context 'Not fooled by' {

        # A scanner that fires on the word 'watchlist' in a comment would be worse than no
        # scanner: nobody trusts a report that cries wolf, and then the real ones get
        # ignored too.
        It 'Should ignore a construct inside a string literal' {
            $path = New-RuleWithQuery -Name 'in-string' -Kql 'DeviceEvents | where Note == "we used _GetWatchlist(x) once"'
            $result = Test-XDRMigrationReadiness -Path $path -WarningAction SilentlyContinue
            ($result.Headline -join ' ') | Should -Not -Match 'will not run'
        }

        It 'Should ignore a construct inside a line comment' {
            $path = New-RuleWithQuery -Name 'in-comment' -Kql "DeviceEvents`n// previously _GetWatchlist('old')`n| take 5"
            $result = Test-XDRMigrationReadiness -Path $path -WarningAction SilentlyContinue
            ($result.Headline -join ' ') | Should -Not -Match 'will not run'
        }

        It 'Should leave a clean Defender query alone' {
            $path = New-RuleWithQuery -Name 'clean' -Kql 'DeviceProcessEvents | where FileName == "powershell.exe"'
            $result = Test-XDRMigrationReadiness -Path $path -WarningAction SilentlyContinue
            $result.Verdict | Should -Be 'Ready'
        }
    }

    Context 'Strings and comments hide each other' {

        # Neither can be processed first. This context exists because getting the order
        # wrong is silent: no error, no warning, just a query that reads as clean.
        It 'Should not let an apostrophe in a comment swallow the rest of the query' {
            # The real one, from the Azure-Sentinel corpus: "shorter URI's may cause noise".
            # The apostrophe opened a phantom string that blanked everything after it, which
            # hid the ASIM parser below and changed the data tier of 22 rules.
            $kql = @"
// Setting URI length threshold count, shorter URI's may cause noise
let lookback = 1d;
_Im_Dns(starttime=ago(lookback)) | take 10
"@
            $path = New-RuleWithQuery -Name 'apostrophe-comment' -Kql $kql
            $result = Test-XDRMigrationReadiness -Path $path -WarningAction SilentlyContinue
            ($result.Headline -join ' ') | Should -Match 'will not run'
        }

        It 'Should not let a URL inside a string look like a comment' {
            # The mirror image: '//' in "https://..." must not start a comment and blank
            # the tables that follow it.
            $kql = @'
let IPList = externaldata(IPAddress:string)[@"https://example.com/list.csv"] with(format="csv");
DeviceNetworkEvents | where RemoteIP in (IPList)
'@
            $path = New-RuleWithQuery -Name 'url-in-string' -Kql $kql
            $result = Test-XDRMigrationReadiness -Path $path -WarningAction SilentlyContinue
            # DeviceNetworkEvents comes AFTER the URL; if '//' had started a comment the
            # table would be invisible and the tier would fall back to SentinelOnly.
            $result.DataTier | Should -Be 'DefenderOnly'
        }

        It 'Should keep the comment markers so comment detection still works' {
            $blanked = InModuleScope SentinelToXDR {
                Remove-KqlStringLiteral -Text "DeviceEvents // don't do this`n| take 5"
            }
            $blanked | Should -Match '//'
            $blanked | Should -Not -Match 'do this'
        }

        It 'Should preserve length so downstream offsets still line up' {
            $text = "DeviceEvents // a comment with 'quote'`n| where X == `"str`" | take 5"
            $blanked = InModuleScope SentinelToXDR { param($t) Remove-KqlStringLiteral -Text $t } -ArgumentList $text
            $blanked.Length | Should -Be $text.Length
        }
    }

    Context 'Data file integrity' {

        It 'Should carry a Metadata block and at least one dependency' {
            $data = Import-PowerShellDataFile -Path (Join-Path (Split-Path $PSScriptRoot -Parent) 'src/Data/QueryDependencyRules.psd1')
            $data.Metadata.FetchedDate | Should -Not -BeNullOrEmpty
            $data.Dependencies.Count | Should -BeGreaterThan 0
        }

        It 'Should give every dependency a pattern that compiles, and a remedy in the reason' {
            $data = Import-PowerShellDataFile -Path (Join-Path (Split-Path $PSScriptRoot -Parent) 'src/Data/QueryDependencyRules.psd1')
            foreach ($dependency in $data.Dependencies) {
                { [regex]::new($dependency.Pattern) } | Should -Not -Throw -Because "$($dependency.Name) must compile"
                $dependency.Reason | Should -Match 'before deploying|inline|Rewrite|Replace|Confirm' `
                    -Because "$($dependency.Name) must tell the reader what to do, not just what is wrong"
            }
        }

        It 'Should use only severities New-ConversionDiagnostic accepts' {
            # Found the hard way: 'Information' is not in the ValidateSet ('Info'), and
            # because the same wrong value was written into both data files the
            # classification test agreed with it. Every rule using that dependency threw
            # at conversion time, and only a run over 3,671 real rules surfaced it.
            $root = Split-Path $PSScriptRoot -Parent
            $deps = Import-PowerShellDataFile -Path (Join-Path $root 'src/Data/QueryDependencyRules.psd1')
            $valid = ((Get-Command New-ConversionDiagnostic -Module SentinelToXDR -ErrorAction SilentlyContinue) ??
                (InModuleScope SentinelToXDR { Get-Command New-ConversionDiagnostic })).Parameters['Severity'].Attributes.Where{
                    $_ -is [System.Management.Automation.ValidateSetAttribute]
                }.ValidValues

            $valid | Should -Not -BeNullOrEmpty
            foreach ($dependency in $deps.Dependencies) {
                $dependency.Severity | Should -BeIn $valid -Because "$($dependency.Name) is emitted as a diagnostic"
            }
        }

        It 'Should classify every dependency severity in MigrationReadiness' {
            # An unclassified diagnostic silently defaults to Low and never reaches the
            # headline — which is exactly the silence this check exists to break.
            $root = Split-Path $PSScriptRoot -Parent
            $deps = (Import-PowerShellDataFile -Path (Join-Path $root 'src/Data/QueryDependencyRules.psd1'))
            $readiness = (Import-PowerShellDataFile -Path (Join-Path $root 'src/Data/MigrationReadiness.psd1'))
            foreach ($severity in ($deps.Dependencies.Severity | Select-Object -Unique)) {
                $rule = $readiness.Rules | Where-Object { $_.Feature -eq $deps.Feature -and $_.Severity -eq $severity }
                $rule | Should -Not -BeNullOrEmpty -Because "severity '$severity' must map to an impact"
                $rule.Impact | Should -BeIn @('Blocking', 'High', 'Medium')
            }
        }
    }
}
