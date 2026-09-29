Describe 'Packaging — the module as someone else receives it' {

    # A published version cannot be replaced or reused. If the package is wrong, the only
    # remedy is another version number, and the broken one stays on the Gallery for good.
    # These tests check the manifest as a PACKAGE rather than as a file: what the Gallery
    # will show, what Install-Module will pull in, and what Import-Module will export.

    BeforeAll {
        $script:RepoRoot     = Split-Path -Path $PSScriptRoot -Parent
        $script:ManifestPath = Join-Path $script:RepoRoot 'src/SentinelToXDR.psd1'
        $script:Manifest     = Import-PowerShellDataFile -Path $script:ManifestPath
        $script:PSData       = $script:Manifest.PrivateData.PSData
    }

    Context 'Manifest' {

        It 'Should be a valid module manifest' {
            { Test-ModuleManifest -Path $script:ManifestPath -ErrorAction Stop } | Should -Not -Throw
        }

        It 'Should carry a three-part semantic version' {
            $script:Manifest.ModuleVersion | Should -Match '^\d+\.\d+\.\d+$'
        }

        It 'Should require PowerShell 7 or later' {
            # The module uses PS7-only syntax and is tested nowhere else. Claiming 5.1 would
            # let Install-Module succeed on Windows PowerShell and fail at import.
            [version]$script:Manifest.PowerShellVersion | Should -BeGreaterOrEqual ([version]'7.0')
        }

        It 'Should declare every dependency it dot-sources at import' {
            $script:Manifest.RequiredModules | Should -Contain 'powershell-yaml'
        }

        It 'Should export functions explicitly, never by wildcard' {
            # A wildcard export leaks every private helper into the caller's session and
            # makes the public surface impossible to change without breaking someone.
            $script:Manifest.FunctionsToExport | Should -Not -Contain '*'
            $script:Manifest.CmdletsToExport   | Should -BeNullOrEmpty
            $script:Manifest.AliasesToExport   | Should -BeNullOrEmpty
            $script:Manifest.VariablesToExport | Should -BeNullOrEmpty
        }

        It 'Should export exactly the functions that exist in src/Public' {
            $public = @(Get-ChildItem -Path (Join-Path $script:RepoRoot 'src/Public') -Filter '*.ps1' -File |
                ForEach-Object { $_.BaseName })

            @($script:Manifest.FunctionsToExport) | Sort-Object | Should -Be ($public | Sort-Object)
        }
    }

    Context 'Gallery metadata' {

        It 'Should carry <Field>' -ForEach @(
            @{ Field = 'Author' }, @{ Field = 'Description' }, @{ Field = 'Copyright' }
        ) {
            $script:Manifest[$Field] | Should -Not -BeNullOrEmpty
        }

        It 'Should carry a project URI, a licence URI and release notes' {
            # These are what the Gallery page renders. Without them the package looks
            # abandoned before anyone has read a line of it.
            $script:PSData.ProjectUri   | Should -Match '^https://'
            $script:PSData.LicenseUri   | Should -Match '^https://'
            $script:PSData.ReleaseNotes | Should -Not -BeNullOrEmpty
        }

        It 'Should carry tags people would actually search for' {
            @($script:PSData.Tags).Count | Should -BeGreaterThan 3
            @($script:PSData.Tags)       | Should -Contain 'Sentinel'
            @($script:PSData.Tags)       | Should -Contain 'Defender'
            # The Gallery rejects a tag containing whitespace.
            foreach ($tag in $script:PSData.Tags) { $tag | Should -Not -Match '\s' }
        }

        It 'Should ship a LICENSE file to back the licence URI' {
            Test-Path -LiteralPath (Join-Path $script:RepoRoot 'LICENSE') | Should -BeTrue
        }
    }

    Context 'Version agreement' {

        It 'Should have a CHANGELOG entry for the version being shipped' {
            # The release workflow checks the git tag against the manifest. Nothing checked
            # the CHANGELOG, so a version could ship with no record of what changed in it.
            $changelog = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'CHANGELOG.md') -Raw
            $version   = [regex]::Escape($script:Manifest.ModuleVersion)

            $changelog | Should -Match "##\s*\[$version\]"
        }

        It 'Should have the shipping version as the first entry in the CHANGELOG' {
            $changelog = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'CHANGELOG.md')
            # An [Unreleased] section above it is allowed (CONTRIBUTING asks for one); the first
            # versioned entry is the one that has to match what ships.
            $first     = $changelog | Where-Object { $_ -match '^##\s*\[(?!Unreleased\])' } | Select-Object -First 1

            $first | Should -Match ([regex]::Escape($script:Manifest.ModuleVersion))
        }

        It 'Should date the shipping entry no earlier than the newest measurement it quotes' {
            # The 1.0.0 entry sat at 2026-08-23 while quoting numbers measured on
            # 2026-09-16. The version check above could not see that: it matches the
            # number, never the date. An entry dated before its own evidence is a doc bug
            # of the kind this release is supposed to have none of.
            $lines   = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'CHANGELOG.md')
            $start   = [array]::IndexOf($lines, ($lines | Where-Object { $_ -match '^##\s*\[(?!Unreleased\])' } | Select-Object -First 1))
            $next    = ($lines | Select-Object -Skip ($start + 1) | Where-Object { $_ -match '^##\s*\[' } | Select-Object -First 1)
            $end     = if ($next) { [array]::IndexOf($lines, $next) } else { $lines.Count }
            $entry   = $lines[$start..($end - 1)]

            $lines[$start] | Should -Match '\d{4}-\d{2}-\d{2}' -Because 'the heading carries the release date'
            $headingDate = [datetime]::ParseExact([regex]::Match($lines[$start], '\d{4}-\d{2}-\d{2}').Value, 'yyyy-MM-dd', $null)
            $headingDate | Should -BeLessOrEqual (Get-Date).Date.AddDays(1) -Because 'a release cannot be dated in the future'

            # Dates quoted in the body, excluding announced future dates (deprecations).
            $quoted = @([regex]::Matches(($entry -join "`n"), '\d{4}-\d{2}-\d{2}') |
                ForEach-Object { [datetime]::ParseExact($_.Value, 'yyyy-MM-dd', $null) } |
                Where-Object { $_ -le (Get-Date).Date })
            if ($quoted.Count -gt 0) {
                $newest = ($quoted | Measure-Object -Maximum).Maximum
                $headingDate | Should -BeGreaterOrEqual $newest -Because "the entry quotes a measurement from $($newest.ToString('yyyy-MM-dd')) and cannot predate it"
            }
        }
    }

    Context 'Every test file parses' {

        # A test file with a syntax error contributes ZERO tests and does not fail. On
        # 2026-09-15 a stray brace in ApiConstraints.Tests.ps1 took 31 tests out of the run
        # and the summary still said 'Failed: 0'. Losing coverage silently is the same
        # class of failure as losing a rule silently, which is the thing this module exists
        # to prevent - so the suite now checks itself.

        It 'Should parse <Name>' -ForEach @(
            Get-ChildItem -Path (Join-Path (Split-Path -Path $PSScriptRoot -Parent) 'tests') -Filter '*.Tests.ps1' -File -Recurse |
                ForEach-Object { @{ Name = $_.Name; FullName = $_.FullName } }
        ) {
            $errors = $null
            [System.Management.Automation.Language.Parser]::ParseFile($FullName, [ref]$null, [ref]$errors) | Out-Null
            ($errors | ForEach-Object { "line $($_.Extent.StartLineNumber): $($_.Message)" }) -join '; ' |
                Should -BeNullOrEmpty -Because 'a test file that does not parse runs none of its tests and still reports no failures'
        }
    }

    Context 'The integration script uses only the public surface' {

        # The round-trip script needs a tenant, so CI can never run it, so nothing checked
        # it at all. Its first live run failed on every rule: it called
        # Invoke-S2XRestRequest, which is Private and not exported, so nothing reached the
        # API — and -WhatIf never gets that far, so the dry run looked perfect.
        #
        # This is a static check of the same property, and it costs nothing. It also
        # enforces something worth enforcing on its own: a validation script that reaches
        # past the public cmdlets validates a code path no user takes.

        BeforeAll {
            $script:IntegrationScripts = @(
                Get-ChildItem -Path (Join-Path $script:RepoRoot 'tests/Integration') -Filter '*.ps1' -File -Recurse -ErrorAction SilentlyContinue
            )
            $script:PrivateNames = @(
                Get-ChildItem -Path (Join-Path $script:RepoRoot 'src/Private') -Filter '*.ps1' -File |
                    ForEach-Object { $_.BaseName }
            )
        }

        It 'Should find integration scripts to check' {
            $script:IntegrationScripts.Count | Should -BeGreaterThan 0
        }

        # Every script under tests/Integration, probes included. This used to name one
        # file, and Measure-Corpus.ps1 - the script that produces every number in the README -
        # reached a private function through module scope for months without anything
        # noticing. A list typed by hand is a list that stops being complete.
        It 'Should never call a Private function from <Name>' -ForEach @(
            Get-ChildItem -Path (Join-Path (Split-Path -Path $PSScriptRoot -Parent) 'tests/Integration') -Filter '*.ps1' -File -Recurse |
                ForEach-Object { @{ Name = $_.Name; FullName = $_.FullName } }
        ) {
            $path = $FullName
            Test-Path -LiteralPath $path | Should -BeTrue

            $errors = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$errors)
            $errors | Should -BeNullOrEmpty -Because 'the script has to parse before anything else matters'

            # Every command the script invokes, excluding functions it defines itself.
            $invoked = @($ast.FindAll({ $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true) |
                ForEach-Object { $_.GetCommandName() } | Where-Object { $_ } | Sort-Object -Unique)

            $selfDefined = @($ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) |
                ForEach-Object { $_.Name })

            $leaked = @($invoked | Where-Object { $_ -in $script:PrivateNames -and $_ -notin $selfDefined })

            $leaked -join ', ' | Should -BeNullOrEmpty -Because 'a private function is not exported, so the call fails before any request is made'
        }
    }

    Context 'The staged package' {

        BeforeAll {
            # Build it the way a release does, rather than testing src/ and hoping the
            # packaging step agrees.
            $script:StagingRoot = Join-Path ([System.IO.Path]::GetTempPath()) "s2x-pkg-$([System.Guid]::NewGuid())"
            $build = Join-Path $script:RepoRoot 'build.ps1'
            & $build -Task Package -OutputPath $script:StagingRoot *>&1 | Out-Null
            $script:StagedModule = Join-Path $script:StagingRoot 'SentinelToXDR'
        }

        AfterAll {
            if ($script:StagingRoot -and (Test-Path -LiteralPath $script:StagingRoot)) {
                Remove-Item -LiteralPath $script:StagingRoot -Recurse -Force -ErrorAction SilentlyContinue
            }
        }

        It 'Should build a folder named after the module' {
            # Publish-Module requires this and fails late and unhelpfully otherwise.
            Test-Path -LiteralPath $script:StagedModule | Should -BeTrue
        }

        It 'Should include <File>, which does not live under src/' -ForEach @(
            @{ File = 'LICENSE' }, @{ File = 'README.md' }, @{ File = 'CHANGELOG.md' }
        ) {
            Test-Path -LiteralPath (Join-Path $script:StagedModule $File) | Should -BeTrue
        }

        It 'Should include the data files the module cannot run without' {
            $data = @(Get-ChildItem -Path (Join-Path $script:StagedModule 'Data') -Filter '*.psd1' -File)
            $source = @(Get-ChildItem -Path (Join-Path $script:RepoRoot 'src/Data') -Filter '*.psd1' -File)

            $data.Count | Should -Be $source.Count -Because 'a missing lookup table breaks conversion at runtime, not at import'
        }

        It 'Should import in a clean session and export exactly 13 commands' {
            $manifest = Join-Path $script:StagedModule 'SentinelToXDR.psd1'
            $output = pwsh -NoProfile -Command "
                `$ErrorActionPreference = 'Stop'
                Import-Module '$manifest' -Force
                (Get-Command -Module SentinelToXDR).Count
            "
            $LASTEXITCODE | Should -Be 0
            [int]($output | Select-Object -Last 1) | Should -Be 13
        }

        It 'Should render full help for every exported command' {
            # Comment-based help that does not parse produces a cmdlet with no help at all,
            # and the first thing a new user runs is Get-Help.
            $manifest = Join-Path $script:StagedModule 'SentinelToXDR.psd1'
            $output = pwsh -NoProfile -Command "
                `$ErrorActionPreference = 'Stop'
                Import-Module '$manifest' -Force
                `$bad = foreach (`$command in Get-Command -Module SentinelToXDR) {
                    `$help = Get-Help `$command.Name -Full
                    if (-not `$help.Synopsis -or `$help.Synopsis -match '^\s*`$') { `$command.Name }
                    elseif (-not `$help.Examples.Example) { `$command.Name }
                }
                `$bad -join ','
            "
            ($output | Select-Object -Last 1) | Should -BeNullOrEmpty -Because 'every public cmdlet needs a synopsis and at least one example'
        }
    }
}
