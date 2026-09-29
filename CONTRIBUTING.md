# Contributing to SentinelToXDR

Issues and pull requests are welcome. The most useful thing you can send is a rule that the
module gets wrong, because every real bug in this project so far was found by running it
against real content, not by the test suite.

## Prerequisites

- PowerShell 7.0+
- [powershell-yaml](https://www.powershellgallery.com/packages/powershell-yaml) (`Install-Module powershell-yaml`)
- [Pester 5](https://pester.dev) (`Install-Module Pester -SkipPublisherCheck`)
- [PSScriptAnalyzer](https://github.com/PowerShell/PSScriptAnalyzer) for `./build.ps1`

## Running the tests

```powershell
./tests/Invoke-Tests.ps1     # the Pester suite
./build.ps1                  # lint, tests and package, exactly what CI runs
```

Set `SENTINELTOXDR_CORPUS` to a clone of
[Azure/Azure-Sentinel](https://github.com/Azure/Azure-Sentinel) to also run the corpus tests.
All tests must pass before a PR is merged.

## Reporting a bug

Open a [bug report](../../issues/new?template=bug_report.md) with the smallest rule that shows
the problem, the command you ran and what came back. Strip anything from your own tenant
first.

## Asking for a feature

Open a [feature request](../../issues/new?template=feature_request.md). A new migration gap
needs evidence: a Microsoft doc, a service error message, or a sample rule.

## How the project works

These rules keep the verdicts honest. A PR that breaks one will get a question, not a merge.

1. **Tests are law.** Every behaviour change ships with a Pester test.
2. **Data over code.** Anything derived from Microsoft's parity tables (MITRE mappings,
   frequency buckets, capability states, entity mappings, readiness impact) lives in
   `src/Data/*.psd1`. Keep the `Metadata` block accurate when you edit one.
3. **Every scenario has a sample.** `Samples.Tests.ps1` fails the build when a classification
   in `MigrationReadiness.psd1` has no rule in `Samples/` that triggers it.
4. **Honest warnings.** A conversion gap gets a diagnostic and a warning, never a silent
   default. A false green costs someone a detection that never fires.
5. **Style.** Approved verbs, `PascalCase`, `Join-Path` rather than hard-coded separators (the
   module runs on Windows, Linux and macOS). Public functions carry full comment-based help.

## Pull requests

1. Fork, branch from `main`, keep one logical change per PR.
2. Add or update tests, run the suite.
3. Add an entry under `[Unreleased]` in [CHANGELOG.md](CHANGELOG.md) for anything a user
   would notice.
4. Open the PR against `main` and fill in the template.
