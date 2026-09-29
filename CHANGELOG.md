# Changelog

All notable changes to **SentinelToXDR** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-09-25

First public release, published on GitHub. The module is not on the PowerShell Gallery;
install it from source or from the release zip (see the [README](README.md#install)).

SentinelToXDR reads Microsoft Sentinel Scheduled and NRT analytics rules from files, a
content repository or a live workspace, grades how well each one migrates, converts the
convertible ones to Microsoft Defender XDR custom detections, and deploys them.

### Added

- **Read.** `Get-SentinelAnalyticsRule` reads community YAML, ARM template JSON (single
  resource or `resources[]`), Content Hub `mainTemplate.json`, REST list exports and live
  workspaces, and emits one normalized rule object whatever the source.
- **Assess.** `Test-XDRMigrationReadiness` gives every rule a verdict (Ready, Review,
  NeedsWork, Blocked) with a score and the findings behind it. `Export-XDRMigrationReport`
  writes it as CSV, Markdown or a self-contained HTML page that says what blocks each rule
  and what to change.
- **Convert.** `ConvertTo-XDRCustomDetection` and `Export-XDRCustomDetection` produce the
  Graph `detectionRule` shape by default, or the flat shape used by
  [XDRConverter](https://github.com/f-bader/XDRConverter) with `-Format XDRConverter`. Every
  compromise is recorded as a structured diagnostic.
- **Deploy.** `Connect-SentinelToXDR`, `Get-SentinelToXDRContext`, `Test-XDRDetectionQuery`
  and `New-`, `Set-`, `Get-`, `Remove-XDRCustomDetection`. All writes support `-WhatIf` and
  prompt before acting; a refused rule carries the service's own `ServiceMessage`.
- **All four in one call** with `Invoke-SentinelToXDRMigration`.
- **Offline query dependency scan.** Watchlists, ASIM parsers, saved functions,
  `externaldata` and `workspace()` are flagged as NeedsWork, because they convert cleanly
  and cannot run in advanced hunting.
- **Data driven classification.** Capability states, parity limits, the Defender table
  catalog, NRT restrictions, entity mappings and readiness impact live in
  `src/Data/*.psd1`, each stamped with the Microsoft document revision it came from.
- **Samples.** `Samples/` holds one rule per migration scenario, and a test fails the build
  if a classification has no sample that triggers it.
- **Claude Code skill.** `.claude/skills/assess-migration` runs the assessment and explains
  the result. The module decides the verdicts; the skill only narrates them.
- 13 cmdlets, PowerShell 7.0+, Windows, Linux and macOS.

### Undocumented API constraints

Deploying to a live tenant turned up six constraints on
`POST /security/rules/detectionRules` that are in neither the Graph reference nor the
product documentation. The module checks them before you deploy:

1. At most one MITRE tactic per rule.
2. Entity mappings are mandatory.
3. Each entity needs a sufficient identifier combination.
4. At least one asset entity (device, user, mailbox) or an IP must be mapped.
5. Every mapped column must be projected by the query output (checked in the tenant by
   `Test-XDRDetectionQuery`, not offline).
6. The rule id must begin with a letter.

Measured over the 5,161 rules in Azure/Azure-Sentinel on 2026-09-16, 3,434 (66.5%) would be
refused as they are. 1,889 of them (36.6%) can only pass constraint 2 through
`impactedAssets`, which Microsoft removes on 2026-10-01. Details, service errors and the
probes to re-check them are in [docs/API-Constraints.md](docs/API-Constraints.md).

### Known limitations

- The detection rule API exists only under `/beta`. Two constraints were enforced in August
  2026 and lifted in September, so every constraint above is true as of the date it was
  measured. Re-run the probes before relying on them.
- The query dependency scan is a heuristic over text, not a KQL parser.
  `Test-XDRDetectionQuery` is the last word on whether a query runs.
- Nothing proves a custom detection fires on the same events as the Sentinel rule it came
  from. Acceptance by the API is not behavioural equivalence. See
  [docs/Validation.md](docs/Validation.md).

[1.0.0]: https://github.com/pkhabazi/SentinelToXDR/releases/tag/v1.0.0
