# SentinelToXDR

[![CI](https://github.com/pkhabazi/SentinelToXDR/actions/workflows/ci.yml/badge.svg)](https://github.com/pkhabazi/SentinelToXDR/actions/workflows/ci.yml)
[![PowerShell 7+](https://img.shields.io/badge/PowerShell-7%2B-blue?logo=powershell)](https://github.com/PowerShell/PowerShell)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

A PowerShell module that reads your **Microsoft Sentinel analytics rules**, tells you which
ones can become **Microsoft Defender XDR custom detections**, converts them, and deploys them.

Point it at a folder, a Content Hub solution, or a live Sentinel workspace. Every rule comes
back with a verdict, and every compromise the conversion had to make comes back as a
diagnostic you can read, instead of a silent default you find out about in production.

---

## Why this exists

Moving detections from Sentinel into the Defender portal looks like copy and paste. Take the
KQL, take the schedule, take the tactics, fill in the form. It is not.

The data a query reads decides what the detection is allowed to do. A rule that joins one
Defender table loses its five minute schedule. A rule that calls a watchlist converts
perfectly and cannot run. And the custom detection API refuses rules for reasons that are
not written down anywhere. I found six of those by deploying to a live tenant and reading
the 400s.

Over the 5,161 analytics rules in the public
[Azure/Azure-Sentinel](https://github.com/Azure/Azure-Sentinel) repository, **3,434 (66.5%)
would be refused by the custom detection API** as they are today. They convert cleanly,
they pass the schema, they run in advanced hunting, and they still come back as a
`BadRequest`. This module tells you before you try, and names the field to change.

With Microsoft's
[Integrated Security Operations Center (ISOC)](https://techcommunity.microsoft.com/blog/microsoftthreatprotectionblog/integrated-security-operations-center-in-microsoft-defender/4559097)
in public preview since 2026-09-23, and existing Sentinel customers able to move to it from
2026-11-15, more teams will be asking what their analytics rules become in the Defender
portal. Microsoft has not published how rules migrate yet. This module will not answer that
for you either, but it answers the question underneath it: which of my rules survive the
move as a custom detection, and what do I have to change for the rest.

---

## What it does

Four jobs, each a cmdlet, or all four in one call with `Invoke-SentinelToXDRMigration`.

| Job | Cmdlets | You get |
|---|---|---|
| **Read** | `Get-SentinelAnalyticsRule` | Rules from YAML, ARM JSON, Content Hub `mainTemplate.json`, REST exports or a live workspace, as one normalized object |
| **Assess** | `Test-XDRMigrationReadiness`, `Export-XDRMigrationReport` | A verdict per rule (Ready, Review, NeedsWork, Blocked), what blocks it and what to change, as CSV, Markdown or one self-contained HTML page |
| **Convert** | `ConvertTo-XDRCustomDetection`, `Export-XDRCustomDetection` | Graph `detectionRule` YAML or JSON, ready to deploy or to review in a pull request |
| **Deploy** | `Connect-SentinelToXDR`, `Test-XDRDetectionQuery`, `New-`/`Set-`/`Get-`/`Remove-XDRCustomDetection` | Queries validated in your tenant, detections created (disabled if you want), updated or cleaned up |

What it deliberately does **not** do: rewrite your KQL. When a rule needs a watchlist
inlined or an entity mapping added, the module tells you exactly that and leaves the change
to you. A tool that silently "fixes" a detection is how you end up with a rule that deploys
green and never fires.

---

## Getting started

You need PowerShell 7.0+ (Windows, Linux or macOS) and
[powershell-yaml](https://www.powershellgallery.com/packages/powershell-yaml). The module is
published on GitHub only, not on the PowerShell Gallery.

```powershell
Install-Module -Name powershell-yaml -Scope CurrentUser
git clone https://github.com/pkhabazi/SentinelToXDR.git
cd SentinelToXDR
Import-Module ./src/SentinelToXDR.psd1
```

Prefer a zip? Every [release](https://github.com/pkhabazi/SentinelToXDR/releases) has one;
[Getting started](docs/Getting-Started.md) shows how to install it.

Then pick how you want to run it. Both run offline, with no tenant and no sign-in.

### With PowerShell

```powershell
# 1. Try it on the samples: one rule per migration scenario
Test-XDRMigrationReadiness -Path ./Samples | Group-Object Verdict -NoElement

# 2. Assess your own rules and write the report
Invoke-SentinelToXDRMigration -Path ./my-rules -Recurse -ReportPath ./readiness.html

# 3. Convert the ones that can move
Invoke-SentinelToXDRMigration -Path ./my-rules -Recurse -OutputFolder ./out
```

```
Count Name
----- ----
    2 Blocked
   15 NeedsWork
    8 Ready
   11 Review
```

The report is one self-contained HTML page (no CDN, no external font), so it opens from a
file share or a mail attachment. Nothing reaches a tenant without `-Deploy`.
**Full walkthrough, including validating and deploying:
[Run it with PowerShell](docs/Run-With-PowerShell.md).**

### With Claude Code

The repository ships a [Claude Code](https://claude.com/claude-code) skill,
[`assess-migration`](.claude/skills/assess-migration/SKILL.md), that runs the assessment and
explains the result.

1. Start Claude Code in the cloned `SentinelToXDR` folder (`claude` in a terminal, or open the
   folder in the desktop app or your IDE).
2. Ask in plain language:
   ```
   assess ./Samples
   which of the rules in ./my-rules can I move to Defender, and what blocks the rest?
   ```
3. Allow it to run `pwsh` when asked. You get `out/assessment/assessment.html` and a five line
   summary: how many rules move today, the biggest blocker and its fix, the rules in the
   2026-10-01 window, and the estate wide prerequisite.

**The module judges, the skill narrates.** Claude never decides a verdict by reading KQL; every
number comes from the tested module. **Full guide, including what is sent to the model:
[Run it with Claude Code](docs/Run-With-Claude-Code.md).**

---

## Reading the verdicts

| Verdict | Means | Do |
|---|---|---|
| **Ready** | Converts cleanly and the API will accept it. | Deploy it. |
| **Review** | Behaves the same, provided a prerequisite holds. Usually: your Sentinel data is available in the Defender portal. | Check the prerequisite once. It applies to the whole estate. |
| **NeedsWork** | Converts, but will not behave the way it did in Sentinel, or the API will refuse it as it is. | Read the reason, make the change, deploy. |
| **Blocked** | Cannot become a custom detection. | Replace it with a native Defender capability. |

```powershell
# What exactly needs a decision, and why?
Test-XDRMigrationReadiness -Path ./Samples |
    Where-Object Verdict -eq 'NeedsWork' |
    Select-Object RuleName -ExpandProperty Headline
```

Real numbers, measured 2026-09-16 over a clone of Azure/Azure-Sentinel:

| Solution | Rules | Ready | Review | NeedsWork | Blocked |
|---|---:|---:|---:|---:|---:|
| Microsoft Defender XDR | 373 | 17 | 24 | 332 | 0 |
| Windows Security Events | 71 | 0 | 46 | 25 | 0 |
| Microsoft Entra ID | 73 | 0 | 49 | 24 | 0 |
| **Whole repository** | **5,161** | **23** | **1,169** | **3,927** | **42** |

`Ready` is small, and it is worth knowing why before reading it as a verdict on the content.
3,717 of those rules read Sentinel data, and a rule that reads Sentinel data always carries
a prerequisite (the data has to be in the Defender portal), which makes it `Review` at best.
Only the 875 rules on Defender tables can reach `Ready`. Most of the rest are held back by
entity mappings: 1,889 rules map no entities at all, 1,202 carry a mapping the service
refuses, and 401 map entities that cannot raise an alert on their own.

These rules were written for Sentinel, where all of that is valid. That is the point of the
assessment, not a criticism of the content.

**The classification is data, and you can disagree with it.** It lives in
[`src/Data/MigrationReadiness.psd1`](src/Data/MigrationReadiness.psd1). If a dropped
suppression window is a Review rather than a NeedsWork in your environment, change the
impact on that one line. The scoring code knows no capability names.

---

## What the API enforces that the docs do not say

Found by deploying to a live tenant. Full detail, the exact service errors and the probes to
re-check them in [docs/API-Constraints.md](docs/API-Constraints.md).

| # | Constraint |
|---|---|
| 1 | At most **one** MITRE tactic per rule |
| 2 | Entity mappings are mandatory |
| 3 | Each entity needs a sufficient identifier combination (an Account by name alone is refused, a Host by name alone is fine) |
| 4 | At least one asset entity (device, user, mailbox) or an IP must be mapped |
| 5 | Every mapped column must be projected by the query output |
| 6 | The rule id must begin with a letter, and most GUIDs do not |

**About 2026-10-01.** On that date Microsoft removes `impactedAssets`, `isEnabled`,
`detectorId`, `schedule.period`, `alertTemplate.category`, `alertTemplate.mitreTechniques`
and `detectionAction.responseActions` from the detection rule API. 1,889 rules in the public
corpus (36.6%) can only get past constraint 2 by way of `impactedAssets`. The module emits
none of the removed properties and flags every rule in that position, so those rules need an
entity mapping before they move.

There is no v1.0 of this API, only `/beta`. Two constraints were enforced in August and gone
by September, so treat everything above as true on the day it was measured, and re-run the
probes before you trust it.

---

## Converting and deploying

When the assessment says a rule can move, the module converts it to the Graph
[`detectionRule`](https://learn.microsoft.com/graph/api/resources/security-detectionrule?view=graph-rest-beta)
format the API accepts, records every compromise as a diagnostic (frequency rounded, lookback
clamped, suppression dropped), and deploys it:

```powershell
Connect-SentinelToXDR

# Does the KQL actually run in this tenant? Read-only, safe against production.
Invoke-SentinelToXDRMigration -Path ./my-rules -Recurse -ValidateQuery -Deploy -DeployDisabled -WhatIf

# Deploy the Ready and Review rules, landed disabled so you can review them in the portal
Invoke-SentinelToXDRMigration -Path ./my-rules -Recurse -ValidateQuery -Deploy -DeployDisabled
```

What it deliberately does **not** do is rewrite your KQL. Fusion, ML, threat intelligence and
other managed rule kinds are reported as Blocked, never turned into an empty detection.

One thing trips everyone: a plain `Connect-AzAccount` token cannot validate queries or deploy
detections, because the Az PowerShell app does not carry `ThreatHunting.Read.All` or
`CustomDetection.ReadWrite.All`. `Connect-SentinelToXDR` signs in with a source that can.

Step by step, with the output format, reviewed-file deployments, cleanup, permissions and
every sign-in option: **[Run it with PowerShell](docs/Run-With-PowerShell.md)**.

---

## How the verdicts are proven

The verdicts started as claims derived from Microsoft's documented contract. That is how
four wrong lookback values survived in this module for months, and how two thirds of the
public corpus was once graded as migrating cleanly into a service that would have refused
it. The documented contract is not the contract, so the verdicts are checked at three levels
(details in [docs/Validation.md](docs/Validation.md)):

| Layer | Proves | Needs | Writes to a tenant |
|---|---|---|---|
| Schema conformance | The payload matches the documented contract | Nothing | No |
| Query execution | The KQL actually runs in your tenant | A read-only token | No |
| Round trip | The API accepts it and keeps what was sent | A dev tenant | Yes |

A query that calls `_GetWatchlist()`, an ASIM parser, a saved function, `externaldata` or
`workspace()` converts perfectly and cannot run in advanced hunting. Over the Azure-Sentinel
corpus, 150 rules were once graded deployable that could not run. The offline dependency
scan now grades those NeedsWork. It is a heuristic over text, not a KQL parser, so
`Test-XDRDetectionQuery` stays the last word on any single query.

**What is still unproven:** whether a custom detection fires on the same events the Sentinel
rule did. Acceptance by the API is not the same as behaving the same. Run both side by side
for a while before you retire the Sentinel rule, and check what automation and playbooks
were bound to it.

---

## Built to follow Microsoft's changes

Capability states, parity limits, the Defender table catalog, the NRT restrictions, the
entity mapping matrix and the rule kind list all live in [`src/Data/*.psd1`](src/Data), each
stamped with the git commit and date of the Microsoft document it was derived from. When
Microsoft moves a capability from Planned to Supported, or adds an entity column, it is a
one line data edit and the converter follows.

---

## Documentation

- **[Getting started](docs/Getting-Started.md)**: install, first assessment, and where to go next
- **[Run it with PowerShell](docs/Run-With-PowerShell.md)**: read, assess, convert, validate,
  deploy, and sign in
- **[Run it with Claude Code](docs/Run-With-Claude-Code.md)**: the assessment skill, step by step
- **[Migration-Gaps.md](docs/Migration-Gaps.md)**: what actually changes when a rule becomes a
  custom detection. Every gap, what triggers it, what it costs, what to do.
- [API-Constraints.md](docs/API-Constraints.md): the six undocumented API constraints, with
  service errors and probes
- [Validation.md](docs/Validation.md): how the verdicts are proven, and what is not
- [Sentinel-to-XDR-Migration-Guide.md](docs/Sentinel-to-XDR-Migration-Guide.md): the narrative
  walkthrough of the gaps that are not obvious
- [Samples/README.md](Samples/README.md): one rule per scenario and what each demonstrates
- [Sentinel-to-XDR-GapAnalysis.md](docs/Sentinel-to-XDR-GapAnalysis.md) and
  [Edge-Case-Implementation-Plan.md](docs/Edge-Case-Implementation-Plan.md): the field level
  mapping and how the hard cases were decided
- [CHANGELOG.md](CHANGELOG.md)

---

## Contributing

Found a rule the module gets wrong? That is the most useful issue you can open. Every real
bug here so far was found by running it over real content with a green test suite. See
[CONTRIBUTING.md](CONTRIBUTING.md), and please report security issues privately
([SECURITY.md](SECURITY.md)).

```powershell
./tests/Invoke-Tests.ps1     # the Pester suite
./build.ps1                  # lint, tests and package, exactly what CI runs
```

---

## Credits

Built on the shoulders of the community content in
[Azure/Azure-Sentinel](https://github.com/Azure/Azure-Sentinel), which is the corpus every
number in this README was measured against, and inspired by Fabian Bader's
[XDRConverter](https://github.com/f-bader/XDRConverter), which showed the conversion could be
automated in the first place.

MIT licensed. Made by [Pouyan Khabazi](https://www.linkedin.com/in/pkhabazi/).
