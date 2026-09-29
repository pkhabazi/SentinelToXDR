# Sample rules

One Sentinel analytics rule per migration use case. Every gap the module detects has a rule
here that triggers it.

This folder does three jobs at once, which is why it is worth keeping honest:

- **The demo.** 37 rules in 36 files, every verdict represented, small enough to read on a slide.
- **A fixture corpus.** `tests/Samples.Tests.ps1` asserts that each file still produces the
  verdict and findings claimed below. A converter change that silently reclassifies a sample
  fails the build instead of quietly making this page wrong.
- **The payload for round-trip validation.** These are what you point at a dev tenant.

Every rule id starts `5a1e`, so they are obvious in a tenant after a validation run.

```powershell
Test-XDRMigrationReadiness -Path ./Samples | Format-Table RuleName, Verdict, DataTier

Test-XDRMigrationReadiness -Path ./Samples |
    Export-XDRMigrationReport -Path ./samples-readiness.html
```

---

## What each one demonstrates

| # | Sample | Verdict | Demonstrates |
|---|---|---|---|
| 01 | `ready-defender-only` | **Ready** | The clean migration. Native Defender tables, one tactic, entities that map fully. |
| 02 | `review-multi-tactic` | **Review** | Three tactics, one carried. The Graph model holds a collection and the service accepts exactly one entry in it. Renamed from `ready-` when that turned out to be true. |
| 03 | `review-sentinel-tier` | **Review** | Works as before, once Sentinel data is in the Defender portal. One prerequisite moves a whole solution. |
| 04 | `needswork-mixed-tier-frequency` | **NeedsWork** | **The mixed-tier trap.** A five-minute schedule survives on Sentinel data; one `join` to `DeviceInfo` caps the whole rule at hourly. |
| 05 | `needswork-nrt-downgrade` | **NeedsWork** | A near-real-time rule that joins, so it cannot stay continuous. Real detection-latency change. |
| 06 | `needswork-behaviour-dropped` | **NeedsWork** | Trigger threshold, suppression, event grouping and alerts-without-incidents, all gone at once. |
| 07 | `needswork-entity-no-equivalent` | **NeedsWork** | An entity type Defender XDR has no home for. The entity beside it still maps, but a file cannot carry an alert on its own, so the service refuses the rule too. |
| 08 | `review-entity-columns-dropped` | **Review** | Partial entity loss: the entity attaches, some columns have no target role. Not the same as losing an entity. |
| 09 | `review-lookback-shortened` | **Review** | A 14-day lookback meeting the fixed four-hour window of an hourly Defender-tier rule. |
| 10 | `review-enrichment` | **NeedsWork** | Custom details and a dynamic title carry; dynamic severity and tactics do not. |
| 11 | `blocked-fusion` | **Blocked** | A Microsoft-managed rule kind with no query. Nothing to convert. |
| 12 | `blocked-no-query` | **Blocked** | A scheduled rule with no query. |
| 13 | `review-arm-template` | **Review** | Content Hub shape: rule nested in a content template, GUID inside a `[concat()]` expression that has to be resolved for the id to survive. |
| 14 | `review-timespan-pascalcase` | **Review** | PascalCase members and serialized TimeSpan objects instead of ISO 8601. Carries no id, so one is generated. |
| 15 | `blindspot-watchlist` | **NeedsWork** | A watchlist dependency. The rule converts perfectly and the query cannot run; caught offline by the query-dependency scan. |
| 16 | `multi-rule-file` | **Ready** ×2 | Two rules in one file. A one-rule-per-file reader drops the second. |
| 17 | `not-a-rule` | *(skipped)* | A workbook. Must not be reported as a rule at all. |
| 18 | `needswork-watchlist-dependency` | **NeedsWork** | The false green: every structural check passes and `_GetWatchlist()` still cannot run. |
| 19 | `needswork-asim-parser` | **NeedsWork** | An ASIM parser is a workspace function, not an advanced hunting table. |
| 20 | `needswork-externaldata` | **NeedsWork** | `externaldata` pulls a list from a URI at query time; unsupported. |
| 21 | `needswork-cross-workspace` | **NeedsWork** | `workspace()` reaches a second workspace; a detection sees only its own tenant. |
| 22 | `needswork-saved-function` | **NeedsWork** | A workspace-saved function. The API refuses the query at POST; inline it. |
| 23 | `ready-custom-details` | **Ready** | Custom details are supported — and the Hashtable map has to survive the trip. |
| 24 | `notarule-placeholder` | *skipped* | A redirect stub. Not a detection that failed; not a detection at all. |
| 25 | `review-comment-apostrophe` | **Review** | An apostrophe in a comment must not blank the rest of the query. |
| 26 | `ready-awkward-name` | **Ready** | A display name with a `/` and a `[` prefix must survive. |
| 27 | `needswork-zero-frequency` | **NeedsWork** | A zero frequency on a scheduled rule must not become a continuous detection. |
| 28 | `ready-tactic-without-technique` | **Ready** | A tactic with no technique. Refused in August, accepted in September — the tactic must be carried, not dropped. |
| 29 | `ready-no-mitre-data` | **Ready** | No MITRE data at all. Same story: the rule converts and deploys, and nothing is invented to fill the gap. |
| 30 | `needswork-no-entity-mappings` | **NeedsWork** | No entity mappings. `entityMappings` or `impactedAssets` is mandatory, and `impactedAssets` is removed 2026-10-01. |
| 31 | `needswork-weak-account-identifier` | **NeedsWork** | An Account mapped on a name alone. A Host on a name alone is accepted; an Account is not. |
| 32 | `needswork-arm-threshold-parameter` | **NeedsWork** | A threshold that is an ARM parameter with no default, in a nested `Microsoft.Resources/deployments` template. The rule used to vanish on an `[int]` cast, straight after a warning that said everything else converts normally. |
| 33 | `review-custom-details-malformed` | **Review** | `customDetails` as a bare string. The converter used to emit `{Length: 18}` as a custom detail on a Ready rule. |
| 34 | `review-hostile-display-name` | **Review** | A name with a right-to-left override, tabs, a newline, a leading `=` and an HTML tag. Controls and overrides are stripped and reported; the report writers neutralise the rest per format. |
| 35 | `review-duplicate-id-first` / `-second` | **Ready** / **Review** | Two files, one id. The second is flagged: deploying both creates one detection and a 409. Only visible when the folder is assessed as a batch. |
| 36 | `review-no-display-name` | **Review** | An empty name. `displayName` is mandatory, so the detection is named after its id and the finding says so; it used to go out nameless, with no finding. |

Read the header comment in each file for the detail: what it triggers, and why it matters.

---

## The two worth putting on a slide

**04 — the mixed-tier trap.** Custom frequency belongs to detections that read Microsoft
Sentinel data *exclusively*. One Defender table forfeits it for the whole rule. Adding a
`join` to `DeviceInfo` for device context is a completely reasonable thing to do when you
move to the Defender portal, and it silently turns a five-minute detection into an hourly
one. Nothing in the portal explains why the option disappeared.

**15 — the query that converts and cannot run.** This rule calls `_GetWatchlist()`.
Watchlists live in the Log Analytics workspace and do not exist in Defender XDR, so the
query fails there regardless of onboarding — while every structural check passes. This was
the module's largest blind spot: it graded Review, blamed the data tier, and a live query
was the only thing that exposed it. The query-dependency scan now catches it offline and
says so. `Test-XDRDetectionQuery` still returns `WatchlistDependency` against a real tenant,
and remains the only thing that proves it per rule — the offline scan is a heuristic, and a
heuristic that stays quiet is how a false green happens.

---

## Using them to validate

```powershell
# Layer 2: do the queries actually run in this tenant? Read-only.
Test-XDRMigrationReadiness -Path ./Samples -PassThruDetection |
    Test-XDRDetectionQuery |
    Format-Table RuleName, QueryValid, FailureKind

# Layer 3: does the API accept them and keep what we sent? Writes to a dev tenant.
./tests/Integration/Invoke-RoundTripValidation.ps1 `
    -Path ./Samples -ConfirmDevelopmentTenant -WhatIf
```

See [docs/Validation.md](../docs/Validation.md).

---

## Adding one

1. Write the rule, with a header comment saying what it demonstrates and what to expect.
2. Add an entry to [`expected.psd1`](expected.psd1) with the verdict and any finding it must
   report.
3. Add a row to the table above.
4. Run `./tests/Invoke-Tests.ps1`. The suite checks that every file has an expectation and
   every expectation has a file, so a half-added sample fails.

---

## Why this folder is a stress test, not a demo

`Samples.Tests.ps1` asserts that **every actionable classification in
`src/Data/MigrationReadiness.psd1` is triggered by a sample here**, that every verdict and
every data tier is represented, and that every pattern in
`src/Data/QueryDependencyRules.psd1` is tripped by at least one query. Adding a new
limitation without a sample that produces it fails the build.

Two classifications are exempted because nothing here can reach them:

| Classification | Why it cannot fire |
|---|---|
| `Custom details not migrated` | only fires when *Enrich alerts with custom details* is not Supported; it is |
| `A MITRE tactic could not be carried` | only fires for the legacy `-Format XDRConverter` shape, which the assessment never uses. The Graph path's own tactic loss is a separate classification, `Only one MITRE tactic is carried`, and sample 02 triggers it |

The exemptions are self-checking: a test asserts each condition still holds, so an exemption
expires by itself rather than quietly excusing a real gap.

Several samples exist because a real bug got past the earlier set — 18 to 21 (the false
green), 23 (custom details corrupted into one garbage key), 24 (312 placeholders counted as
blocked rules), 25 (an apostrophe blanking a query), 26 (94 rules losing their name). Each
one is a regression test with a story attached.

32 to 36 came out of the 2026-09-16 stress test on input the converter had not seen: a rule
that disappeared between being read and being assessed, a custom detail invented from a
string's `Length` property, a name that reorders itself on screen, and two rules that would
have deployed as one. None was found by the suite, which was green throughout.

30 and 31 got past everything before them. Each converts cleanly, validates
against `CustomDetection.schema.json`, runs in advanced hunting — and is refused on
deployment by a constraint stated in no Microsoft documentation. They were found by POSTing
to a live tenant, not by the suite, which was green throughout.

28 and 29 are the other half of that lesson. They were written as `needswork-` samples for
two constraints that the service dropped three weeks later, and they are kept — inverted and
renamed — because a sample proving the module does **not** invent a rejection is worth as
much as one proving it reports a real one. See
[docs/API-Constraints.md](../docs/API-Constraints.md).
