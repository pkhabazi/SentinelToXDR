# What actually changes when a Sentinel rule becomes a custom detection

This is the reference for every gap SentinelToXDR detects: what triggers it, what the module
does, what it costs you, and what to do about it.

The short version: **the data your query reads decides what your detection is allowed to
do.** Almost every surprise in a Sentinel-to-XDR migration traces back to that one fact.

Each gap below names the verdict it drives in `Test-XDRMigrationReadiness`
(Ready / Review / NeedsWork / Blocked). The impact classification is data, in
[`src/Data/MigrationReadiness.psd1`](../src/Data/MigrationReadiness.psd1) — disagree with a
weighting and change that line.

---

## 1. The data tier decides everything

The module classifies every query by the tables it reads:

| Classification | Meaning |
|---|---|
| `DefenderOnly` | Every table is a native Defender XDR advanced hunting table. |
| `SentinelOnly` | No table is a Defender table (the binary rule: anything not in the catalog is Sentinel-tier). |
| `Mixed` | Both. |

That classification then controls frequency and lookback:

| | Custom frequency | Configurable lookback |
|---|---|---|
| `SentinelOnly` | **Yes** | **Yes**, bounded by frequency |
| `Mixed` | No | No |
| `DefenderOnly` | No | No |

### The mixed-tier trap

**Custom frequency belongs to detections that read Microsoft Sentinel data *exclusively*.
One Defender table in the query forfeits it for the entire rule.**

This is the gap most likely to bite silently. A rule that runs every five minutes against
`SigninLogs` keeps its schedule. Add a `join` to `DeviceInfo` for device context — a
completely reasonable thing to do when you move to the Defender portal — and the same rule
is now capped at hourly. Nothing warns you in the portal; the option simply is not there.

```
SecurityEvent | join kind=inner DeviceInfo on DeviceName    ← Mixed
queryFrequency: PT5M   →   schedule.frequency: PT1H
```

The module rounds it, says so, and names the table that caused it, because the fix is
usually structural: split the Defender part into its own detection and the Sentinel part
keeps its original schedule.

**Verdict:** `NeedsWork` when the frequency actually changes. `Review` when the rule is
Sentinel-tier and only needs the data to be available in the Defender portal.

---

## 2. Frequency

| Source | Target | Notes |
|---|---|---|
| Any duration, `SentinelOnly` | Carried as-is | ISO 8601 on `schedule.frequency` |
| Any duration, `Mixed` / `DefenderOnly` | Rounded to `1H`, `3H`, `12H` or `24H` | Nearest bucket; ties round up |
| `kind: NRT`, compatible query | `0` (continuous) | |
| `kind: NRT`, incompatible query | Shortest scheduled frequency | Downgraded, with the offending construct named |
| Zero or unparseable | Shortest scheduled frequency | Never silently becomes continuous |

### Continuous (NRT) compatibility

A query runs continuously only if it references **one table**, uses supported operators, and
uses **no** `join`, `union` or `externaldata`, and **no comments**. The module validates the
query against that list rather than trusting `kind: NRT`, because a Sentinel NRT rule with a
join is legal in Sentinel and impossible as a continuous detection.

A downgrade from continuous to hourly is a real detection-latency change.
**Verdict:** `NeedsWork`.

Restrictions are data:
[`src/Data/NrtQueryRestrictions.psd1`](../src/Data/NrtQueryRestrictions.psd1).

---

## 3. Lookback

**The module never emits a lookback.** The Graph `ruleSchedule` carries a frequency and
nothing else. Lookback is reported so you know what window your detection will actually
evaluate — it is not a field the converter sets.

### Defender-tier data: fixed, not configurable

| Frequency | Lookback the product applies |
|---|---|
| Every 24 hours | 30 days |
| Every 12 hours | 48 hours |
| Every 3 hours | 12 hours |
| Hourly | 4 hours |

If your Sentinel rule looked back further than the fixed window, **the detection will see
less data**. A rule running hourly over a 14-day window becomes an hourly rule over four
hours. The module warns only when the source window genuinely exceeds the fixed one.

The lever is counter-intuitive: to look back further, run *less* often.

### Sentinel-tier data: configurable, bounded by frequency

| Frequency | Maximum lookback |
|---|---|
| More often than hourly | Under 48 hours |
| Hourly to daily | 14 days |
| Daily or less often | 30 days |

Overall supported range is 5 minutes to 30 days.

**Verdict:** `Review` when the window shortens, `Ready` when the source already fits.

> Custom detections evaluate `ingestion_time()`, not the event timestamp, so events with a
> `TimeGenerated` older than the lookback can still be evaluated. Match the time filter in
> your query to the lookback; results outside it are ignored.

Values live in
[`src/Data/FrequencyLookbackRules.psd1`](../src/Data/FrequencyLookbackRules.psd1), quoted
from the product documentation.

---

## 4. MITRE ATT&CK

| Source | Target |
|---|---|
| `tactics: [A, B, C]` | The first one, in `alertTemplate.tactics[]`. The rest are dropped and named |
| `relevantTechniques` / `techniques` | Nested under the tactic as `techniques[].technique` |
| Subtechniques (`T1078.004`) | Carried |
| A tactic with no ATT&CK equivalent | Dropped and named |
| A tactic with no technique at all | Carried with an empty `techniques` collection (accepted since 2026-09-15; refused before) |

**Multiple tactics are collapsed, and this page used to say the opposite.** The Graph model
carries a collection of tactics, each with its own techniques, and the renderer was built to
that model. The service accepts exactly one entry and refuses more — `Multiple MITRE tactics
are not supported. Specify a single tactic.` Not documented anywhere; found by POSTing a rule
to a live tenant. The module's own capability data had said so all along: `Link multiple
MITRE tactics` is `State = Planned`.

Until 2026-09-15 the service also required that entry to carry at least one technique, and
required `tactics` or `category` to be present at all, so a rule naming a tactic but no
technique had no acceptable payload and was graded `NeedsWork`. Both requirements were gone
when re-probed on fresh ids that day. The tactic is now carried with an empty `techniques`
collection, and a rule with no MITRE data at all deploys. See
[API-Constraints.md](API-Constraints.md) for the dates.

One honest limitation on top: Sentinel keeps tactics and techniques as two unrelated lists, so
nothing in the source says which technique belongs to which tactic. The module attaches the
whole technique list to the tactic it keeps, rather than inventing an association.

See [What the custom detection API actually enforces](API-Constraints.md).

Custom detections do not yet appear on the ATT&CK coverage page. That is real, but it is true
of every rule, so it never drives a verdict.

---

## 5. Entity mapping

Sentinel: an entity type plus field mappings. Graph: one typed object per entity kind, one
property per role, each holding a query column name. **The Sentinel `identifier` is what
selects the target column** — `FullName` → `nameColumn`, `Sid` → `sidColumn`.

All field mappings for one entity collapse into a single Graph entry.

Sixteen entity kinds map: accounts, hosts, ips, urls, files, processes, mailboxes,
mailMessages, mailClusters, registryValues, azureResources, cloudApplications, dns,
securityGroups, oAuthApplications, plus AWS and Google Cloud resources.

Two different losses, weighted differently:

| Loss | Example | Verdict |
|---|---|---|
| **A column has no target** — the entity still attaches, with fewer roles | `Process` / `CommandLine`, `File` / `Directory`, `RegistryValue` / `Value` | `Review` |
| **The entity type has no equivalent** — nothing attaches | `IoTDevice`, `Malware`, `SubmissionMail` | `NeedsWork` |

A column with no entity role is still in your query output and can be carried as a custom
detail instead.

`FileHash` is a special case: Sentinel pairs an algorithm column with a value column, while
Graph has typed `sha1Column` / `sha256Column` on the file entity. When the algorithm comes
from a query column rather than a literal, the module cannot know which applies, defaults to
SHA-256 and flags it.

Mapping table:
[`src/Data/GraphDetectionRule.psd1`](../src/Data/GraphDetectionRule.psd1).

---

## 6. Behaviour that has no target

These convert, but the detection stops doing something the Sentinel rule did.

| Sentinel feature | What happens | Verdict |
|---|---|---|
| `triggerThreshold` / `triggerOperator` | Dropped. Custom detections alert on **every result row**. Move the threshold into the KQL (`summarize` + `where count_ > N`). | `NeedsWork` |
| `suppressionEnabled` / `suppressionDuration` | Dropped. No post-run suppression window. | `NeedsWork` |
| `eventGroupingSettings` | Dropped. The correlation engine decides grouping. Custom detections do deduplicate identical entities/details automatically. | `NeedsWork` |
| `incidentConfiguration.createIncident: false` | Dropped. Alerts will be correlated into incidents. | `NeedsWork` |
| `incidentConfiguration.groupingConfiguration` | Dropped. | `NeedsWork` |
| `alertDetailsOverride` title/description | **Carried.** Confirm the `{{Column}}` placeholder syntax against the product. | `Review` |
| `alertDetailsOverride` severity/tactics columns | Not migrated. Dynamic alert properties beyond title and description are Planned. | `NeedsWork` |
| `customDetails` | **Carried** into `alertTemplate.customDetails`. | `Ready` |
| Automation rules / playbooks | Not migrated, and not visible in the rule. Flagged when an `incidentConfiguration` hints at downstream automation. | `Review` |
| Native XDR response actions | Nothing to map *from*; Sentinel rules have none. Configure post-migration. | — |

> These gaps were **silently skipped for community YAML** in pre-release builds. A presence
> check written as `$obj.PSObject.Properties['name']` returns nothing for a Hashtable key,
> and community YAML parses to a Hashtable. Fixed before 1.0.0, so every public release
> behaves correctly.

---

## 7. Rules that cannot migrate at all

No query means no custom detection. These produce a `Blocked` verdict and no output:

| Kind | Why | Instead |
|---|---|---|
| `Fusion` | Microsoft-managed multistage correlation, no query | Defender XDR correlates natively |
| `MLBehaviorAnalytics` | Managed model, no query | Native Defender detections |
| `ThreatIntelligence` | Server-side indicator matching | Defender TI / IoC matching |
| `MicrosoftSecurityIncidentCreation` | Only forwards another product's alerts | Those alerts arrive natively in the Defender portal |
| `Anomaly` | Tunable managed model | — |
| `HuntingQuery` | A query, but no schedule, severity or entities | Promote it to a scheduled rule first, then convert |
| Any rule with an empty query | Nothing to convert | Check whether the file is a stub |

Rule kinds are data:
[`src/Data/SentinelRuleKinds.psd1`](../src/Data/SentinelRuleKinds.psd1).

---

## 8. Identity and idempotency

The rule id is what makes a re-run safe: same id, and a second deployment updates rather than
duplicates. The module recovers it from the community `id`, an ARM resource name, or a
`[concat(parameters('workspace'),'/Microsoft.SecurityInsights/',parameters('rule-id'))]`
expression resolved against the template's parameters.

Some Content Hub templates set the id to `[newGuid()]`, generated at deploy time. There is no
stable id to recover, so the module generates one and says so. Pin it with `-Guid` if you
need the same detection id across runs. **Verdict:** `Review`.

---

## 9. What the module does not claim

Being explicit about the edges:

- **Deployment is proven, behaviour is not.** The verdicts have been checked against a live
  tenant (schema, query execution and a full create/read/update round trip), but no layer
  proves that a custom detection fires on the same events the Sentinel rule did. A `Ready`
  rule is one the API accepts and the module believes behaves the same. See
  [Validation.md](Validation.md).
- **Table classification is a heuristic**, not a KQL parser. It handles the common shapes
  (single table, union lists, joins, `let`-bound subqueries). Misclassification falls back to
  Sentinel-tier, which is the conservative direction.
- **Watchlists, ASIM parsers, saved functions and cross-workspace references are detected,
  heuristically.** A query using `_GetWatchlist()` or `_Im_ProcessCreate()` converts cleanly
  and cannot run in advanced hunting; the query-dependency scan
  (`src/Data/QueryDependencyRules.psd1`) now grades those rules NeedsWork and says which
  construct it found. Against the Azure-Sentinel corpus this took the count of rules graded
  deployable-but-unrunnable from 150 to 9, and those nine are constructs inside a string
  literal or a commented-out line, where not firing is correct.

  It remains a heuristic over text, not a KQL parser: a construct built by string
  concatenation, or reached through a `let`-bound alias, can still slip past. Only
  `Test-XDRDetectionQuery` proves a specific query runs, and it stays the last word.
- **KQL is carried verbatim.** No operator translation, no table renaming, no schema mapping
  between `SecurityEvent` and `DeviceEvents`.
- **The compare doc lags the API.** The parity documentation lists multiple MITRE tactics as
  Planned; the beta API accepts a tactics collection today. Where they disagree, the module
  follows the API and says so.

---

## Reading the verdicts

| Verdict | Means | Typical cause |
|---|---|---|
| **Ready** | Deploy it. | Defender-tier data, one tactic carrying a technique, entities that map to an identifier combination the service accepts. |
| **Review** | Behaves the same if a prerequisite holds. | Sentinel-tier data needing the Defender portal; a lookback that shortens harmlessly; an entity column with no role. |
| **NeedsWork** | Converts, behaves differently — **or the service will refuse it**. | Frequency changed, NRT downgraded, an entity or a behaviour dropped; or a missing tactic, technique or entity mapping, or an entity mapping with no sufficient identifier. |
| **Blocked** | Cannot be a custom detection. | Managed rule kind, or no query. |

A whole solution coming back `Review` is normal and good news: it usually means one
prerequisite — Sentinel data in the Defender portal — moves every rule at once.
