# What the custom detection API actually enforces

Six constraints on `POST /security/rules/detectionRules` that appear in neither the
[Graph reference](https://learn.microsoft.com/graph/api/resources/security-detectionrule?view=graph-rest-beta)
nor the [product documentation](https://learn.microsoft.com/defender-xdr/custom-detection-rules).
Every one was found by deploying a rule to a live tenant and reading the 400.

They matter because a rule can convert perfectly, validate against
[`CustomDetection.schema.json`](../CustomDetection.schema.json), run cleanly through advanced
hunting — and still be refused on deployment. That is the most expensive answer this module
can give, and until 2026-08-19 it gave it silently.

**There is no v1.0 of this API.** `security/rules/detectionRules` is published only under
`/beta`, and asking Microsoft Learn for the v1.0 view returns the beta page. The banner on
every one of those pages — *subject to change, not supported in production* — is not
boilerplate here. Two of the constraints below were enforced in August and gone by
September. Re-run the probes before trusting any of this.

---

## The six constraints

| # | Constraint | Service error |
|---|---|---|
| 1 | At most **one** tactic | `Multiple MITRE tactics are not supported. Specify a single tactic.` |
| 2 | `entityMappings` is mandatory | `At least one of impactedAssets or entityMappings must be provided.` |
| 3 | Entity mappings need a **sufficient identifier combination**, per entity type | `Entity mapping for 'User' is invalid. Set non-empty column values for all fields in at least one of these combinations: …` |
| 4 | At least one **asset entity or IP** must be mapped | `At least one asset entity (Machine, User, or Mailbox) or an IP entity must be included.` |
| 5 | Entity mapping columns must be **projected by the query output** | `Entity mappings reference the following column(s) which are not projected by the query output: X..` |
| 6 | The rule **id must begin with a letter** (letters, digits, `-`, `_`, at most 100) | `Invalid rule identifier format. Rule ID must consist of letters, numbers, dashes, or underscores only, begin with a letter, and not exceed 100 characters.` |

An empty `entityMappings` object counts as absent — it produces the constraint 2 error.

### Three that are not on the list, and why

This started as eight. Three came off, and how each one came off is more useful than the
constraint would have been.

**A tactic with no technique** was refused on 2026-08-19 with `Tactic 'Execution' must
specify at least one technique.` On **2026-09-15** the same payload was accepted and stored
as `{"tactic":"Execution","techniques":[]}`.

**`tactics` or `category`** was mandatory on 2026-08-19 — `Either tactics or category must
be provided.` On **2026-09-15** a rule with neither was accepted.

Both were almost certainly retired ahead of 2026-10-01, when `category` is removed. A
requirement for *tactics or category* becomes *tactics, mandatory* on that date, which would
make every rule with no MITRE data unmigratable by any client. Dropping the requirement
first is the sane way to retire the field.

Between them, those two had been condemning **1,216 corpus rules** as certain rejections.
That is a false rejection, which is the same failure as a false green pointed the other way,
and it survived three weeks because nothing re-checked a constraint once it was recorded.
Both limits lived in `TacticConstraints` and `RequiredAlertTemplateFields` as data, so
withdrawing them was an edit to two tables. `TacticConstraints.History` keeps the dates.

**Subtechniques collapsing** was never a constraint at all. The round trip reported *sent 2
techniques, stored 1* and it was written up as the service silently discarding data. When
the drift report was changed to name values instead of counting them, the stored form turned
out to be `{technique: T1059, subTechniques: [T1059.001]}` — the documented
[`mitreTechnique`](https://learn.microsoft.com/graph/api/resources/security-mitretechnique?view=graph-rest-beta)
shape, into which the service normalises a flat list. Nothing was lost. A count-only diff
made a renderer detail look like an undocumented constraint.

Worth noting that Microsoft's own pages disagree here: the `mitreTechnique` resource type
says `technique` holds the parent and `subTechniques` holds the children, while the
[create example](https://learn.microsoft.com/graph/api/security-rulesroot-post-detectionrules?view=graph-rest-beta)
sends a subtechnique in `technique`. The API accepts both and stores the first. The module
emits the stored form, verified by POST on 2026-09-15, so a round trip shows no drift.

---

## 1 — the tactics collection is not what it looks like

`mitreTactic` is modelled as a **collection**, each entry with its own `techniques` array.
The renderer was built to that model, and the model is not what the service accepts: exactly
one tactic.

This confirms what the module's own capability data already said. `Link multiple MITRE
tactics` is `State = Planned` in
[`CustomDetectionCapabilities.psd1`](../src/Data/CustomDetectionCapabilities.psd1). The Graph
renderer overrode it on the reasoning that the beta API models the array. **It models it; it
does not accept it.** A data-over-code violation that no amount of offline testing could
have caught.

## 2 — the fallback expires on 2026-10-01

The requirement names a deprecated property as the acceptable alternative:

- `impactedAssets` — replaced by `entityMappings`, **removed 2026-10-01**

This module never emits it, so for its output `entityMappings` is a hard requirement. But the
consequence is bigger than one module's behaviour: **a Sentinel rule with no entity mappings
can migrate today only by way of a property that stops existing in a matter of weeks.** After
that date, such a rule cannot become a custom detection until someone edits the source rule.

That is a dated migration window, and it belongs in front of anyone planning an estate move.
Measured over the corpus on 2026-09-16: **1,889 rules (36.6%)**.

## 3 — entity mappings are validated per type, and the service now says how

The Graph reference lists every column on `accountEntityMapping` and marks none required.
The product documentation describes the portal's identifier picker. Neither states which
combinations the API will accept.

Until 2026-09-15 this had to be established one probe at a time. The refusal message then
changed, and now **enumerates the accepted combinations**:

> Entity mapping for 'User' is invalid. Set non-empty column values for all fields in at
> least one of these combinations: `aadUserIdColumn`; `sidColumn`; `upnColumn`;
> `nameColumn + ntDomainColumn`; `nameColumn + dnsDomainColumn`; `nameColumn + upnSuffixColumn`.

Copied verbatim into `EntityIdentifierRequirements`, per entity type:

| Entity | Sufficient combinations |
|---|---|
| **User** (`accounts`) | `aadUserIdColumn` · `sidColumn` · `upnColumn` · `nameColumn + ntDomainColumn` · `nameColumn + dnsDomainColumn` · `nameColumn + upnSuffixColumn` |
| **Machine** (`hosts`) | `deviceIdColumn` · `nameColumn` · `nameColumn + ntDomainColumn` · `nameColumn + dnsDomainColumn` · `netBiosNameColumn + ntDomainColumn` · `netBiosNameColumn + dnsDomainColumn` |
| **File** (`files`) | `sha1Column` · `sha256Column` · `nameColumn + sha1Column` · `nameColumn + sha256Column` |
| **MailMessage** (`mailMessages`) | `networkMessageIdColumn + recipientColumn + senderColumn + subjectColumn` — all four |
| **RegistryValue** (`registryValues`) | `keyColumn + valueNameColumn` |
| `ips` · `urls` · `mailboxes` | a single address column is accepted; the full list is not stated |

**Sufficiency is a property of column SETS, not of single columns.** An account on a name
alone is refused; a name plus a domain is accepted, though the domain alone is not. A flat
list of "strong" columns cannot express that, which is why the table holds combinations.

Two things this corrected in the earlier, probed table — both of which had the module
**under**-reporting: `nameColumn + dnsDomainColumn` and `nameColumn + upnSuffixColumn` are
sufficient for accounts, and a host on `netBiosNameColumn` alone is refused.

Where the service has enumerated the list, a mapping outside it is **known** to be refused.
Where it has not, an untested combination stays **unknown** and produces no finding. Grading
a rule down on an unprobed combination would be the same class of error this release removes.

This is the constraint with the widest blast radius, because the converter maps Sentinel
identifiers to Graph columns **one at a time**, with no notion of a combination being
sufficient.

**A known limitation, not fixed in 1.0.0.** Sentinel splits a registry key and its value
across two entity types (`RegistryKey`, `RegistryValue`), and a file name and its hash across
`File` and `FileHash`. Graph needs each pair in one entry. The converter emits two, so a
correctly-mapped Sentinel rule is refused. Merging them would rescue at most **14 of 5,161**
corpus rules (`PairMergeRescueUpperBound` in the `Measure-Corpus.ps1` summary, 2026-09-16:
rules refused *only* on weak identifiers, every one of them on a split pair whose partner is
also mapped), which is why it waits. An earlier ad-hoc count said 19; this one is the
reproducible one.

## 4 — some entities cannot carry an alert on their own

A rule mapping only a file, a URL, a registry value or a cloud application is refused however
well-formed those mappings are. At least one of `hosts`, `accounts`, `mailboxes` or `ips`
has to be present. **401 corpus rules (7.8%)**.

This also invalidated part of an earlier probe: a lone `urls` mapping could never have been
accepted, so that case said nothing about URL identifiers.

## 5 — the columns have to exist in the query output

`Entity mappings reference the following column(s) which are not projected by the query
output: Dvc..` — the mapping is checked against the query's actual output schema. A
`summarize` that drops the column an entity maps is enough to fail it.

**The module does not check this offline, deliberately.** Doing so means resolving the output
schema of arbitrary KQL through `project`, `summarize`, `extend`, `join` and workspace
functions — a feature, not a constraint check, and one whose wrong answers would grade rules
down on an inference. [`Test-XDRDetectionQuery`](../README.md) runs the query against the
tenant and answers it definitively.

It is worth knowing how this one bites during *authoring*: two samples in this repository
acquired entity mappings on `Dvc` and `Computer` while being made deployable, and both
queries had already dropped those columns in a `summarize`. The API caught what review did
not.

---

## What it costs, measured

`tests/Integration/Measure-Corpus.ps1` over the public
[Azure/Azure-Sentinel](https://github.com/Azure/Azure-Sentinel) corpus, **5,161 rules**,
on **2026-09-16**. Counted from the diagnostics the converter actually raised, so this is
what would really have been sent.

| Constraint | Rules | | Refused? |
|---|---:|---:|---|
| `EntityMappingsMissing` | 1,889 | 36.6% | yes |
| `EntityIdentifierWeak` | 1,202 | 23.3% | yes |
| `AssetEntityMissing` | 401 | 7.8% | yes |
| `TacticsTruncated` | 1,243 | 24.1% | no — deploys, loses a tactic |
| **Would be refused by the service** | **3,434** | **66.5%** | |
| Inside the 2026-10-01 window | 1,889 | 36.6% | |

**66.5% is a lower bound.** Constraint 5 is not counted at all, because the module does not
check it offline, and every untested identifier combination stays silent.

And the resulting verdicts over the same 5,161 rules:

| Verdict | Rules | |
|---|---:|---:|
| Ready | 23 | 0.4% |
| Review | 1,169 | 22.7% |
| NeedsWork | 3,927 | 76.1% |
| Blocked | 42 | 0.8% |

`Ready` reads worse than it is: 3,717 of these rules are Sentinel-tier and can never be
`Ready`, because a tenant prerequisite is a `Review` by definition. `Ready` is reachable only
by the 875 Defender-tier rules, and 23 of them reach it; a 24th is held at `Review` only
because another rule in the repository carries the same id.

Withdrawing the two lifted constraints moved only **44 rules** between verdicts, against
1,216 that lost a finding. Almost all of them fail on something else as well — usually no
entity mappings. That is worth stating plainly: correcting a false rejection mattered for
honesty, not for the headline.

---

## A technique can go missing on read-back, and the cause is not established

Observed 2026-09-16. Two things were seen and they do not agree:

| Run | Sent under one tactic | Read back |
|---|---|---|
| round trip, sample 02, 10:35 | `T1003` + `T1003.001`, `T1547` (under `CredentialAccess`) | `T1003` + `T1003.001` only |
| round trip, sample 02, second clean run | same | `T1003` + `T1003.001` only |
| probe, first run | `T1059`, `T1547` (under `Execution`) | `T1059` only |
| probe, clean run an hour later | same | **both** |
| probe, both runs | `T1059`, `T1047` (both Execution) | both |

The first three rows read like the service discarding a technique that does not belong to
the tactic. The fourth row contradicts it on the same payload. The read path lags the write
path by hours (see deleting, below), so an immediate read-back may not be the stored state;
or the behaviour depends on something not varied here (a subtechnique present alongside).
**Not established, and not modelled.** What is certain: the round trip names the value that
differs (`StoredWithDrift`), a multi-tactic rule is where it shows up, and the
`TacticsTruncated` remedy warns that techniques of the dropped tactics may not survive.
`TechniqueShape.ForeignTechniquesObserved` records the date; re-run
`Probe-ApiBehaviour.ps1` and read the two `stored:` lines before believing either version.

## 6 — the id must begin with a letter, and most GUIDs do not

Found 2026-09-16 on the **first** deploy of a rule carrying its raw Sentinel GUID, during a
demo rehearsal. Ten GUIDs in sixteen begin with a digit, so most Sentinel rule ids are
refused as-is. Probed the same day: `5a1e…` refused, `a5a1…` accepted, `r-5a1e…` accepted,
101 characters refused, a `.` refused.

It had never been seen because every live run before it prefixed its ids, `s2x-validation-`
and `s2x-probe-`, so that the run could find and remove what it created. The prefix begins
with a letter. A validation harness that never sends the payload a user would send has a
blind spot exactly the size of the difference, and this was it. The round trip keeps its
prefix, because cleanup depends on it; `Probe-ApiBehaviour.ps1` now carries both cases.

The converter keeps an acceptable id unchanged so a re-run maps to the same detection, and
otherwise prefixes it with `r-` and replaces disallowed characters, deterministically,
reporting the mapping as an Info finding (`RuleIdPrefixed`). The policy is data:
`RuleIdPolicy` in `GraphDetectionRule.psd1`.

## The query is validated at POST

Observed 2026-09-16, round trip over `Samples/`. Two rules were refused with `400
BadRequest` on their KQL rather than on any property of the rule:

| Sample | Query | Service message |
|---|---|---|
| 21 `needswork-cross-workspace` | `join (workspace('other-soc').SecurityEvent ...)` | `The query contains syntax errors: The request had some invalid properties.` |
| 22 `needswork-saved-function` | `_MyOrgDeviceBaseline()` | `The query has a semantic error: Unknown function: '_MyOrgDeviceBaseline'. Fix semantic errors in your query.` |

So the deploy path runs the same resolution `Test-XDRDetectionQuery` runs, and a query the
tenant cannot resolve is refused at creation, not at first run. Two consequences. A
query-dependency `NeedsWork` (watchlist, ASIM parser, `externaldata`, `workspace()`) is a
predicted refusal, and the round trip now files it as one. And the saved-function `Review`
is settled by the API: the module said *confirm it resolves*, the service said it does not.
That is not a constraint on the rule shape and the module does not check it offline; it is
recorded here because the round-trip classifier was misreading it, and because the message
wording is what `Probe-ApiBehaviour.ps1` matches on.

## Deleting takes hours, and nothing you can call confirms it

`DELETE` returns `2xx`. A second `DELETE` on the same id returns `404`. `GET` by that id
returns `200` with the full rule, `DELETE` by its `detectorId` returns `404`, the list
endpoint returns it, and **the portal shows it**. Measured 2026-09-16 on 30 rules, some
more than two hours after their delete; the day before, 33 such rules were gone the next
morning.

So the service takes the delete at once and completes it on a scale of hours, and the read
path, portal included, serves the rule until then. Three wrong reports came out of this
before the right one:

- *Cleanup complete: nothing left behind*, from the `DELETE` status code (until 2026-09-15).
- A 90-second `GET` poll for 404, which reported every cleanup as unconfirmed, because 404
  never comes inside the window (2026-09-15).
- *Confirmed by a second `DELETE`*, which is true of the request and false of the tenant:
  the portal still lists every rule (2026-09-16, for a few hours).

What the scripts say now: the `DELETE` was **refused**, or the delete was **taken** (second
`DELETE` answers `404`), and how many the read path still serves. They never say *clean*.
If you need the portal clean before the service gets there, delete the `s2x-*` rules in the
portal, which takes effect immediately.

---

## Reproducing it

The probe scripts are deliberately minimal: each rule differs from the next in exactly one
way, so every 400 names one cause rather than a combination. Everything is created
**disabled**, prefixed, and cleaned up in a `finally` block.

**A probe has to be valid in every respect except the one under test**, and this took three
attempts to get right:

- Round 1: probes A and D were *too* minimal, failed on the tactics and entityMappings
  requirements before reaching the question they were asking, and looked like evidence
  against the constraints they were testing.
- Round 3: four of thirteen results were worthless. The query was `DeviceProcessEvents | take
  1`, which projects no `AccountUpnSuffix`, `RemoteIP`, `RecipientEmailAddress` or `Url`, so
  those cases failed on constraint 5. A fifth, a lone `urls` mapping, failed on constraint 4.
  Reading any of them as identifier failures would have put wrong entries in the data file.
- Round 4 removes both confounds by construction: every column is synthesised with `extend`
  so it is always projected, and every case carries a confirmed-good `hosts` mapping so the
  asset requirement is always satisfied.

And one more that is easy to miss: **re-using an id that already exists in the tenant
invalidates the test.** The 2026-09-15 evidence that the tactics requirements had gone was
initially unusable for that reason, and had to be re-established on fresh GUIDs.

First full run on 2026-09-16: 15 of 15 cases `AsExpected`, none `CHANGED`, none `VOID` — after
a first attempt in which the baseline query itself was refused (a backslash in a single-quoted
KQL string) and the baseline case correctly voided the run. The flat technique list was stored
as `{"technique":"T1059","subTechniques":["T1059.001"]}`, confirming the shape. Every created
rule accepted its `DELETE` and was still readable 90 seconds later.

Since 2026-09-16 all of that is one script, `tests/Integration/Probes/Probe-ApiBehaviour.ps1`:
one case per constraint on this page, each the accepted baseline altered in one way, fresh
GUIDs, `extend`-projected columns, and a refusal counted only when the message names the
constraint under test (`VOID` otherwise, `CHANGED` when the service disagrees with the data
file). `Probe-EntityCombinations.ps1` remains for the identifier table. The two earlier
probes, which still encoded the withdrawn constraints as expected behaviour, were removed.

### Provenance, per constraint

Every "the service will refuse this" finding the module can raise, and when the service was
last seen doing it. Anything here older than the date at the top of this page is due a
re-probe; `Probe-ApiBehaviour.ps1` carries the same dates as its `LastObserved` column.

| Finding | Data | First seen | Last confirmed | How |
|---|---|---|---|---|
| `TacticsTruncated` (Medium: deploys, loses tactics) | `TacticConstraints.MaxTactics` | 2026-08-19 | 2026-09-16 | `Probe-ApiBehaviour.ps1` |
| `EntityMappingsMissing` | `RequiredAlertTemplateFields` | 2026-08-19 | 2026-09-16 | round trip, sample 30 |
| `EntityIdentifierWeak` | `EntityIdentifierRequirements` | 2026-08-24 | 2026-09-16 | round trip, samples 10 and 31 |
| `AssetEntityMissing` | `RequiredEntityKinds` | 2026-08-24 | 2026-09-16 | round trip, sample 07 |
| *(withdrawn)* `TacticsMissing`, `TechniqueMissing` | `TacticConstraints.History` | 2026-08-19 | still gone 2026-09-16 | `Probe-ApiBehaviour.ps1` |
| `RuleIdPrefixed` (Info: id rewritten, deploys) | `RuleIdPolicy` | 2026-09-16 | 2026-09-16 | demo rehearsal; `Probe-ApiBehaviour.ps1` |
| *(not checked offline)* columns must be projected | — | 2026-08-24 | 2026-09-16 | `Probe-ApiBehaviour.ps1` |
| *(not checked offline)* KQL validated at POST | — | 2026-09-16 | 2026-09-16 | round trip, samples 21 and 22; `Probe-ApiBehaviour.ps1` |
| *(not established)* a technique missing on read-back | `TechniqueShape.ForeignTechniquesObserved` | 2026-09-16 | inconsistent 2026-09-16 | `Probe-ApiBehaviour.ps1`; round trip, sample 02 |

Verdict-bearing data that rests on **documentation rather than observation**, and says so:
`CustomDetectionCapabilities.psd1` (Microsoft's parity table, `ms.date` 2026-05-19),
`NrtQueryRestrictions.psd1` (three operators from the product doc plus ten conservative
additions marked `Authoritative = $false`), `QueryDependencyRules.psd1` (heuristics, proven
per rule only by `Test-XDRDetectionQuery`), and the entity-column and Sentinel-only tactic
maps in `GraphDetectionRule.psd1`. None of these claims the service *refuses* anything.

---

## What this means for the module

The verdict model gained a class it did not have: **structurally convertible, but the service
will refuse it.**

Not `Blocked` — nothing here is impossible, and in most cases one added field fixes it. The
right answer is `NeedsWork` carrying the specific instruction: *this rule needs an entity
mapping*, or *this rule's Account mapping needs a SID, UPN or Entra object ID column, not
just a name*.

That is the module's stated purpose applied to a gap nobody had documented — not "this rule
needs work", but "add this field and it will deploy". It is worth more than the conversion
itself, and it is the reason 1.0.0 waited.

The other half of that principle is the part this document exists to record: **a constraint
that stops being true has to come out as fast as it went in.** Two of them did, and the
module was wrong about 1,216 rules until it re-checked.

## Related

- [What actually changes when a Sentinel rule becomes a custom detection](Migration-Gaps.md)
- [How the verdicts are proven, and what is still unproven](Validation.md)
- [`GraphDetectionRule.psd1`](../src/Data/GraphDetectionRule.psd1) — the constraints as data,
  with provenance and history, so lifting one is a data edit rather than an archaeology
  exercise
