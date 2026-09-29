# Proving the verdicts are right

A migration assessment is a set of claims: this rule deploys cleanly, that one cannot be
migrated at all, this one will look back four hours instead of fourteen days. Every claim is
derived from Microsoft's documented contract — which is exactly how four wrong lookback
values survived in this module for months, stated with total confidence, until someone asked
where the numbers came from.

So the assessment is checked at three levels, in increasing cost and increasing strength.

| Layer | Proves | Needs | Writes |
|---|---|---|---|
| 0. Corpus arithmetic | Every rule read produced a verdict | A content repository | No |
| 1. Schema conformance | The payload matches the documented contract | Nothing | No |
| 2. Query execution | The KQL actually runs **in your tenant** | A read-only token | No |
| 3. Round trip | The API accepts it and keeps what we sent | A dev tenant | **Yes** |

Layers 0 and 1 run offline. Layer 2 is safe against production. Layer 3 is for a tenant you
are willing to write to.

---

## Layer 0 — Corpus arithmetic (offline)

The cheapest check in this document, and the one that has found the most bugs. Read every
rule in a content repository, convert them all, and compare two integers:

```powershell
$rules = @(Get-SentinelAnalyticsRule -Path <content-repo> -Recurse -WarningAction SilentlyContinue)
$converted = @($rules | ConvertTo-XDRCustomDetection -As Object -Force `
    -WarningAction SilentlyContinue -ErrorAction SilentlyContinue)

$rules.Count -eq $converted.Count   # must be $true
```

**Every rule must produce a verdict, convertible or blocked.** If the counts differ, a rule
disappeared somewhere between the file and the report — no verdict, no diagnostic, no line
anywhere. That is the worst failure this module has, because the report looks complete and
there is nothing to notice.

It is worth stating why this is a separate layer rather than a test. The suite asserts the
same invariant, and the suite passed: 366 tests green on the day two rules were being lost.
The invariant only bites over content nobody wrote a fixture for. On the eve of 1.0.0 this
one line found both an unguarded `[int]` cast that deleted a rule mid-normalization, and a
blank ARM authoring template being read as a rule and then producing nothing — two unrelated
causes of the same missing `1`.

Run it against `Azure/Azure-Sentinel` before any release.

---

## Layer 1 — Schema conformance (offline)

Every generated payload is validated against
[`CustomDetection.schema.json`](../CustomDetection.schema.json), which mirrors
`microsoft.graph.security.detectionRule`.

```powershell
./tests/Invoke-Tests.ps1
```

This catches structural drift — a renamed property, a severity that stopped being
lower-case, a frequency that is no longer an ISO 8601 duration, a stray field the API would
reject. It runs across the bundled examples and, with `SENTINELTOXDR_CORPUS` set, across
every convertible rule in three real Content Hub solutions.

A validator that never rejects anything proves nothing, so the suite also asserts that the
schema **rejects** each mistake the converter could plausibly make: a missing
`queryCondition`, `severity: High` instead of `high`, the deprecated `1H` frequency enum in
place of `PT1H`, a resurrected `isEnabled`, an invented entity column, a tactic id
(`TA0001`) where a technique id belongs.

**What it cannot tell you:** whether the detection does anything useful. A structurally
perfect payload can still reference a table your tenant does not have.

---

## Layer 2 — Query execution (read-only, any tenant)

`Test-XDRDetectionQuery` runs each converted query through advanced hunting
(`POST /security/runHuntingQuery`) and reports what the product says.

```powershell
Test-XDRMigrationReadiness -Path './Analytic Rules' -Recurse -PassThruDetection |
    Test-XDRDetectionQuery |
    Where-Object { -not $_.QueryValid } |
    Format-Table RuleName, FailureKind, ServiceMessage
```

The question worth asking first:

```powershell
# Does anything the assessment called Ready fail for real?
Test-XDRMigrationReadiness -Path './Analytic Rules' -Recurse -PassThruDetection |
    Where-Object Verdict -eq 'Ready' |
    Test-XDRDetectionQuery |
    Where-Object { -not $_.QueryValid }
```

It creates nothing and needs only `ThreatHunting.Read.All`, so it is safe against
production. Failures are classified, because the *kind* is what makes a batch actionable —
two hundred rules failing on `UnresolvedName` is one onboarding conversation, two hundred
failing on `SyntaxError` is a converter bug:

| FailureKind | Means |
|---|---|
| `UnresolvedName` | A table or column the tenant does not have. Usually Sentinel data not onboarded to the Defender portal. |
| `WatchlistDependency` | The query calls `_GetWatchlist()`. Watchlists do not exist in Defender. |
| `AsimParserDependency` | The query calls an ASIM parser (`_Im_*`, `ASim*`). |
| `CrossWorkspaceDependency` | The query calls `workspace()`. The service says only *invalid properties*; the query says why. |
| `MissingFunction` | A saved function the workspace has and the Defender portal does not. |
| `SyntaxError` | The Defender query engine rejects the KQL. |
| `Permission` / `Throttled` / `Timeout` | Your problem, not the rule's. Re-run. |

**This closes the module's largest known blind spot.** Static analysis cannot see that
`_GetWatchlist('HighValue')` over `DeviceProcessEvents` is non-portable — it classifies as
`DefenderOnly` and reports clean. Layer 2 fails it immediately.

Cost control: advanced hunting enforces a CPU quota per 15 minutes and a 10-minute per-query
timeout. The default `-Timespan PT5M` keeps each query cheap (the service applies whichever
is shorter, the timespan or a time filter in the query) and validation only needs the query
to resolve, not to return data. `-DelayMilliseconds` paces a large batch.

---

## Layer 3 — Round trip (writes, development tenant only)

The strongest proof available: create the detection, read it back, compare what the service
stored against what we sent, delete it.

```powershell
# Dry run first. Always.
./tests/Integration/Invoke-RoundTripValidation.ps1 `
    -Path './Analytic Rules' -Recurse -First 5 `
    -ConfirmDevelopmentTenant -WhatIf

# Then for real
./tests/Integration/Invoke-RoundTripValidation.ps1 `
    -Path './Analytic Rules' -Recurse `
    -ConfirmDevelopmentTenant -ReportPath ./roundtrip.csv
```

Three questions only this can answer:

1. **Does the API accept the payload?** A rejection means our shape is wrong, and the Graph
   error body names the property. Any rejection here is a module bug.
2. **Does the service keep what we sent?** A field that returns changed or absent was
   silently ignored — worse than a rejection, because the detection looks deployed and
   behaves differently. Reported as `StoredWithDrift` with a field-by-field list.
3. **Are `Blocked` rules genuinely impossible?** With `-IncludeBlocked` they are attempted
   rather than assumed.
4. **Does the SECOND run work?** After reading the rule back, the script re-applies it over
   itself. Create and update are different requests — `PATCH` accepts a closed set of
   properties — so a module that creates perfectly can still fail to update, and a
   create-only round trip cannot see it. That is not hypothetical: it is exactly how the
   id-in-PATCH-body bug survived to the eve of 1.0.0. The first run of anything gets checked
   by hand; the second one gets trusted.

Outcomes, per rule:

| Outcome | Means |
|---|---|
| `Verified` | Created, read back identical, re-applied over itself. |
| `StoredWithDrift` | Created, but the service stored something other than what was sent. Field-by-field list. |
| `UpdateFailed` | Created and stored, but the second run (`PATCH`) failed. |
| `RefusalPredicted` | Refused, and the assessment said it would be: an API-constraint finding, or a query-dependency `NeedsWork`. The verdict holding. |
| `ReviewConfirmed` | Refused with `Unknown function` after a `Review` that said *confirm this function resolves*. The Review holding; not deployable as written. |
| `Rejected` | Refused, and nothing in the assessment predicted it. **A module bug if the verdict was `Ready`.** |
| `BlockedConfirmed` / `BlockedButAccepted` | With `-IncludeBlocked`: the API agreed with, or overruled, a `Blocked` verdict. |
| `ScriptError` | Never reached the API. Says nothing about the module; the run is void for that rule. |
| `WhatIf` | Dry run. |

Until 2026-09-16 the list here had six entries, one of which (`NotAttempted`) the script never
emitted, and it missed the two that matter most for reading a run honestly:
`RefusalPredicted` and `ScriptError`. On the same day two rules the module had graded
`NeedsWork` and `Review` for their queries were refused because **the API validates the KQL
at `POST`** (`Unknown function`, `The query contains syntax errors`) and the script filed
them under *the module believed these were convertible*. It had not. `ReviewConfirmed` and
the widened `RefusalPredicted` exist so the report never reads worse than the truth either.

### Safety

It is a script in `tests/Integration/`, not a shipped cmdlet, because writing to a tenant
should mean running a file out of the tests folder — not tab-completing the module.

- Every detection is created **disabled**. Nothing created here can fire an alert.
- Every id is prefixed `s2x-validation-` so it is obvious in the portal what these are.
- Cleanup runs in a `finally` block, so it happens on Ctrl+C and on failure. If a delete
  fails, the script says exactly which ids remain and how to remove them.
- `-ConfirmDevelopmentTenant` is mandatory: the script cannot be pointed at production by
  muscle memory.
- `-First N` exists so you start small.

---

## What the live tenant has now proven

Layers 2 and 3 have been run against a development tenant. Those runs are what found the
six undocumented constraints on `POST /security/rules/detectionRules` written up in
[API-Constraints.md](API-Constraints.md) — every one of which refuses a rule that passes
Layers 0 and 1 and runs cleanly in advanced hunting.

**A green Layer 0 and 1 have never been sufficient**, and the release before this one would
have shipped believing they were. The suite was green on the day, as it was on the day two
rules were being lost.

### Layer 3 has to compare, not just succeed

The round trip once reported *sent 2 techniques, stored 1* and it was written up as the
service silently discarding data. That was only visible because Layer 3 compares what was
**stored** against what was **sent**, rather than checking that the call returned 200 — an
acceptance test that stopped at the status code would have seen nothing.

And then the diff itself was not good enough. It counted items without naming them, so it
could prove something had changed but not what, and the wrong conclusion stood for three
weeks. When it was changed to print values, the stored form turned out to be the documented
`mitreTechnique` shape and nothing had been lost at all. **A diff that cannot be acted on is
half a diff.**

### Layer 3 also has to re-check what it already believes

Two constraints recorded in August were gone by September, and this repository kept asserting
them — grading 1,216 corpus rules as certain rejections that the service accepts. Nothing
re-ran the probes, because a constraint once measured felt like a fact.

So a fourth property belongs in this document alongside the three layers: **a recorded
constraint has an expiry date.** There is no v1.0 of this API, only `/beta`. Everything here
is true as of the date beside it in `src/Data/GraphDetectionRule.psd1`, and
`TacticConstraints.History` exists so the next person can see which claims have already
moved.

### And it has to be told the truth about its own cleanup

`Cleanup complete: nothing left behind` was printed from the status code of a `DELETE`, while
a tenant held 33 detections from previous runs. Then the first fix — read one id back and
treat any 200 as a failure — would have called every cleanup a failure, because deletion on
this API is asynchronous. Both directions are misreporting, and so was the third attempt: a
second `DELETE` answers `404`, which was written up as confirmation until the portal was
found listing all 30 rules of a run whose every second `DELETE` had answered `404`. Deletion
completes hours later and nothing callable observes it. Every script that writes to a tenant
now reports the delete as **refused** or **taken**, plus how many `GET` still serves, and
never says *clean*. The two older probes that still expected the constraints lifted on
2026-09-15 were folded into `Probe-ApiBehaviour.ps1`.

### And it has to re-check every constraint in one run

`tests/Integration/Probes/Probe-ApiBehaviour.ps1` is the re-check. One case per constraint
in `GraphDetectionRule.psd1`, each the accepted baseline rule altered in exactly one way, on
a fresh GUID, with every mapped column projected by `extend`. A refusal counts as confirming
a constraint only when the service message names *that* constraint; otherwise the case is
`VOID`. A case whose outcome differs from the data file is `CHANGED`, and a `CHANGED` row is
a data edit due the same day. It also records how many seconds each `DELETE` takes to
answer 404. Run it before trusting any date in this repository.

### Round trip over `Samples/`, 2026-09-16 (run twice; second run from a clean tenant)

36 rules assessed, 34 sent (the two `Blocked` samples skipped), 27 created. Both runs gave
the same outcomes; the second is the record.

| Outcome | Rules | Which |
|---|---:|---|
| `Verified` | 26 | every `Ready` sample (8 of 8), 9 `Review`, 9 `NeedsWork` |
| `RefusalPredicted` | 6 | samples 07, 10, 21, 30, 31 refused with the message their finding names; sample 35 (second duplicate id) with `409 Conflict` |
| `ReviewConfirmed` | 1 | sample 22, `Unknown function` |
| `StoredWithDrift` | 1 | sample 02 — see below |
| `Rejected` / `UpdateFailed` / `ScriptError` | 0 | |

`Probe-ApiBehaviour.ps1` on the same clean tenant, immediately before: 17 of 17
`AsExpected`, cleanup confirmed for all 8.

Zero `Ready` rules rejected. Every `DELETE` taken (second `DELETE` answers `404` on every id).
The portal and `GET` still listed the rules hours later; yesterday's cleared overnight.

Three things this run said that the offline assessment does not:

- **The drift on sample 02 is real and its cause is not established.** Sent under the one
  surviving tactic: `T1003` with `T1003.001`, and `T1547`. Read back: `T1003` with
  `T1003.001` only, on two of two runs. A probe sending `T1059` + `T1547` under `Execution`
  read it back missing once and intact an hour later. See
  [API-Constraints.md](API-Constraints.md); until a probe settles it, the round trip's
  named drift is the report.
- **`_GetWatchlist()` and the ASIM parser were accepted.** Samples 15, 18 and 19 deployed
  in this tenant, which has Microsoft Sentinel connected to the Defender portal, so the
  workspace functions resolve. The `NeedsWork` finding says the query *will not run*; in a
  unified tenant it may. The finding is a heuristic and says so, but the wording is stronger
  than the evidence, and `Test-XDRDetectionQuery` remains the only per-tenant answer.
- **`externaldata` was accepted too** (sample 20). Same caveat.

### And it has to send what the user would send

The sixth constraint, *a rule id must begin with a letter*, was found on 2026-09-16 during a
demo rehearsal, on the first deploy of a rule carrying its raw Sentinel GUID. It had survived
every round trip and every probe because all of them prefixed their ids, `s2x-validation-`
and `s2x-probe-`, so that the run could find and remove what it created, and the prefix
begins with a letter. Ten GUIDs in sixteen do not.

So a fifth property joins the four above: **the harness has to send the payload a user
would send.** Every field the harness rewrites for its own convenience is a field the tenant
has never checked. The round trip keeps its prefix, because cleanup depends on it, and
`Probe-ApiBehaviour.ps1` now carries a digit-leading id and a prefixed one as explicit cases.
Anything else the harness rewrites belongs on that list the day it is added.

## What is still unproven

Being explicit, since that is the point of this document:

- **The entity identifier table is incomplete.** `EntityIdentifierRequirements` in
  `src/Data/GraphDetectionRule.psd1` lists the combinations a live tenant confirmed and marks
  the rest `Untested`. An untested combination is treated as **unknown, not invalid**, and
  never grades a rule down — a verdict asserted rather than measured is the same class of
  error the 1.0.0 work removed. Rerun
  `tests/Integration/Probes/Probe-EntityCombinations.ps1` to shrink the untested set.
- **Behavioural equivalence is not tested by any layer.** That a detection deploys and its
  query runs does not prove it fires on the same events as the Sentinel rule did. Comparing
  alert output across both platforms over the same window is a fourth layer that does not
  exist.
- **Layer 3 proves acceptance, not correctness.** The API storing a value is not the API
  honouring it at run time.

When you run layers 2 and 3 against the dev tenant, the results belong in this document.
