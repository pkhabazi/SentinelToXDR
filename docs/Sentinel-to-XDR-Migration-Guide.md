# Moving detections from Sentinel to Defender XDR: what actually happens

*A practical guide for detection engineers — and the story of what we found running it over
every public Sentinel analytics rule.*

---

## The pitch, and the problem with it

Microsoft's story for consolidating onto the Defender portal is a good one, and custom
detections are a real feature: a KQL query, a schedule, an alert template, entity mappings,
automated response actions. If you have written a Sentinel scheduled analytics rule, you
have written most of a custom detection already.

So the migration looks like copy and paste. Take the query, take the schedule, take the
tactics, fill in the form.

It is not copy and paste, and the reason is a single sentence that is not written down
anywhere obvious:

> **The data your query reads decides what your detection is allowed to do.**

Almost every surprise in a Sentinel-to-XDR migration traces back to that one fact. Not the
query language — KQL is KQL. Not the alert fields. The *tables*.

This guide walks through what changes, what it costs you, and how to find out which of your
rules are affected before you start hand-editing them.

One number to set expectations. Over the public Azure/Azure-Sentinel corpus — 5,161 rules,
measured 2026-09-16 — **3,434 (66.5%) would be refused outright by the custom detection
API**, for reasons stated in no Microsoft documentation. Not because the rules are bad:
because the API enforces requirements the Sentinel rule format has no reason to satisfy.
Most are fixed by adding one field. See
[What the custom detection API actually enforces](API-Constraints.md), and read the section
on the **2026-10-01 deadline** before you plan the work — 1,889 rules (36.6%) can migrate
today only by way of a property that is removed on that date.

---

## Four gaps that are not obvious

### 1. One Defender table can change your whole schedule

Custom detections let you set a custom frequency **only when the query reads Microsoft
Sentinel data exclusively.** One Defender advanced hunting table anywhere in the query
forfeits it for the entire rule.

That sounds like a footnote until you picture the actual migration. You have a rule that
runs every five minutes against `SigninLogs`. You are moving to the Defender portal, so you
add a `join` to `DeviceInfo` to enrich the alert with device context — a completely
reasonable thing to do, arguably the *point* of consolidating.

```kql
SigninLogs
| where ResultType == 0
| join kind=inner DeviceInfo on $left.DeviceDetail_deviceId == $right.DeviceId
```

That rule is now capped at hourly. Your five-minute detection is a sixty-minute detection.

Nothing warns you. In the portal, the option simply is not there — and an absent control is
much harder to notice than a rejected value. The fix is usually structural: split the
Defender part into its own detection so the Sentinel part keeps its schedule.

### 2. Lookback is fixed, and the lever runs backwards

For Defender-tier data, you do not choose a lookback. The product picks it from your
frequency:

| Frequency | Lookback you get |
|---|---|
| Hourly | 4 hours |
| Every 3 hours | 12 hours |
| Every 12 hours | 48 hours |
| Every 24 hours | 30 days |

Read that table twice, because the lever runs the wrong way round: **to look back further,
you must run less often.** A Sentinel rule that ran hourly over a 14-day window becomes an
hourly rule over a four-hour window. It will not fire on what it used to fire on, it will
not error, and nothing in the conversion will look wrong.

There is a second-order trap underneath it. Custom detections evaluate `ingestion_time()`,
not the event timestamp — so an event whose `TimeGenerated` is older than the lookback can
still be evaluated if it was ingested recently. If your query filters on `TimeGenerated`,
that filter and the lookback are now measuring different things.

### 3. Entity mappings are typed, and some of yours have nowhere to go

Sentinel models an entity as a shape: `{ entityType, fieldMappings[{ identifier, columnName }] }`.
Graph models it as a typed object per entity kind, one property per role:

```yaml
# Sentinel
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: AccountName
      - identifier: Sid
        columnName: AccountSid
```
```json
// Defender XDR
"entityMappings": {
  "accounts": [ { "nameColumn": "AccountName", "sidColumn": "AccountSid" } ]
}
```

Cleaner, and mostly a direct translation. But the mapping is not total, and the holes are
not where you would guess:

- `Process` carries **hash columns only**. Your `ProcessId` and `CommandLine` mappings have
  no target — they belong in custom details instead.
- `FileHash` does not exist as an entity. Graph puts hashes *on* the file entity, one
  property per algorithm — and there is no MD5 column at all.
- `IoTDevice`, `Malware` and `SubmissionMail` have no equivalent collection. The whole
  entity goes.
- Sentinel splits `RegistryKey` and `RegistryValue`; Graph has one `registryValue` entity
  carrying both.

An entity that quietly fails to map does not break the detection. It produces an alert that
an analyst cannot pivot from, which they will discover at 2am.

### 4. NRT means something narrower than you think

A Sentinel NRT rule and a continuous custom detection are not the same contract. Continuous
requires: one table, supported operators only, and **no** `join`, `union` or `externaldata`
— and no comments.

A Sentinel NRT rule with a join is perfectly legal in Sentinel and impossible as a
continuous detection. `kind: NRT` in the source file tells you what the author wanted, not
what the target can do. The only honest way to decide is to check the query itself.

---

## The one nobody expects: it converts perfectly and cannot run

Everything above is structural — you can see it in the rule. This one you cannot.

A Sentinel query can reach things that exist only in the Log Analytics workspace:

```kql
let watchlist = _GetWatchlist('HighValueAssets') | project SearchKey;
imProcessCreate
| where TargetUsername in (watchlist)
```

Watchlists (`_GetWatchlist`), ASIM parsers (`_Im_*`, `ASim*`), saved functions,
`workspace()` cross-workspace references, `externaldata` URIs. Advanced hunting has none of
them.

Every structural check passes. The tables look fine. The entities map. The schedule
converts. The report says Ready. And the detection fails on its first run in the tenant,
which is the most expensive place to find out.

This was the largest known blind spot in the module. Over the public Azure-Sentinel corpus,
**150 rules were graded deployable that could not actually run.** An offline dependency scan
now grades those NeedsWork and names what to change, taking it to 9 — and all nine are the
construct appearing inside a string literal or a commented-out line, where staying quiet is
the correct answer.

The scan is a heuristic over text, not a KQL parser. Only running the query proves the
query runs, which is why the module ships a cmdlet that does exactly that against your
tenant, read-only:

```powershell
Test-XDRMigrationReadiness -Path ./rules -Recurse -PassThruDetection |
    Where-Object Verdict -eq 'Ready' |
    Test-XDRDetectionQuery |
    Where-Object { -not $_.QueryValid }
```

That pipeline asks the only question that matters: **does anything I called Ready fail for
real?**

---

## Doing it

`SentinelToXDR` is a PowerShell 7 module that does the whole thing. Get it from GitHub:

```powershell
Install-Module -Name powershell-yaml -Scope CurrentUser
git clone https://github.com/pkhabazi/SentinelToXDR.git
Import-Module ./SentinelToXDR/src/SentinelToXDR.psd1
```

### Start with the size of the problem

Before converting anything, find out what you are dealing with. This writes an HTML report
and touches no tenant:

```powershell
Invoke-SentinelToXDRMigration -Path ./rules -Recurse -ReportPath ./readiness.html
```

Every rule comes back graded:

| Verdict | Meaning |
|---|---|
| **Ready** | Converts with no loss worth reviewing |
| **Review** | Converts, but something changed that you should look at |
| **NeedsWork** | Converts, but a real capability was lost — schedule, lookback, or a dependency that will not resolve |
| **Blocked** | Cannot become a custom detection at all |

The report says what is blocking each rule *and what to change*. That distinction is the
whole point: "this rule needs work" is not actionable, "this rule's frequency went from 5
minutes to 1 hour because of the `DeviceInfo` join on line 4" is.

### Then convert, review, and deploy turned off

```powershell
# Convert, and write a JSON artifact a colleague can review
Get-SentinelAnalyticsRule -Path ./rules -Recurse |
    ConvertTo-XDRCustomDetection -As Object -Force |
    Export-XDRCustomDetection -Path ./out -Format Both -Combine

# Sign in — Graph needs its own sign-in, see the note below
Connect-SentinelToXDR

# Prove the queries run, before anything is deployed
Test-XDRMigrationReadiness -Path ./rules -Recurse -PassThruDetection | Test-XDRDetectionQuery

# Preview the deployment
New-XDRCustomDetection -Path ./out/customDetections.json -WhatIf

# Deploy DISABLED, review in the portal, then enable deliberately
New-XDRCustomDetection -Path ./out/customDetections.json -Disabled -Force
Set-XDRCustomDetection -Id <rule-id> -Status enabled -Force
```

Deploying disabled is not excessive caution. A converted detection with a shortened lookback
or a dropped entity mapping is still a *working* detection — it just is not the one you had.
Landing them off means the review happens before the alerts do.

Re-running is safe: `-Update` patches what already exists rather than failing on the
conflict.

### One thing that trips everyone

Reading Sentinel rules over ARM works from a plain `Connect-AzAccount`. **Microsoft Graph
does not.**

The Az PowerShell client is a first-party application with a fixed set of Graph permissions,
and `ThreatHunting.Read.All` and `CustomDetection.ReadWrite.All` are not among them. No
amount of re-running `Get-AzAccessToken` will produce a token that carries them — the app
has no consent for those scopes. You get a 403 that lists the permissions it *does* have,
which sends you looking for a bug that is not there.

Use `Connect-SentinelToXDR`, which signs in with the scopes this actually needs.

---

## What we found running it over everything

The module is measured against the public
[Azure/Azure-Sentinel](https://github.com/Azure/Azure-Sentinel) content repository rather
than only against its own test suite. That decision has earned its keep — **every
significant bug found in this project was found that way, with a green suite.**

A sample of what a green test suite did not catch:

- **Custom details were corrupted on 863 rules.** The tests used rules with simple custom
  details. The corpus had nested ones.
- **94 rules lost their display name.** ARM templates that build the name with a `concat()`
  expression. No sample in the suite did that.
- **An apostrophe in a KQL comment blanked an entire query.** One character.
- **150 rules were graded deployable that could not run** — the watchlist and ASIM problem
  above.
- **On release day, a rule out of 5,000+ silently vanished — for two unrelated reasons.**
  The count did not balance: 5,162 rules read, 5,161 converted. One cause was an ARM
  template referencing a `triggerThreshold` parameter with no default, where an unguarded
  `[int]` cast threw mid-normalization and took the whole rule with it. Fixing that left the
  count still off by one — and now completely silently. The second cause was a blank ARM
  *authoring template*, the scaffold the repository ships for people to fill in: it declares
  the alert-rule type, a kind, a display name and a query, and every one of those values is
  a parameter with no default. Since "has a query" is the decisive test for *is this a
  rule*, the scaffold passed it, was read as a rule whose query was not KQL, and produced
  nothing. A rule that vanishes is worse than one that fails, because the report looks
  complete.
- **And then six constraints the documentation does not mention.** A rule can convert
  cleanly, validate against the schema, run without complaint in advanced hunting — and be
  refused on deployment, because the API accepts only one MITRE tactic, requires entity
  mappings, requires an asset entity or IP among them, and validates those mappings against
  sufficient identifier combinations and against the query's own output columns — none of
  which it publishes. 3,434 rules (66.5%) of the corpus are affected. Nothing offline could
  have found any of it: it took POSTing rules to a live tenant and reading the errors. The
  suite was green the whole time, and would have shipped the release.
- **Then two of those constraints vanished, three weeks later.** A tactic with no technique,
  and a rule with no MITRE data at all, were both refused in August and both accepted in
  September — almost certainly because `category` is removed on 2026-10-01 and a
  tactics-or-category requirement could not survive that date. For three weeks this module
  told 1,216 rules they would be rejected by a service that takes them. If you are planning
  an estate migration around constraints, re-check them: there is no v1.0 of this API, only
  `/beta`.
- **Also on release day: the update path had never sent a correct request.** `PATCH` accepts
  a closed set of properties; the module was sending the whole rule object, id included. The
  first run of a migration looked perfect. The second run — the one that updates rather than
  creates — would have failed against a real tenant. Nothing in a 366-test suite noticed,
  because nothing in it had ever inspected an HTTP request.

The lesson generalises well beyond this module: **a test suite proves the cases you thought
of.** Real content is where the cases you did not think of live — and a live tenant is where
the cases the *documentation* did not mention live. If you are migrating an estate, run the
assessment over all of it before you trust any of it, and deploy one rule for real before you
trust the assessment.

---

## What this does not tell you

Worth being explicit, because the gap matters.

Nothing here tests **behavioural equivalence** — whether the custom detection fires on the
same events the Sentinel rule fired on. The module proves the payload matches Microsoft's
documented contract, that the query runs in your tenant, and that the API accepts what was
sent and stores it unchanged. Acceptance is not equivalence.

There is also no automatic translation of the things that genuinely have no target:
incident configuration, alert grouping, suppression, dynamic alert titles, non-default
trigger thresholds. These are reported, never guessed. A converter that silently invents a
mapping is worse than one that tells you it cannot, because the first one is discovered in
production.

---

## Further reading

- **[What actually changes when a Sentinel rule becomes a custom detection](Migration-Gaps.md)**
  — the complete reference: every gap, what triggers it, what it costs, what to do.
- [How the verdicts are proven, and what is still unproven](Validation.md)
- [The sample rules](../Samples/README.md) — one rule per case, and what each demonstrates
- [Microsoft: Create custom detection rules](https://learn.microsoft.com/defender-xdr/custom-detection-rules)
- [Microsoft Graph: detectionRule resource type](https://learn.microsoft.com/graph/api/resources/security-detectionrule?view=graph-rest-beta)

The module is MIT-licensed. Source, releases and issues live at
[github.com/pkhabazi/SentinelToXDR](https://github.com/pkhabazi/SentinelToXDR).
