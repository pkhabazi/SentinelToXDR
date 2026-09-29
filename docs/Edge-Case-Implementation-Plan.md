# Edge-Case Implementation Plan — Sentinel analytics rules → Defender XDR custom detections

Status: **Implemented.** Stages 0-6 shipped; this document is kept as the record of the
decisions and why they were made, not as a to-do list. Current behaviour is described in
[Migration-Gaps.md](Migration-Gaps.md); the data files are the source of truth.
Source of truth for capability states: [Feature comparison doc](../Feature%20comparison-%20Microsoft%20Sentinel%20analytics%20rules%20and%20Microsoft%20Defender%20custom%20detections.md)
(`git_commit_id: 5c6b247409b0a426e2a24485684a6bcd0a14cf05`, `ms.date: 2026-05-19`).

This plan covers the conversion edge cases that cannot be mapped 1:1, why they're hard,
and the staged order in which we implement them. It is deliberately built so that as
Microsoft closes the parity gaps, we flip a data entry rather than rewrite logic.

---

## Locked decisions (from review on 2026-06-04)

1. **Frequency/lookback target = the new flexible model.** We extend the output schema to
   emit custom frequency + explicit lookback (period), not just the legacy `0/1H/3H/12H/24H`
   enum. We confirm downstream (XDRConverter / Graph custom-detection API) accepts it.
2. **Diagnostics = structured object + report file.** Every conversion returns a structured
   `Diagnostics` collection attached to the result, and can optionally write a companion
   `<rule>.report.json` + `<rule>.report.md`. `Write-Warning` still fires for back-compat,
   but is emitted *from* the structured records.
3. **Table classification is binary.** We maintain the full catalog of Defender XDR tables.
   A table in that catalog is Defender; **every other table is a Sentinel-tier table.**
   There is no "unknown" bucket.
4. **Build for change.** A data-driven capability matrix mirrors the compare doc row-for-row;
   converter logic reads it. Flipping `Planned → Supported` is a data edit, not a code change.

---

## Core architecture (foundations everything hangs off)

### A. Capability Matrix — `src/Data/CustomDetectionCapabilities.psd1`

A PowerShell data file mirroring the compare table row-for-row. Each entry:

```
@{
    Feature      = 'Rule lookback'
    Capability   = 'Lookback support'
    State        = 'PublicPreview'   # Supported | NotSupported | Planned | PublicPreview
    DocAnchor    = '#rule-lookback'
    Handler      = 'Resolve-Lookback'  # which converter routine acts on it
    Notes        = 'Parity with analytics rules on Sentinel data.'
}
```

Stamped with the doc `git_commit_id` / `ms.date` so drift from the live doc is detectable.
The converter asks the matrix "what is the state of capability X?" and decides
map / drop / warn accordingly. When MS ships parity, edit the `State` (and wire a handler
if newly supported) — core logic is untouched.

### B. Structured Diagnostic record — `src/Private/New-ConversionDiagnostic.ps1`

Each conversion returns the YAML **plus** a `Diagnostics` collection. One record per decision:

```
Feature       # e.g. 'Rule frequency'
Capability    # e.g. 'Flexible frequency'
Severity      # Info | Warning | Blocking
Action        # Mapped | Rounded | Dropped | Unsupported | RequiresReview
SourceValue   # what Sentinel had
TargetValue   # what XDR got (or $null)
Reason        # human-readable explanation
DocReference  # link/anchor into the compare doc
```

`Write-Warning` is generated *from* these records (back-compat). The collection is attached
to the result object and feeds the report writer (Stage 0) and batch summary (Stage 6).

### C. Table classification — `src/Data/DefenderXdrTables.psd1` + `src/Private/Get-QueryTableClassification.ps1`

- `DefenderXdrTables.psd1`: maintained catalog of Defender XDR tables
  (`Device*`, `Email*`, `Identity*`, `Cloud*`, `Alert*`, `Url*`, etc.).
- `Get-QueryTableClassification`: extract referenced tables from the KQL, then:
  - in catalog → Defender; **not in catalog → Sentinel** (binary, per locked decision #3).
  - Result: `SentinelOnly` | `DefenderOnly` | `Mixed`.
- This classification is the input to the frequency/lookback and NRT logic.

---

## Frequency & lookback decision table (Stage 2 target behavior)

| Classification | Frequency | Lookback |
| --- | --- | --- |
| `SentinelOnly` | Flexible/custom — carry source `queryFrequency`, clamp to parity limits | Carry source `queryPeriod`; parity limits: ≤ 14d when freq ≤ 1h, ≤ 48h when freq > 1h |
| `DefenderOnly` | Constrained to supported **default** set; round source freq + diagnose | Default lookback matched to chosen default frequency |
| `Mixed` | Treated as Defender (constrained default) — Defender freq/lookback wins | Default lookback matched (same as Defender) |

Every rounding/clamping/constraint event emits a Diagnostic (`Action = Rounded` or
`Constrained`, with `SourceValue` / `TargetValue`).

---

## Stages (each independently shippable; review between stages)

### Stage 0 — Foundations *(no behavior change)*
- Capability matrix data file + loader.
- `New-ConversionDiagnostic` + Diagnostic record model.
- Refactor the existing `Write-Warning` sites (~13: GUID, KQL tables, frequency
  rounded/unparseable/missing, multi-tactic/sentinel-only/unknown/no-tactics, alert title,
  trigger threshold, unknown/no-equivalent entity) in
  [ConvertFrom-SentinelToCustomDetection.ps1](../src/Private/ConvertFrom-SentinelToCustomDetection.ps1)
  to emit through it; attach `Diagnostics` to the result.
- Opt-in companion report writer (`<rule>.report.json` + `.md`).

### Stage 1 — KQL table classification
- `DefenderXdrTables.psd1` catalog + `Get-QueryTableClassification`.
- Replace the universal "may reference Sentinel tables" warning (currently
  [line 180](../src/Private/ConvertFrom-SentinelToCustomDetection.ps1#L180)) with a precise
  classification diagnostic. Unlocks Stages 2–3.

### Stage 2 — Frequency & lookback *(the keystone gap)*
- Extend `CustomDetection.schema.json` with flexible frequency + lookback/period fields.
- Implement the decision table above, driven by Stage 1 classification.
- Replace the always-round logic
  ([lines 82–104](../src/Private/ConvertFrom-SentinelToCustomDetection.ps1#L82-L104)).
- Parse and carry `queryPeriod` (currently dropped); clamp to parity limits + diagnose.

> **Stage 2 status — IMPLEMENTED.** The converter now branches on the Stage 1
> classification (computed once, reused). SentinelOnly rules carry a FLEXIBLE
> frequency + lookback; DefenderOnly/Mixed rules keep the legacy rounded enum with a
> default lookback (custom lookback dropped + diagnosed). NRT stays `0`.
>
> - **Representation:** flexible frequency + lookback use **ISO 8601 duration strings**
>   (`PT45M`, `PT6H`, `P14D`) — chosen for unambiguous round-tripping over shorthand.
> - **Output field names (ASSUMPTIONS — confirm against the real Graph custom-detection
>   API / XDRConverter):** `frequency` (enum for constrained, ISO 8601 for flexible) and
>   the new `lookbackPeriod` (ISO 8601 / `0`). The lookback field name may instead be
>   `period` or `lookback` downstream; if so, change the key in
>   `ConvertFrom-SentinelToCustomDetection.ps1` (`$yamlObj`/`$defaultSortOrder`) and in
>   `CustomDetection.schema.json` together.
> - **Tunables** (parity limits 48h / 14d / 1h threshold and the
>   default-lookback-per-frequency map) live in `src/Data/FrequencyLookbackRules.psd1` —
>   a data edit, not a code change, when Microsoft shifts the parity limits.
> - **Constrained path is genuinely data-driven.** `DefaultLookbackPerFrequency` is the
>   single source of truth for the constrained (DefenderOnly/Mixed) path: its non-`0` keys
>   define the scheduled rounding buckets (label → hours via the leading number), and its
>   values define the per-bucket default lookback. `ConvertTo-XdrFrequency` derives the
>   buckets and computes the rounding boundaries as the arithmetic mean (midpoint) of
>   adjacent buckets — nothing is hardcoded. Adding/removing a default frequency (e.g. a
>   future `6H`) is a **pure data edit** with no code change. (The standalone
>   `DefenderDefaultFrequencies` array was removed; it was dead and duplicated these keys.)
> - **No duplicated constant.** `MaxLookbackHoursWhenFreqOneHourOrLess` (336) is no longer
>   stored in the psd1; the loader derives it as `MaxLookbackDaysWhenFreqOneHourOrLess × 24`
>   at load time, so days remain the single source of truth (no drift).
> - **Zero/invalid scheduled frequency does NOT silently become NRT.** A zero / non-positive
>   *scheduled* `queryFrequency` (e.g. `PT0S`) on both the constrained and flexible paths
>   falls back to the shortest supported frequency and emits a diagnostic, instead of being
>   coerced to continuous `0`. Genuine NRT rules (`kind=NRT`) still produce `0`.

### Stage 3 — NRT decisioning
- Heuristic NRT-compatibility KQL validator (forbid `join`, multi-table `union`, and other
  constructs not allowed in continuous queries).
- Keep continuous (`0`) only if the query is NRT-compatible **and** classification permits;
  otherwise fall back to the shortest valid scheduled frequency + diagnose why.
- Replace the unconditional NRT→`0`
  ([lines 193–194](../src/Private/ConvertFrom-SentinelToCustomDetection.ps1#L193-L194)).

> **Stage 3 status — IMPLEMENTED.** The converter no longer maps every `kind=NRT`
> rule to `0`. For NRT rules it runs `Test-NrtQueryCompatibility` on the query and:
> emits continuous `0` (lookback `0`) + a confirming Info diagnostic **only** when the
> query is NRT-compatible; otherwise it **downgrades** to the shortest scheduled
> frequency (`$shortestFreq` from Stage 2, e.g. `1H`) with its matched default lookback
> and emits a Warning/`Constrained` diagnostic naming the violating construct(s).
> Scheduled (`kind != NRT`) rules are untouched — the validator never runs on them.
>
> - **Restriction list is data-driven.** The disallowed operators/constructs live in
>   `src/Data/NrtQueryRestrictions.psd1` (metadata-stamped like the other data files) —
>   a Microsoft change to continuous-query limits is a DATA edit, not a code change.
> - **Authoritative source:** the MS docs page *Create custom detection rules* →
>   "Queries you can run continuously"
>   (`/en-us/defender-xdr/custom-detection-rules#queries-you-can-run-continuously`,
>   `git_commit_id 78bcfca…`, `ms.date 2026-05-19`): a query runs continuously only if it
>   references **one table only**, uses supported KQL operators, and does **not** use
>   `join`, `union`, or `externaldata`, and contains **no comments**. The psd1 adds a
>   conservative superset (`evaluate`, `partition`, `fork`, graph operators, `lookup`,
>   cross-cluster/workspace refs) — err toward flagging is safe (downgrade + diagnose).
> - **Validator heuristic** (`Test-NrtQueryCompatibility`): mirrors the Stage 1
>   comment-strip + tokenization; detects comments on the raw query, disallowed operators
>   as word-boundary pipe tokens, disallowed constructs as substrings, and >1 base table
>   via the Stage 1 extractor. Conservative DENY list (not a positive allow-list).

### Stage 4 — MITRE completeness
- Multiple tactics: pick one (configurable strategy), **record dropped tactics + count** in a
  Diagnostic (today they're only mentioned in prose at
  [lines 254–258](../src/Private/ConvertFrom-SentinelToCustomDetection.ps1#L254-L258)).
- Techniques/subtechniques: validate against the supported set (full support is *Planned*);
  flag and count unsupported entries dropped.

### Stage 5 — Remaining feature gaps *(matrix-driven drop + diagnose)*
- `alertDetailsOverride` (dynamic title/description) — map what's supported, diagnose the rest.
- `customDetails` — map if/when target supports.
- `eventGroupingSettings` / `incidentConfiguration` (alert grouping, suppression,
  alerts-without-incidents) — `NotSupported` → drop + diagnose.
- Automation rules (*Planned*) and native remediation `actions` — surface; map actions where possible.

### Stage 6 — Batch summary report
- Aggregate diagnostics across a run: counts of dropped / rounded / unsupported / requires-review,
  machine-readable (JSON) + human-readable (Markdown) summary.

---

## Gap → Stage cross-reference

| Compare-doc capability | State | Stage |
| --- | --- | --- |
| Flexible/high frequency (Sentinel data) | Supported | 1, 2 |
| Rule lookback (parity) | Public preview | 1, 2 |
| NRT on Sentinel data / streaming | Supported | 3 |
| Determine rule's first run | Not supported | 3 (diagnose) |
| Link multiple MITRE tactics | Planned | 4 |
| Full MITRE techniques/subtechniques | Planned | 4 |
| Reflect in MITRE ATT&CK page | Planned | 4 (diagnose) |
| Defender XDR data | Supported | 1 |
| Native remediation actions | Supported | 5 |
| Define all alert properties dynamically | Planned | 5 |
| Customize alert grouping | Not supported | 5 |
| Create alerts without incidents | Not supported | 5 |
| Alert suppression | Not supported | 5 |
| Automation rules (incident/alert trigger) | Planned | 5 (diagnose) |
| Bicep / content hub / repos / multi-workspace | Planned | out of scope (diagnose only) |

---

## Design-for-change guarantees

- New capability states live in `CustomDetectionCapabilities.psd1`, not in code.
- The Defender table catalog lives in `DefenderXdrTables.psd1`; binary classification means a
  new Defender table is a one-line catalog add.
- Every gap is a structured Diagnostic with a `DocReference`, so the report always traces back
  to the exact compare-doc capability — making it obvious what to revisit when MS updates the doc.
