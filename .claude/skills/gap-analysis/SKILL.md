---
name: gap-analysis
description: Reason about a Sentinel-to-XDR conversion gap — whether/how a Sentinel rule feature maps to XDR custom detections — using the repo's docs, schemas, and Microsoft parity doc. Use when deciding how to handle a conversion edge case or whether current behaviour is correct.
---

# Gap analysis

Use this when you need to decide how a Sentinel analytics-rule feature should map (or fail to map)
to an XDR custom detection — e.g. a new entity type, a trigger setting, a frequency edge, a KQL
construct.

## Authoritative sources (read in this order)

1. **`Feature comparison- Microsoft Sentinel analytics rules and Microsoft Defender custom detections.md`**
   (repo root) — Microsoft's parity table. This is the source of truth the `src/Data/*.psd1` files
   are derived from.
2. **`docs/Migration-Gaps.md`** (current) and `docs/Sentinel-to-XDR-GapAnalysis.md` (v1 field-level detail) — the project's documented gaps, each with default
   behaviour, warning text, and examples.
3. **`docs/Edge-Case-Implementation-Plan.md`** — how edge cases are staged/implemented.
4. **`Sentinel.schema.json`** (input shape + field mapping notes) and
   **`CustomDetection.schema.json`** (output shape).
5. The current behaviour in `src/Private/` (especially `ConvertFrom-SentinelToCustomDetection.ps1`)
   and the `src/Data/*.psd1` tables.

## How to analyse

- State the Sentinel feature and the XDR target precisely (field names, enum values).
- Determine: does XDR support it directly, partially, or not at all? Cite the parity doc row.
- Decide the conversion behaviour following the repo's rules:
  - Prefer a faithful mapping; where impossible, **degrade explicitly with a warning/diagnostic** —
    never silently drop or guess.
  - If the behaviour is governed by a parity value, it belongs in `src/Data/*.psd1`
    (use `/add-lookup-rule`), not in code.
- Check whether current code/tests/docs already cover it, and whether the README "Conversion Gaps"
  table and `docs/Sentinel-to-XDR-GapAnalysis.md` need updating to stay accurate.

## Output

A short decision: the mapping (or explicit gap), the warning/diagnostic the user should see,
where the change lands (code vs. data vs. docs), and the tests needed. Flag any contradiction
between the code and the parity doc you find along the way.
