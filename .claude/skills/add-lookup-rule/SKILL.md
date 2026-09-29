---
name: add-lookup-rule
description: Safely add or change an entry in a src/Data/*.psd1 lookup table (MITRE mappings, frequency/lookback buckets, capability limits, XDR tables, NRT restrictions) while keeping the Metadata and derivation invariants intact. Use when conversion behaviour changes because Microsoft's parity tables changed.
---

# Add / change a lookup rule

Conversion behaviour that depends on Microsoft's published parity tables is **data, not code**.
It lives in `src/Data/*.psd1`. Editing a value here is the correct way to track Microsoft's
changes — do not hard-code it into a function.

## The data files

| File | What it controls |
|---|---|
| `MitreSupportRules.psd1` | MITRE tactic → XDR `alertCategory` support/mapping |
| `FrequencyLookbackRules.psd1` | Frequency parity limits + default-frequency buckets + per-bucket default lookback |
| `CustomDetectionCapabilities.psd1` | XDR custom-detection capability limits/feature checks |
| `DefenderXdrTables.psd1` | Defender XDR advanced-hunting table classification |
| `FeatureGapRules.psd1` | Known Sentinel→XDR feature gaps |
| `NrtQueryRestrictions.psd1` | KQL restrictions for NRT-compatible queries |

## Invariants — do not break these

1. **`Metadata` block is the drift anchor.** Every file stamps `SourceDoc`, `GitCommitId`, and
   `MsDate` from Microsoft's source doc (the `Feature comparison-...md` in the repo root). If you
   change a value *because the source doc changed*, update `GitCommitId` and `MsDate` to match the
   new doc revision. If you're fixing a bug without a doc change, leave Metadata alone.
2. **Single source of truth — never duplicate a derived value.** Several values are derived at
   load time (e.g. in `FrequencyLookbackRules.psd1`, the hours limit for "freq ≤ 1h" is derived
   from the days value × 24; rounding buckets are derived from the `DefaultLookbackPerFrequency`
   keys). Add the canonical value only; let the loader derive the twin. Read the file's header
   comments — they spell out exactly what's derived.
3. **Match the existing shape.** Keys/value types must match what the corresponding
   `Get-*`/loader function in `src/Private/` expects.

## Steps

1. Identify the right file and read it in full — including the header comments and `Metadata`.
2. Read the matching `src/Private/Get-*.ps1` (or loader) to confirm the key/value contract and
   what is derived vs. stored.
3. Make the data edit. Update `Metadata` only if driven by a source-doc change.
4. Add/extend a Pester test asserting the new mapping flows through conversion correctly.
5. Run `/run-tests`.
