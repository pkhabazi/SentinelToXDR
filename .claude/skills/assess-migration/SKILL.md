---
name: assess-migration
description: Assess one or more Microsoft Sentinel analytics rules for migration to Defender XDR custom detections and produce a self-contained HTML report showing how many can migrate, which cannot, and what blocks each one. Use when asked "which of these rules can I migrate", "assess this estate", "run the migration assessment", "what blocks these rules", or when pointed at a folder of Sentinel rules (community YAML, ARM JSON, Content Hub solution) and asked whether they move to Defender XDR.
---

# Assess a Sentinel estate for Defender XDR migration

One run, one report. The verdicts come from the SentinelToXDR module in this repository;
this skill runs it, reads the result back, and tells the user what it means. **The skill
never decides a verdict itself.** The module is the judge because its verdicts are
validated against 5,161 corpus rules and six API constraints observed on a live tenant (eight were found; two were withdrawn when the service stopped enforcing them, and one was never a constraint);
an AI reading KQL by eye is not.

## Steps

1. **Find the rules.** The user names a file or folder. Community YAML, ARM JSON, ARM
   deployment templates and Content Hub `mainTemplate.json` are all read by the module.
   If they point at a whole solution or repo, add `-Recurse`. Do not convert or pre-read
   the rules yourself.

2. **Run the engine.** From the repo root:
   ```bash
   pwsh -NoProfile -File .claude/skills/assess-migration/scripts/Invoke-MigrationAssessment.ps1 -Path <path> [-Recurse] -OutputFolder ./out/assessment -Title "<estate name> migration assessment"
   ```
   It writes `assessment.json` and `assessment.html` and prints a short summary. Takes
   seconds for a folder, about a minute for a full Content Hub solution.

3. **Read `assessment.json`**, not the HTML. It carries: `Verdicts` (counts), `RulesInWindow`
   (rules that can only migrate via a property removed on `DeprecationDate`), `Blockers`
   (one row per finding, counted per rule, with the remedy text), `EstatePrereqs`, `DataTiers`,
   and `Rules` (per rule: verdict, drivers, remedy).

4. **Open the report** so the user sees it, with the opener for their platform:
   ```bash
   open ./out/assessment/assessment.html        # macOS
   start ./out/assessment/assessment.html       # Windows
   xdg-open ./out/assessment/assessment.html    # Linux
   ```

5. **Say what it means, in five lines or fewer**, from the JSON numbers only:
   - the split: how many deploy today (Ready + Review), how many need work, how many are blocked
   - the single biggest blocker and what fixes it (from `Blockers[0].Remedy`)
   - the deprecation window count if it is not zero, with the date
   - the estate-wide prerequisite if there is one (usually: Sentinel data in the Defender portal)
   - where the report is

## What the verdicts mean

| Verdict | Means | Do |
|---|---|---|
| Ready | Converts cleanly. | Deploy it. |
| Review | Behaves the same once a prerequisite holds, usually estate-wide. | Check it once. |
| NeedsWork | Converts, but behaves differently, or the API will refuse it. The finding names the field to add. | Decide, or edit the source rule. |
| Blocked | Cannot become a custom detection (Fusion, ML, TI, no query). | Use the native Defender capability. |

## Rules for the narration

- Quote counts from `assessment.json`. Never estimate, never round differently than the report.
- Never re-grade a rule. If the user disagrees with a verdict, point them to
  `src/Data/MigrationReadiness.psd1`, where the impact classification lives as data.
- The KQL scans are heuristics. If the user asks "will this query actually run", the honest
  answer is `Test-XDRDetectionQuery` against their tenant, which this skill does not call.
- Do not offer to fix rules in this skill. Remediation is a separate step.

## Demo path (Samples)

`./Samples` holds 31 files, one per migration scenario, every verdict represented, with the
expected verdicts pinned in `Samples/expected.psd1`. Assessing it is the two-minute demo:

```bash
pwsh -NoProfile -File .claude/skills/assess-migration/scripts/Invoke-MigrationAssessment.ps1 -Path ./Samples -Title "Sample estate"
```
