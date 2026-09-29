# Run it with Claude Code

The repository ships a [Claude Code](https://claude.com/claude-code) skill,
[`assess-migration`](../.claude/skills/assess-migration/SKILL.md). You point it at a folder of
Sentinel rules in plain language, and you get the HTML assessment report plus a short
explanation of what it means: how many rules move today, what blocks the rest, and what to
change first.

It is the same assessment as `Test-XDRMigrationReadiness`, with Claude doing the reading and
summarizing. No tenant, no sign-in, nothing deployed.

## The one rule behind it

**The module judges, the skill narrates.** The skill never decides a verdict by reading KQL
itself. Every verdict and every count comes from the PowerShell module, which is tested
against 5,161 real rules and six API constraints observed on a live tenant. Every real bug
this project ever had was in extraction (table detection, ARM expressions, TimeSpan shapes),
exactly the kind of detail a language model gets wrong without telling you. So the code
decides, and Claude explains what the code decided.

## What you need

- [Claude Code](https://docs.claude.com/en/docs/claude-code/overview), in the terminal, the
  desktop app or your IDE
- PowerShell 7.0+ as `pwsh` on your `PATH`
- [powershell-yaml](https://www.powershellgallery.com/packages/powershell-yaml):
  `Install-Module powershell-yaml -Scope CurrentUser`
- A clone of this repository. The skill lives in `.claude/skills/`, so it is only available
  when Claude Code runs in the repository folder. The release zip does not include it.

## Step by step

**1. Clone the repository and start Claude Code in it**

```bash
git clone https://github.com/pkhabazi/SentinelToXDR.git
cd SentinelToXDR
claude
```

In the desktop app or an IDE, open the `SentinelToXDR` folder instead.

**2. Try it on the samples first**

```
assess ./Samples
```

`Samples/` holds one rule per migration scenario, so this shows you every verdict the module
can give. It takes a few seconds.

**3. Point it at your own rules**

Copy or export your rules somewhere Claude Code can reach (inside the repository is easiest;
`out/` and anything you add to `.gitignore` stay out of git), then ask in your own words:

```
assess ./my-rules
which of the rules in ./export can I move to Defender, and what blocks the rest?
run the migration assessment on "./Azure-Sentinel/Solutions/Microsoft Entra ID"
```

Claude Code asks for permission the first time it runs `pwsh`. That is the skill running the
module; allow it.

**4. Read the result**

The skill runs
[`Invoke-MigrationAssessment.ps1`](../.claude/skills/assess-migration/scripts/Invoke-MigrationAssessment.ps1),
which writes two files:

| File | What it is |
|---|---|
| `out/assessment/assessment.html` | The report: verdict tiles, what blocks the most rules and the remedy, rules in the 2026-10-01 window, estate wide prerequisites, one row per rule. Self contained, no CDN, safe to mail. |
| `out/assessment/assessment.json` | The same data, machine readable. This is what Claude reads. |

It opens the HTML and answers in five lines or fewer, all numbers from the JSON:

- how many rules deploy today (Ready plus Review), how many need work, how many are blocked
- the single biggest blocker and what fixes it
- how many rules sit in the 2026-10-01 window, if any
- the estate wide prerequisite, usually that your Sentinel data is visible in the Defender portal
- where the report is

On `./Samples` the console summary looks like this:

```
  NeedsWork    15  42%
  Review       11  31%
  Ready         8  22%
  In the 2026-10-01 window: 1

Top blockers (rules affected):
    2  Cannot be migrated
    5  The query depends on something that does not exist in Defender XDR and will not run
    2  The service will refuse this entity mapping: no sufficient identifier
```

**5. Ask follow-up questions**

The JSON has one row per rule with its findings and remedy, so follow-ups work well:

```
which rules are blocked, and what should replace them?
list the NeedsWork rules that only need an entity mapping
what does "trigger threshold dropped" mean for rule 04?
```

## What the skill will not do

- **Re-grade a rule.** If you disagree with a verdict, the classification lives as data in
  [`src/Data/MigrationReadiness.psd1`](../src/Data/MigrationReadiness.psd1). Change it there.
- **Prove a query runs.** The dependency scan is a heuristic. Only
  `Test-XDRDetectionQuery` against your tenant proves it (see
  [Run it with PowerShell](Run-With-PowerShell.md#4-validate-and-deploy)).
- **Fix or deploy rules.** It assesses and explains. Converting and deploying are PowerShell
  steps, on purpose.

## What leaves your machine

The module runs locally. What Claude reads, and therefore what is sent to the model, is
`assessment.json`: rule names, file paths, verdicts and findings. The skill does not tell
Claude to read your KQL, but Claude Code can read any file in the folder if you ask it to.
If your rules or their names are sensitive, run the assessment with
[PowerShell](Run-With-PowerShell.md) instead, or follow your organization's policy for AI
tools.

## Without Claude

The script behind the skill runs fine on its own:

```bash
pwsh -NoProfile -File .claude/skills/assess-migration/scripts/Invoke-MigrationAssessment.ps1 -Path ./my-rules -Recurse -Title "My estate"
```

| Parameter | Default | |
|---|---|---|
| `-Path` | (required) | File or folder of rules |
| `-Recurse` | off | Search subfolders |
| `-OutputFolder` | `./out/assessment` | Where the two files land |
| `-Title` | `Sentinel to Defender XDR migration assessment` | Report heading |

## Troubleshooting

| Symptom | Fix |
|---|---|
| `pwsh: command not found` | Install PowerShell 7 and make sure `pwsh` is on your `PATH`. |
| `The required module 'powershell-yaml' is not loaded` | `Install-Module powershell-yaml -Scope CurrentUser` |
| Claude does not use the skill | Make sure Claude Code was started in the repository folder, then ask more directly: "use the assess-migration skill on ./my-rules". |
| "no rules found" | The path holds no analytics rules, or they sit in subfolders: ask again with "recursively". The script reports how many files it looked at and why the first was skipped. |
| The report did not open | It is at `out/assessment/assessment.html`; open it in any browser. |

---

Next: [Run it with PowerShell](Run-With-PowerShell.md) to convert and deploy what the
assessment says is ready.
