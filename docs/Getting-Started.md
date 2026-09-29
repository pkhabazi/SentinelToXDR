# Getting started

From nothing to your first migration assessment in about five minutes. No tenant and no
sign-in needed for any of it.

## 1. Prerequisites

- **PowerShell 7.0 or later** on Windows, Linux or macOS. Check with `$PSVersionTable.PSVersion`.
  If you only have Windows PowerShell 5.1, [install PowerShell 7](https://learn.microsoft.com/powershell/scripting/install/installing-powershell)
  alongside it.
- **powershell-yaml**, the one dependency:

  ```powershell
  Install-Module -Name powershell-yaml -Scope CurrentUser
  ```

- **git**, if you clone (recommended).
- **Claude Code**, only if you want to use the [skill](Run-With-Claude-Code.md).

## 2. Install

The module is published on GitHub only. It is not on the PowerShell Gallery.

**Clone the repository** (recommended: you also get `Samples/` and the Claude Code skill)

```powershell
git clone https://github.com/pkhabazi/SentinelToXDR.git
cd SentinelToXDR
Import-Module ./src/SentinelToXDR.psd1
```

**Or download a release**

Grab `SentinelToXDR-<version>.zip` from
[Releases](https://github.com/pkhabazi/SentinelToXDR/releases) and put the module folder on
your `PSModulePath`:

```powershell
$zip  = "$HOME/Downloads/SentinelToXDR-1.0.0.zip"
$dest = ($env:PSModulePath -split [IO.Path]::PathSeparator)[0]
Expand-Archive -Path $zip -DestinationPath $dest -Force

# Windows only: files from the internet are blocked under RemoteSigned
Get-ChildItem (Join-Path $dest 'SentinelToXDR') -Recurse | Unblock-File

Import-Module SentinelToXDR
```

The zip holds the module only. For `Samples/` and the skill, clone.

**Check it loaded**

```powershell
Get-Command -Module SentinelToXDR
```

You should see 13 commands.

## 3. Your first assessment, on the samples

From the repository root:

```powershell
Test-XDRMigrationReadiness -Path ./Samples | Group-Object Verdict -NoElement
```

```
Count Name
----- ----
    2 Blocked
   15 NeedsWork
    8 Ready
   11 Review
```

`Samples/` holds one rule for every migration scenario the module detects, so this shows you
every verdict it can give. [Samples/README.md](../Samples/README.md) says what each rule
demonstrates.

## 4. Now your own rules

Get your rules as files first. Any of these works:

| You have | Point the module at |
|---|---|
| Rules in a git repository (YAML or ARM) | the folder, with `-Recurse` |
| An export from the Sentinel portal (ARM JSON) | the file or folder |
| A Content Hub solution | a clone of [Azure/Azure-Sentinel](https://github.com/Azure/Azure-Sentinel), `Solutions/<name>`, with `-Recurse` |
| Only a live workspace | skip the files and read it directly, see [Run it with PowerShell](Run-With-PowerShell.md#1-read-your-rules) |

Then write the report:

```powershell
Invoke-SentinelToXDRMigration -Path ./my-rules -Recurse -ReportPath ./readiness.html
```

Open `readiness.html` in a browser. It is one self contained page (no CDN, no external font),
so you can mail it or put it on a file share.

## 5. Pick your path

| I want to | Go to |
|---|---|
| Ask in plain language and get the report explained | [Run it with Claude Code](Run-With-Claude-Code.md) |
| Assess, convert, validate and deploy from a prompt | [Run it with PowerShell](Run-With-PowerShell.md) |
| Understand a specific gap or verdict | [Migration-Gaps.md](Migration-Gaps.md) |
| Know why a rule the docs allow was refused | [API-Constraints.md](API-Constraints.md) |
| Know how far to trust a verdict | [Validation.md](Validation.md) |

## If something goes wrong

| Symptom | Fix |
|---|---|
| `The required module 'powershell-yaml' is not loaded` | `Install-Module powershell-yaml -Scope CurrentUser` |
| "requires a minimum Windows PowerShell version of '7.0'" on import | You are in Windows PowerShell 5.1. Run `pwsh`, not `powershell`. |
| `cannot be loaded because running scripts is disabled` or "not digitally signed" (Windows) | The zip was blocked. Run the `Unblock-File` line above, or `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`. |
| "no rules found" | The folder holds no analytics rules, or they sit in subfolders: add `-Recurse`. The warning says how many files were checked and why the first was skipped. |

Still stuck? [Open an issue](https://github.com/pkhabazi/SentinelToXDR/issues/new?template=bug_report.md)
with the command and the output.
