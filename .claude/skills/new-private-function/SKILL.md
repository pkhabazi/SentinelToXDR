---
name: new-private-function
description: Scaffold a new Private helper function for SentinelToXDR plus a matching Pester test, following the module's auto-discovery and naming conventions. Use when adding internal conversion/import/diagnostic logic.
---

# New private function

Add an internal helper to `src/Private/` the way the existing ones are built. The module loader
(`src/SentinelToXDR.psm1`) dot-sources every `*.ps1` in `Private/` then `Public/` automatically,
so **no manifest or loader edit is needed** — just drop the file in the right folder with the
right filename.

## Conventions (match the existing Private functions)

- **Filename = function name**, `Verb-Noun.ps1`, approved PowerShell verb
  (`Get-`, `Test-`, `New-`, `Import-`, `Write-`, `Remove-`, `ConvertFrom-`, …).
  Look at `src/Private/` for the established patterns before naming.
- One function per file. `[CmdletBinding()]`, typed/validated parameters, comment-based help
  (`.SYNOPSIS` / `.DESCRIPTION` / `.PARAMETER` / `.OUTPUTS`).
- Cross-platform PS 7: `Join-Path`, no Windows-only APIs.
- If the helper encodes Microsoft parity behaviour, push the *values* into a `src/Data/*.psd1`
  table (see `/add-lookup-rule`) and keep the function as logic only.
- Conversion gaps emit a diagnostic + warning — reuse `New-ConversionDiagnostic`, don't invent a
  parallel path.

## Steps

1. Confirm name and folder (`Private` unless it's a new exported cmdlet — those go in `Public/` and
   must be added to `FunctionsToExport` in `src/SentinelToXDR.psd1`).
2. Read 1–2 similar files in `src/Private/` to mirror style, error handling, and help format.
3. Create `src/Private/<Verb-Noun>.ps1`.
4. Create a matching `tests/<Verb-Noun>.Tests.ps1` (or add a `Describe` block to the relevant
   existing test file) that asserts real behaviour — happy path, edge cases, and the warning/
   diagnostic path if applicable. Tests import the module via the suite bootstrap; follow how
   `tests/ConvertTo-XDRCustomDetection.Tests.ps1` sets up.
5. Run `/run-tests` and confirm green before reporting done.
