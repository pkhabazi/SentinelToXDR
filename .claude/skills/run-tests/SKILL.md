---
name: run-tests
description: Run the SentinelToXDR Pester test suite and report results. Use when asked to run tests, verify a change, or confirm the suite is green before committing.
---

# Run tests

Run the module's Pester suite and report clearly.

## Steps

1. Run the suite from the repo root:
   ```bash
   pwsh -NoProfile -File tests/Invoke-Tests.ps1
   ```
   The runner auto-installs `Pester` and `powershell-yaml` if missing, imports the module, and
   exits non-zero on any failure.

2. For CI-style output (e.g. when generating an artifact):
   ```bash
   pwsh -NoProfile -File tests/Invoke-Tests.ps1 -OutputFormat NUnitXml -OutputPath ./testresults.xml
   ```

3. To run a single test file or filter while iterating:
   ```bash
   pwsh -NoProfile -c "Invoke-Pester -Path tests/ConvertTo-XDRCustomDetection.Tests.ps1 -Output Detailed"
   ```

## Report

- Quote the **Passed / Failed / Skipped** counts — never say "tests pass" without the numbers.
- If anything failed, list each failing test name and its error message, then point at the
  likely cause (`file:line`). Do not paper over a failure.
- If the suite is green, say so plainly with the counts.
