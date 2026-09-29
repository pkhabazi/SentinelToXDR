<#
.SYNOPSIS
Run all Pester tests for the SentinelToXDR module.

.DESCRIPTION
Executes all Pester tests in the Tests directory and generates a report.

.PARAMETER OutputFormat
Output format for the test results (NUnitXml, JUnitXml, None)

.PARAMETER OutputPath
Path where to save the test results file

.EXAMPLE
.\Invoke-Tests.ps1
.\Invoke-Tests.ps1 -OutputFormat NUnitXml -OutputPath ./testresults.xml
#>

param(
    [Parameter(Mandatory = $false)]
    [ValidateSet('NUnitXml', 'JUnitXml', 'None')]
    [string]$OutputFormat = 'None',

    [Parameter(Mandatory = $false)]
    [string]$OutputPath
)

Write-Host "==== SentinelToXDR Pester Test Runner ====" -ForegroundColor Cyan

# Ensure required modules are available.
# The test suite relies on Pester 5's [PesterConfiguration] type, so an older
# built-in Pester (v3/v4) does not satisfy the requirement — enforce a minimum.
$requiredModules = @(
    @{ Name = 'Pester'; MinimumVersion = [version]'5.0.0' }
    @{ Name = 'powershell-yaml'; MinimumVersion = [version]'0.0.0' }
)

foreach ($module in $requiredModules) {
    $name = $module.Name
    $minVersion = $module.MinimumVersion

    $available = Get-Module -ListAvailable -Name $name |
        Where-Object { $_.Version -ge $minVersion }

    if (-not $available) {
        Write-Host "$name >= $minVersion not found. Installing..." -ForegroundColor Yellow
        try {
            Install-Module -Name $name -MinimumVersion $minVersion -Scope CurrentUser -Force -ErrorAction Stop
            Write-Host "$name installed successfully." -ForegroundColor Green
        } catch {
            Write-Host "ERROR: Failed to install ${name}: $_" -ForegroundColor Red
            exit 1
        }
    }
}

# Import required modules (pin Pester to >= 5 so the v3/v4 shipped with Windows
# PowerShell is never the one loaded).
Import-Module -Name 'Pester' -MinimumVersion '5.0.0' -Force
Import-Module -Name 'powershell-yaml' -Force

# Get test files. Wrap in @() so a single match still exposes a reliable .Count
# (a lone FileInfo has no .Count, which would make the guard below misbehave).
$testFiles = @(Get-ChildItem -Path $PSScriptRoot -Filter '*.Tests.ps1' -Recurse)

if ($testFiles.Count -eq 0) {
    Write-Host "No test files found in $PSScriptRoot" -ForegroundColor Yellow
    exit 0
}

Write-Host "`nFound $($testFiles.Count) test file(s):" -ForegroundColor Green
$testFiles | ForEach-Object { Write-Host "  - $($_.Name)" -ForegroundColor Green }

# Run Pester tests
Write-Host "`nRunning tests..." -ForegroundColor Cyan
$configuration = [PesterConfiguration]@{
    Run    = @{
        Path     = $PSScriptRoot
        PassThru = $true
    }
    Output = @{
        Verbosity = 'Detailed'
    }
}

if ($OutputFormat -ne 'None' -and $OutputPath) {
    $configuration.TestResult = @{
        Enabled      = $true
        OutputFormat = $OutputFormat
        OutputPath   = $OutputPath
    }
}

$testResults = Invoke-Pester -Configuration $configuration

# Display summary
Write-Host "`n==== Test Summary ====" -ForegroundColor Cyan
Write-Host "Total Tests: $($testResults.Tests.Count)" -ForegroundColor White
Write-Host "Passed: $($testResults.Passed.Count)" -ForegroundColor Green
Write-Host "Failed: $($testResults.Failed.Count)" -ForegroundColor $(if ($testResults.Failed.Count -gt 0) { 'Red' } else { 'Green' })
Write-Host "Skipped: $($testResults.Skipped.Count)" -ForegroundColor Yellow

if ($testResults.Failed.Count -gt 0) {
    Write-Host "`n==== Failed Tests ====" -ForegroundColor Red
    $testResults.Failed | ForEach-Object {
        Write-Host "  x $($_.Name)" -ForegroundColor Red
        Write-Host "    Error: $($_.ErrorRecord.Exception.Message)" -ForegroundColor Red
    }
}

if ($OutputFormat -ne 'None' -and $OutputPath) {
    Write-Host "`nResults saved to: $OutputPath" -ForegroundColor Green
}

# A run that silently lost tests must not pass. Packaging.Tests.ps1 checks that every
# test file parses, which is the structural half of the guard; this is the numeric half.
# The floor lives in tests/minimum-test-count.txt and is raised, never lowered, as the
# suite grows. Override with SENTINELTOXDR_MIN_TESTS for a deliberate partial run.
$floorFile = Join-Path $PSScriptRoot 'minimum-test-count.txt'
$minimum = if ($env:SENTINELTOXDR_MIN_TESTS) { [int]$env:SENTINELTOXDR_MIN_TESTS }
           elseif (Test-Path -LiteralPath $floorFile) { [int](Get-Content -LiteralPath $floorFile -Raw).Trim() }
           else { 0 }
$ran = $testResults.Tests.Count
$lostTests = $ran -lt $minimum
if ($lostTests) {
    Write-Host "`nOnly $ran test(s) ran; the floor is $minimum. Tests have gone missing - a file that does not parse, a Describe that did not register. Treating this as a failure." -ForegroundColor Red
}

# Exit with appropriate code
exit $(if ($testResults.Failed.Count -gt 0 -or $lostTests) { 1 } else { 0 })
