<#
.SYNOPSIS
    Lints, tests, packages and publishes the SentinelToXDR module.

.DESCRIPTION
    One script, run identically by a developer and by CI. Before this existed the
    publishing logic lived only inside .github/workflows/release.yml, which meant the first
    time anyone saw the package being built was during a tagged release — the one moment
    when getting it wrong is expensive and a version number cannot be reused.

    Tasks run in order and stop on the first failure:

      Lint     PSScriptAnalyzer over ./src at Error severity, matching CI.
      Test     The Pester suite.
      Package  Stage the module into a folder named SentinelToXDR (Publish-Module
               requires the folder name to match the module name), and validate the
               manifest from the staged copy rather than from source — so what is
               checked is what would actually ship.
      Publish  Push the staged package to the PowerShell Gallery. Refuses to run
               without -Execute, so the default is always a dry run.

    The staged folder deliberately includes LICENSE, README.md and CHANGELOG.md alongside
    src/*. The Gallery shows the README on the package page and the licence matters
    legally; a package carrying neither is a worse artifact than the repository it came
    from.

.PARAMETER Task
    What to run. 'All' runs Lint, Test and Package. Publish is never part of 'All': it is
    the one irreversible step and has to be asked for by name.

.PARAMETER Execute
    Required for the Publish task to actually push. Without it, Publish reports what it
    would send and stops. Deliberately not named -Confirm: that name means "prompt me" to
    every other PowerShell command, and a flag that publishes when the user expected a
    prompt is the wrong way round.

.PARAMETER ApiKey
    PowerShell Gallery API key. Defaults to the PSGALLERY_API_KEY environment variable.

.PARAMETER OutputPath
    Where to stage the package. Defaults to ./artifacts.

.EXAMPLE
    ./build.ps1

    Lint, test and package. The everyday check.

.EXAMPLE
    ./build.ps1 -Task Package

    Build the package and validate it, without re-running the suite.

.EXAMPLE
    ./build.ps1 -Task Publish

    Dry run: shows exactly what would be pushed to the Gallery, and pushes nothing.

.EXAMPLE
    ./build.ps1 -Task Publish -Execute

    The real thing.
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('All', 'Lint', 'Test', 'Package', 'Publish')]
    [string]$Task = 'All',

    [Parameter()]
    [switch]$Execute,

    [Parameter()]
    [string]$ApiKey = $env:PSGALLERY_API_KEY,

    [Parameter()]
    [string]$OutputPath
)

$ErrorActionPreference = 'Stop'

$RepoRoot     = $PSScriptRoot
$SourcePath   = Join-Path $RepoRoot 'src'
if (-not $OutputPath) { $OutputPath = Join-Path $RepoRoot 'artifacts' }
$StagingPath = Join-Path $OutputPath 'SentinelToXDR'

# Files that belong in the package but do not live under src/.
$PackageExtras = @('LICENSE', 'README.md', 'CHANGELOG.md')

function Write-Step {
    param([string]$Message)
    Write-Host "`n==== $Message ====" -ForegroundColor Cyan
}

function Invoke-LintTask {
    Write-Step 'Lint'

    if (-not (Get-Module -ListAvailable -Name PSScriptAnalyzer)) {
        throw 'PSScriptAnalyzer is not installed. Install-Module PSScriptAnalyzer -Scope CurrentUser'
    }
    Import-Module PSScriptAnalyzer -Force

    # Error severity only, matching .github/workflows/ci.yml. Warnings are surfaced by the
    # editor hook during development; failing the build on them would make the build a
    # style gate rather than a correctness gate.
    $findings = @(Invoke-ScriptAnalyzer -Path $SourcePath -Recurse -Severity Error)
    if ($findings.Count -gt 0) {
        $findings | Format-Table -AutoSize | Out-String | Write-Host
        throw "PSScriptAnalyzer reported $($findings.Count) error(s)."
    }
    Write-Host 'No errors.' -ForegroundColor Green
}

function Invoke-TestTask {
    Write-Step 'Test'
    & (Join-Path $RepoRoot 'tests/Invoke-Tests.ps1')
    if ($LASTEXITCODE -ne 0) { throw "The test suite failed (exit code $LASTEXITCODE)." }
}

function Invoke-PackageTask {
    Write-Step 'Package'

    if (Test-Path -LiteralPath $StagingPath) {
        Remove-Item -LiteralPath $StagingPath -Recurse -Force
    }
    New-Item -ItemType Directory -Path $StagingPath -Force | Out-Null

    Copy-Item -Path (Join-Path $SourcePath '*') -Destination $StagingPath -Recurse -Force

    foreach ($extra in $PackageExtras) {
        $source = Join-Path $RepoRoot $extra
        if (Test-Path -LiteralPath $source) {
            Copy-Item -LiteralPath $source -Destination $StagingPath -Force
        } else {
            Write-Warning "$extra was not found at the repository root and is not in the package."
        }
    }

    # Validate the STAGED manifest, not the source one. A file that failed to copy is
    # invisible to a check that reads from src/, and that is precisely the failure this
    # step exists to catch.
    $manifest = Test-ModuleManifest -Path (Join-Path $StagingPath 'SentinelToXDR.psd1')

    Write-Host "Module:   $($manifest.Name) $($manifest.Version)" -ForegroundColor Green
    Write-Host "Exports:  $($manifest.ExportedFunctions.Count) function(s)"
    Write-Host "Staged:   $StagingPath"

    # Import the staged copy in a separate process, so a module already loaded in this
    # session cannot make a broken package look importable.
    $importCheck = pwsh -NoProfile -Command "
        `$ErrorActionPreference = 'Stop'
        Import-Module '$(Join-Path $StagingPath 'SentinelToXDR.psd1')' -Force
        (Get-Command -Module SentinelToXDR).Count
    "
    if ($LASTEXITCODE -ne 0) { throw 'The staged package failed to import.' }

    $exported = [int]($importCheck | Select-Object -Last 1)
    $declared = $manifest.ExportedFunctions.Count
    if ($exported -ne $declared) {
        throw "The staged package exports $exported command(s) but the manifest declares $declared."
    }
    Write-Host "Imported cleanly and exported $exported command(s)." -ForegroundColor Green

    $size = [math]::Round((Get-ChildItem -LiteralPath $StagingPath -Recurse -File |
        Measure-Object -Property Length -Sum).Sum / 1KB, 1)
    Write-Host "Size:     $size KB"
}

function Invoke-PublishTask {
    Write-Step 'Publish'

    if (-not (Test-Path -LiteralPath $StagingPath)) {
        throw 'Nothing staged. Run ./build.ps1 -Task Package first.'
    }

    $manifest = Test-ModuleManifest -Path (Join-Path $StagingPath 'SentinelToXDR.psd1')

    # A version already on the Gallery cannot be replaced or reused. Finding that out from
    # Publish-Module's error, after a tag has been pushed, is a bad way to learn it.
    $existing = Find-Module -Name $manifest.Name -RequiredVersion $manifest.Version -ErrorAction SilentlyContinue
    if ($existing) {
        throw ("$($manifest.Name) $($manifest.Version) is already on the PowerShell Gallery. " +
            'Versions are immutable: bump ModuleVersion in src/SentinelToXDR.psd1.')
    }

    Write-Host "Would publish: $($manifest.Name) $($manifest.Version)"
    Write-Host "  From:        $StagingPath"
    Write-Host "  Project:     $($manifest.PrivateData.PSData.ProjectUri)"
    Write-Host "  Licence:     $($manifest.PrivateData.PSData.LicenseUri)"
    Write-Host "  Tags:        $($manifest.PrivateData.PSData.Tags -join ', ')"

    if (-not $Execute) {
        Write-Host "`nDry run. Nothing was published. Re-run with -Execute to publish." -ForegroundColor Yellow
        return
    }

    if (-not $ApiKey) {
        throw 'No API key. Pass -ApiKey or set the PSGALLERY_API_KEY environment variable.'
    }

    Publish-Module -Path $StagingPath -NuGetApiKey $ApiKey -Verbose
    Write-Host "`nPublished $($manifest.Name) $($manifest.Version)." -ForegroundColor Green
}

switch ($Task) {
    'Lint'    { Invoke-LintTask }
    'Test'    { Invoke-TestTask }
    'Package' { Invoke-PackageTask }
    'Publish' { Invoke-PublishTask }
    'All'     {
        Invoke-LintTask
        Invoke-TestTask
        Invoke-PackageTask
        Write-Host "`nReady. ./build.ps1 -Task Publish shows what would go to the Gallery." -ForegroundColor Green
    }
}
