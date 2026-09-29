<#
.SYNOPSIS
    Re-checks every undocumented constraint this module asserts, on fresh ids, in one run.

.DESCRIPTION
    Every "the service will refuse this" claim in src/Data/GraphDetectionRule.psd1 was found
    by deploying a rule and reading the 400. Two of them were true in August and gone by
    September, and the module kept asserting them for three weeks because nothing re-ran
    the probe. There is no v1.0 of this API, only /beta: a recorded constraint has an
    expiry date, and this script is how it gets checked.

    One probe per constraint. Each rule is the BASELINE rule (which the tenant accepts)
    altered in exactly one way, so a 400 names one cause and not a combination. Three
    things this gets right that earlier probes got wrong, each of which cost a wrong entry
    in the data file:

      - every id is a fresh GUID. Re-using an id that still exists in the tenant produces
        a 409 that looks like a constraint.
      - every column any case maps is synthesised with 'extend', so the projected-columns
        constraint can never be what fails, and every case that is not testing the asset
        requirement carries a hosts mapping the tenant accepts on its own.
      - a refusal is only counted as confirming the constraint under test when the service
        message names THAT constraint. A 400 for a different reason is VOID, not evidence.

    Outcomes per case:
      AsExpected  the service did what the data file says it does
      CHANGED     it did not - accepted what the data file says it refuses, or vice versa.
                  A CHANGED row is a data edit waiting to happen; see TacticConstraints.History.
      VOID        refused, but for a reason other than the one under test. Says nothing.

    Deletion: a second DELETE answering 404 shows the service has taken the delete, and
    that is all any call shows. GET and the portal keep the rule for hours afterwards
    (measured 2026-09-16). The script says 'taken', never 'clean'.

    Everything is created disabled, prefixed 's2x-probe-', and removed in a finally block.
    Public surface only - Packaging.Tests.ps1 enforces it.

.PARAMETER ConfirmDevelopmentTenant
    Mandatory. This script creates detections. Do not point it at production.

.PARAMETER ReportPath
    Optional CSV of the per-case results.

.PARAMETER IdPrefix
    Prefix for every probe id. Defaults to 's2x-probe-'.

.EXAMPLE
    pwsh -NoProfile -NoExit -c 'Import-Module ./src/SentinelToXDR.psd1 -Force; Connect-SentinelToXDR; ./tests/Integration/Probes/Probe-ApiBehaviour.ps1 -ConfirmDevelopmentTenant -ReportPath ./validation/probe-api-behaviour.csv'
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [switch]$ConfirmDevelopmentTenant,

    [Parameter()]
    [string]$ReportPath,

    [Parameter()]
    [string]$IdPrefix = 's2x-probe-'
)

$ErrorActionPreference = 'Continue'

if (-not $ConfirmDevelopmentTenant) { throw 'Pass -ConfirmDevelopmentTenant. This script writes to the tenant.' }

if (-not (Get-Module -Name SentinelToXDR)) {
    Import-Module -Name (Join-Path $PSScriptRoot '../../../src/SentinelToXDR.psd1') -Force
}

# A Graph delegated session lives in the process that created it, so a script launched with
# pwsh -File starts with nothing. Connect here rather than requiring the caller to have done
# it in this exact process.
$context = Get-SentinelToXDRContext
if (-not $context.CanManageDetections) {
    Write-Host 'No Graph session in this process. Signing in...' -ForegroundColor Yellow
    try { Connect-SentinelToXDR -ErrorAction Stop } catch { Write-Host "Sign-in FAILED: $($_.Exception.Message)" -ForegroundColor Red; throw }
    $context = Get-SentinelToXDRContext
}
if (-not $context.CanManageDetections) {
    throw ("Signed in as '$($context.Account)' but CanManageDetections is false " +
        "(AuthMode=$($context.AuthMode), missing=$($context.MissingScopes -join ', ')). Cannot probe.")
}
Write-Host "Tenant: $($context.Account) ($($context.TenantId))`n" -ForegroundColor Cyan

# ---- the baseline: accepted by the tenant on 2026-09-16 (Samples/01 round trip) ----------
# Every column any case maps is projected here whatever the table holds.
$baselineQuery = @'
DeviceProcessEvents
| take 1
| extend AccountDomain = 'CONTOSO', RemoteIP = '10.0.0.1', Url = 'https://example.com',
         RegistryKeyX = @'HKLM\Software', RegistryValueNameX = 'Run'
'@
# The registry key is a KQL VERBATIM string (@'...'). In a plain single-quoted KQL string
# the backslash is an escape, and on 2026-09-16 the first run of this probe refused every
# case that reached the query with 'Query could not be parsed at '\\''. The baseline case
# caught it - which is what it is for - and the run proved nothing else.

function Get-BaselineRule {
    param([string]$Name)
    [ordered]@{
        id              = "$IdPrefix$([guid]::NewGuid())"
        displayName     = "S2X probe $Name"
        description     = 'SentinelToXDR constraint probe. Safe to delete.'
        status          = 'disabled'
        queryCondition  = [ordered]@{ queryText = $baselineQuery }
        schedule        = [ordered]@{ frequency = 'PT1H' }
        detectionAction = [ordered]@{
            alertTemplate = [ordered]@{
                title          = "S2X probe $Name"
                description    = 'SentinelToXDR constraint probe. Safe to delete.'
                severity       = 'low'
                tactics        = @([ordered]@{ tactic = 'Execution'; techniques = @([ordered]@{ technique = 'T1059' }) })
                entityMappings = [ordered]@{ hosts = @([ordered]@{ nameColumn = 'DeviceName' }) }
            }
        }
    }
}

# Each case: what it changes, what the data file says will happen, the constraint it tests,
# when that was last observed, and the message that proves the refusal was about THIS
# constraint rather than another one. A refusal whose message does not match is VOID.
$cases = @(
    @{ Name = 'baseline'; Expect = 'Created'; Constraint = '(none)'; LastObserved = '2026-09-16'
       Alter = { } }

    @{ Name = 'id-begins-with-digit'; Expect = 'Refused'; Constraint = 'RuleIdPolicy: id must begin with a letter'; LastObserved = '2026-09-16'
       Message = 'Invalid rule identifier'
       Alter = { param($r) $r.id = "5$($r.id.Substring($IdPrefix.Length))" } }

    @{ Name = 'id-prefixed-guid'; Expect = 'Created'; Constraint = 'RuleIdPolicy: a letter prefix on a digit-leading GUID is accepted'; LastObserved = '2026-09-16'
       Alter = { param($r) $r.id = "r-5$($r.id.Substring($IdPrefix.Length))" } }

    @{ Name = 'two-tactics'; Expect = 'Refused'; Constraint = 'TacticConstraints.MaxTactics = 1'; LastObserved = '2026-09-15'
       Message = 'Multiple MITRE tactics|Only one tactic'
       Alter = { param($r) $r.detectionAction.alertTemplate.tactics = @(
            [ordered]@{ tactic = 'Execution'; techniques = @([ordered]@{ technique = 'T1059' }) },
            [ordered]@{ tactic = 'Persistence'; techniques = @([ordered]@{ technique = 'T1547' }) }) } }

    @{ Name = 'tactic-without-technique'; Expect = 'Created'; Constraint = 'TacticConstraints.TechniqueRequiredPerTactic = $false (lifted 2026-09-15)'; LastObserved = '2026-09-15'
       Alter = { param($r) $r.detectionAction.alertTemplate.tactics = @([ordered]@{ tactic = 'Execution'; techniques = @() }) } }

    @{ Name = 'no-tactics-no-category'; Expect = 'Created'; Constraint = "RequiredAlertTemplateFields: 'tactics' entry removed 2026-09-15"; LastObserved = '2026-09-15'
       Alter = { param($r) $r.detectionAction.alertTemplate.Remove('tactics') } }

    @{ Name = 'flat-subtechnique-list'; Expect = 'Created'; Constraint = 'TechniqueShape: stored as {technique, subTechniques[]}'; LastObserved = '2026-09-15'
       ReadBack = 'detectionAction.alertTemplate.tactics'
       Alter = { param($r) $r.detectionAction.alertTemplate.tactics = @([ordered]@{ tactic = 'Execution'; techniques = @(
            [ordered]@{ technique = 'T1059' }, [ordered]@{ technique = 'T1059.001' }) }) } }

    # The round trip on 2026-09-16 stored one of two techniques sent under one tactic:
    # [T1003 + T1003.001] kept, T1547 (a Persistence technique) dropped from CredentialAccess.
    # Two cases separate 'only one technique per tactic' from 'only techniques that belong
    # to the tactic'. Both Created; what matters is the stored: line.
    @{ Name = 'two-techniques-same-tactic'; Expect = 'Created'; Constraint = 'techniques per tactic: are two kept when both belong to the tactic?'; LastObserved = '2026-09-16'
       ReadBack = 'detectionAction.alertTemplate.tactics'
       Alter = { param($r) $r.detectionAction.alertTemplate.tactics = @([ordered]@{ tactic = 'Execution'; techniques = @(
            [ordered]@{ technique = 'T1059' }, [ordered]@{ technique = 'T1047' }) }) } }

    @{ Name = 'technique-of-another-tactic'; Expect = 'Created'; Constraint = 'techniques per tactic: is a technique from another tactic kept?'; LastObserved = '2026-09-16'
       ReadBack = 'detectionAction.alertTemplate.tactics'
       Alter = { param($r) $r.detectionAction.alertTemplate.tactics = @([ordered]@{ tactic = 'Execution'; techniques = @(
            [ordered]@{ technique = 'T1059' }, [ordered]@{ technique = 'T1547' }) }) } }

    @{ Name = 'entity-mappings-absent'; Expect = 'Refused'; Constraint = 'RequiredAlertTemplateFields: entityMappings (EntityMappingsMissing)'; LastObserved = '2026-09-16'
       Message = 'impactedAssets or entityMappings'
       Alter = { param($r) $r.detectionAction.alertTemplate.Remove('entityMappings') } }

    @{ Name = 'entity-mappings-empty-object'; Expect = 'Refused'; Constraint = 'RequiredAlertTemplateFields: empty object counts as absent'; LastObserved = '2026-08-19'
       Message = 'impactedAssets or entityMappings'
       Alter = { param($r) $r.detectionAction.alertTemplate.entityMappings = [ordered]@{} } }

    @{ Name = 'file-only-no-asset'; Expect = 'Refused'; Constraint = 'RequiredEntityKinds (AssetEntityMissing)'; LastObserved = '2026-09-16'
       Message = 'asset entity'
       Alter = { param($r) $r.detectionAction.alertTemplate.entityMappings = [ordered]@{ files = @([ordered]@{ sha256Column = 'SHA256' }) } } }

    @{ Name = 'account-name-only'; Expect = 'Refused'; Constraint = 'EntityIdentifierRequirements.accounts (EntityIdentifierWeak)'; LastObserved = '2026-09-16'
       Message = "Entity mapping for 'User'"
       Alter = { param($r) $r.detectionAction.alertTemplate.entityMappings['accounts'] = @([ordered]@{ nameColumn = 'AccountName' }) } }

    @{ Name = 'account-name-ntdomain'; Expect = 'Created'; Constraint = 'EntityIdentifierRequirements.accounts: nameColumn + ntDomainColumn'; LastObserved = '2026-09-15'
       Alter = { param($r) $r.detectionAction.alertTemplate.entityMappings['accounts'] = @([ordered]@{ nameColumn = 'AccountName'; ntDomainColumn = 'AccountDomain' }) } }

    @{ Name = 'host-netbios-only'; Expect = 'Refused'; Constraint = 'EntityIdentifierRequirements.hosts: netBiosNameColumn alone refused'; LastObserved = '2026-09-15'
       Message = "Entity mapping for 'Machine'"
       Alter = { param($r) $r.detectionAction.alertTemplate.entityMappings = [ordered]@{ hosts = @([ordered]@{ netBiosNameColumn = 'DeviceName' }) } } }

    @{ Name = 'registry-key-and-value-one-entry'; Expect = 'Created'; Constraint = 'EntityIdentifierRequirements.registryValues: keyColumn + valueNameColumn'; LastObserved = '2026-09-15'
       Alter = { param($r) $r.detectionAction.alertTemplate.entityMappings['registryValues'] = @([ordered]@{ keyColumn = 'RegistryKeyX'; valueNameColumn = 'RegistryValueNameX' }) } }

    @{ Name = 'column-not-projected'; Expect = 'Refused'; Constraint = 'constraint 5: columns must be projected by the query output (not checked offline)'; LastObserved = '2026-08-24'
       Message = 'not projected'
       Alter = { param($r) $r.detectionAction.alertTemplate.entityMappings['ips'] = @([ordered]@{ addressColumn = 'ColumnThatDoesNotExist' }) } }

    @{ Name = 'query-unknown-function'; Expect = 'Refused'; Constraint = 'KQL is validated at POST (round trip 2026-09-16, sample 22)'; LastObserved = '2026-09-16'
       Message = 'Unknown function|semantic error'
       Alter = { param($r) $r.queryCondition.queryText = "_MyOrgDeviceBaseline() | take 1 | extend DeviceName = 'x'" } }

    @{ Name = 'query-workspace-operator'; Expect = 'Refused'; Constraint = 'KQL is validated at POST (round trip 2026-09-16, sample 21)'; LastObserved = '2026-09-16'
       Message = 'syntax|semantic'
       Alter = { param($r) $r.queryCondition.queryText = "DeviceLogonEvents | join kind=inner (workspace('other').SecurityEvent) on `$left.DeviceName == `$right.Computer | project DeviceName" } }
)

$results = [System.Collections.Generic.List[object]]::new()
$created = [System.Collections.Generic.List[string]]::new()
$probeInvalid = $false

try {
    foreach ($case in $cases) {
        if ($probeInvalid) { break }
        $rule = Get-BaselineRule -Name $case.Name
        & $case.Alter $rule

        $status = 'Unknown'; $message = ''
        try {
            $result = $rule | New-XDRCustomDetection -Force -ErrorAction SilentlyContinue -ErrorVariable probeError
            $status = if ($result) { [string]$result.Status } else { 'NoResult' }
            $message = if ($result) { [string]$result.Error } else { ($probeError -join ' ') }
            if ($status -eq 'Created') { $created.Add([string]$rule.id) }
        } catch { $status = 'Threw'; $message = $_.Exception.Message }

        $apiMessage = ''
        if ($message -match '"message"\s*:\s*"([^"]+)"') { $apiMessage = $Matches[1] }
        $reachedTheApi = ($status -eq 'Created') -or ($message -match 'failed with HTTP \d+')

        $observed = if ($status -eq 'Created') { 'Created' } elseif ($reachedTheApi) { 'Refused' } else { 'ScriptError' }

        $outcome = if ($observed -eq 'ScriptError') { 'ScriptError' }
                   elseif ($observed -ne $case.Expect) { 'CHANGED' }
                   elseif ($observed -eq 'Refused' -and $case.Message -and $apiMessage -notmatch $case.Message) { 'VOID' }
                   else { 'AsExpected' }

        $stored = ''
        if ($status -eq 'Created' -and $case.ReadBack) {
            try {
                $back = Get-XDRCustomDetection -Id $rule.id -ErrorAction Stop
                $node = $back
                foreach ($segment in $case.ReadBack.Split('.')) { $node = $node.$segment }
                $stored = ($node | ConvertTo-Json -Compress -Depth 6)
            } catch { $stored = "read-back failed: $($_.Exception.Message)" }
        }

        $colour = switch ($outcome) { 'AsExpected' { 'Green' } 'VOID' { 'Yellow' } 'ScriptError' { 'Red' } default { 'Magenta' } }
        Write-Host ("{0,-11} {1,-34} expected {2,-8} got {3}" -f $outcome, $case.Name, $case.Expect, $observed) -ForegroundColor $colour
        if ($apiMessage) { Write-Host "            $apiMessage" -ForegroundColor DarkGray }
        if ($stored)     { Write-Host "            stored: $stored" -ForegroundColor DarkGray }

        # If the baseline itself is refused, every later case would fail for the same
        # reason and read as CHANGED. That is the probe being wrong, not the API moving.
        if ($case.Name -eq 'baseline' -and $observed -ne 'Created') {
            $probeInvalid = $true
            Write-Host "`nTHE BASELINE WAS REFUSED. The probe is invalid; nothing below it was run. Fix the baseline rule first: $apiMessage" -ForegroundColor Red
        }

        $results.Add([PSCustomObject]@{
            Case = $case.Name; Constraint = $case.Constraint; LastObserved = $case.LastObserved
            Expected = $case.Expect; Observed = $observed; Outcome = $outcome
            ApiMessage = $apiMessage; Stored = $stored; Id = $rule.id
            Detail = $(if ($observed -eq 'ScriptError') { $message } else { '' })
        })
    }
}
finally {
    # Cleanup runs even on Ctrl+C. DELETE is asynchronous on this API: it returns 2xx with
    # the rule still readable, and the list endpoint lags for a day. So each id is read back
    # individually until it answers 404 or 90 seconds pass, and the time is recorded -
    # that number is itself a measurement worth having.
    $deletion = [System.Collections.Generic.List[object]]::new()
    if ($created.Count -gt 0) {
        Write-Host "`nCleaning up $($created.Count) probe rule(s)..." -ForegroundColor Cyan
        $failed = [System.Collections.Generic.List[string]]::new()
        foreach ($id in $created) {
            try { Remove-XDRCustomDetection -Id $id -Confirm:$false -ErrorAction Stop | Out-Null }
            catch { $failed.Add($id); Write-Warning "Could not delete '$id': $($_.Exception.Message)" }
        }
        # A second DELETE answering 404 shows the delete was TAKEN. Nothing callable shows it
        # completed: GET and the portal keep the rule for hours (measured 2026-09-16).
        $unconfirmed = [System.Collections.Generic.List[string]]::new()
        foreach ($id in $created) {
            if ($failed.Contains($id)) { continue }
            $second = Remove-XDRCustomDetection -Id $id -Confirm:$false -ErrorAction SilentlyContinue
            $gone = ($second.Status -eq 'Failed' -and [string]$second.Error -match 'HTTP 404')
            $readable = $true
            try { Get-XDRCustomDetection -Id $id -ErrorAction Stop | Out-Null } catch { $readable = -not ($_.Exception.Message -match 'HTTP 404') }
            $deletion.Add([PSCustomObject]@{ Id = $id; ConfirmedBySecondDelete = $gone; StillReadable = $readable })
            if (-not $gone) { $unconfirmed.Add($id) }
        }
        if ($failed.Count -gt 0) {
            Write-Warning "$($failed.Count) detection(s) could not be deleted and remain in the tenant: $($failed -join ', ')"
        } elseif ($unconfirmed.Count -gt 0) {
            Write-Host ("Delete taken for most; {0} did not answer 404 to a second DELETE - re-check in the portal: {1}" -f $unconfirmed.Count, ($unconfirmed -join ', ')) -ForegroundColor Yellow
        } else {
            Write-Host "Delete taken by the service for all $($created.Count) probe rule(s). Completion takes hours; the portal will show them until then." -ForegroundColor Yellow
        }
        $lagging = @($deletion | Where-Object StillReadable).Count
        if ($lagging -gt 0) {
            Write-Host "$lagging of $($deletion.Count) rule(s) whose delete was taken are still returned by GET." -ForegroundColor DarkGray
        }
    }
}

Write-Host "`n==== What the API enforces today ($(Get-Date -Format yyyy-MM-dd)) ====" -ForegroundColor Cyan
$results | Format-Table Outcome, Case, Expected, Observed, LastObserved -AutoSize | Out-Host

$changed = @($results | Where-Object Outcome -eq 'CHANGED')
$void    = @($results | Where-Object Outcome -eq 'VOID')
$errors  = @($results | Where-Object Outcome -eq 'ScriptError')
if ($errors.Count -gt 0) {
    Write-Host "$($errors.Count) case(s) never reached the API. THIS RUN PROVED NOTHING for them:" -ForegroundColor Red
    $errors | ForEach-Object { Write-Host "  $($_.Case): $($_.Detail)" -ForegroundColor Red }
}
if ($probeInvalid) {
    Write-Host 'THIS RUN PROVED NOTHING: the baseline rule was refused, so no case was valid.' -ForegroundColor Red
}
elseif ($changed.Count -gt 0) {
    Write-Host "$($changed.Count) constraint(s) CHANGED since last observed. Each one is a data edit in src/Data/GraphDetectionRule.psd1, today:" -ForegroundColor Magenta
    $changed | ForEach-Object { Write-Host "  $($_.Case) - $($_.Constraint) (last observed $($_.LastObserved)): $($_.ApiMessage)" -ForegroundColor Magenta }
}
if ($void.Count -gt 0) {
    Write-Host "$($void.Count) case(s) VOID - refused for a reason other than the one under test. Fix the probe; do not record them:" -ForegroundColor Yellow
    $void | ForEach-Object { Write-Host "  $($_.Case): $($_.ApiMessage)" -ForegroundColor Yellow }
}
if ($changed.Count -eq 0 -and $void.Count -eq 0 -and $errors.Count -eq 0) {
    Write-Host 'Every constraint in the data file behaves as recorded. Stamp LastConfirmed with today''s date.' -ForegroundColor Green
}

if ($ReportPath) {
    $results | Export-Csv -LiteralPath $ReportPath -NoTypeInformation -Encoding utf8
    Write-Host "`nPer-case CSV: $ReportPath" -ForegroundColor DarkGray
}

$results
