<#
.SYNOPSIS
    Proves converted detections survive a real deployment, against a DEVELOPMENT tenant.

.DESCRIPTION
    The strongest validation available, and the only one that writes: for each rule it
    creates the detection, reads it back, compares what the service stored against what we
    sent, and deletes it again.

    That round trip answers three questions nothing else can:

      1. Does the API accept our payload at all? A 400 means the shape is wrong, and the
         error body names the property.
      2. Does the service keep what we sent? A field that comes back changed or absent was
         silently ignored, which is worse than a rejection because the detection looks
         deployed and behaves differently.
      3. Are Blocked rules genuinely impossible? With -IncludeBlocked they are actually
         SENT, as the minimal payload the converter would have produced, so the refusal is
         tested rather than assumed. Refused by both = BlockedConfirmed. Accepted by the
         API = BlockedButAccepted, meaning the module is refusing rules the product would
         take, which is the most valuable thing this script can find.

    Outcomes, per rule:
      Verified          created, read back identical, re-applied over itself (the update path)
      StoredWithDrift   created, but the service stored something other than what was sent
      UpdateFailed      created and stored, but the second run (PATCH) failed
      RefusalPredicted  refused, and the assessment said it would be - an API-constraint
                        finding or a query-dependency Warning. The verdict holding.
      ReviewConfirmed   refused on 'Unknown function' after a Review that said 'confirm this
                        function resolves'. The Review holding; not deployable as written.
      Rejected          refused, and nothing in the assessment predicted it. A module bug
                        if the verdict was Ready.
      BlockedConfirmed  -IncludeBlocked: refused by the module and by the API
      BlockedButAccepted -IncludeBlocked: refused by the module, accepted by the API
      ScriptError       never reached the API. Says nothing about the module.
      WhatIf            dry run

    This is deliberately a script rather than a shipped cmdlet. It writes to a tenant, and
    that should be a decision you make by running a file out of the tests folder, not
    something reachable by tab-completing the module.

    SAFETY
      - Every rule is created DISABLED. Nothing you create here can fire an alert.
      - Every created id is prefixed (default 's2x-validation-') so it is obvious in the
         portal what these are and where they came from.
      - Cleanup runs in a finally block, so it happens even on Ctrl+C or a mid-run failure.
         -KeepDetections skips it when you want to inspect the results in the portal.
      - -WhatIf shows the whole plan without sending anything.
      - Refuses to run without -ConfirmDevelopmentTenant, so it cannot be pointed at
         production by muscle memory.

.PARAMETER Path
    Folder or file of Sentinel analytics rules to validate.

.PARAMETER Recurse
    Search subfolders.

.PARAMETER AccessToken
    Graph bearer token with CustomDetection.ReadWrite.All. Falls back to an Az context.

.PARAMETER First
    Validate only the first N rules. Start small.

.PARAMETER IdPrefix
    Prefix for the detection ids created. Default 's2x-validation-'.

.PARAMETER IncludeBlocked
    Also attempt the rules the module refused, to confirm the API refuses them too.

.PARAMETER KeepDetections
    Skip cleanup and leave the detections in the tenant for inspection.

.PARAMETER ConfirmDevelopmentTenant
    Required. Asserts you are pointing this at a tenant you are willing to write to.

.PARAMETER ReportPath
    Write the per-rule results to a CSV.

.EXAMPLE
    ./tests/Integration/Invoke-RoundTripValidation.ps1 `
        -Path '~/repos/Azure-Sentinel/Solutions/Microsoft Defender XDR/Analytic Rules' `
        -Recurse -First 5 -ConfirmDevelopmentTenant -WhatIf

    Dry run of the first five rules.

.EXAMPLE
    ./tests/Integration/Invoke-RoundTripValidation.ps1 `
        -Path './Analytic Rules' -Recurse -ConfirmDevelopmentTenant `
        -ReportPath ./roundtrip.csv

    The full stress test, with a report.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory, Position = 0)]
    [string]$Path,

    [Parameter()]
    [switch]$Recurse,

    [Parameter()]
    [AllowNull()]
    [object]$AccessToken,

    [Parameter()]
    [int]$First = 0,

    [Parameter()]
    [string]$IdPrefix = 's2x-validation-',

    [Parameter()]
    [switch]$IncludeBlocked,

    [Parameter()]
    [switch]$KeepDetections,

    [Parameter(Mandatory)]
    [switch]$ConfirmDevelopmentTenant,

    [Parameter()]
    [string]$ReportPath,

    [Parameter()]
    [string]$GraphEndpoint = 'https://graph.microsoft.com/beta'
)

$ErrorActionPreference = 'Stop'
Import-Module -Name (Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'src/SentinelToXDR.psd1') -Force

if (-not $ConfirmDevelopmentTenant) {
    throw 'This script writes detections to a tenant. Pass -ConfirmDevelopmentTenant to acknowledge that.'
}

# Compare what we sent against what came back. Only the fields we actually set are
# compared: the service adds createdBy, timestamps and its own ids, and those are not drift.
function Compare-RoundTrip {
    param([object]$Sent, [object]$Received)

    $differences = [System.Collections.Generic.List[string]]::new()

    function Compare-Node {
        param([object]$A, [object]$B, [string]$NodePath)

        if ($null -eq $A) { return }

        if ($A -is [System.Collections.IDictionary]) {
            foreach ($key in $A.Keys) {
                $childPath = if ($NodePath) { "$NodePath.$key" } else { [string]$key }
                $bValue = $null
                if ($null -ne $B) {
                    $property = $B.PSObject.Properties | Where-Object { $_.Name -ieq [string]$key } | Select-Object -First 1
                    if ($property) { $bValue = $property.Value }
                }
                if ($null -eq $bValue) {
                    $differences.Add("$childPath : sent, not stored")
                    continue
                }
                Compare-Node -A $A[$key] -B $bValue -NodePath $childPath
            }
            return
        }

        if ($A -is [System.Collections.IList] -and $A -isnot [string]) {
            $bList = @($B)
            if ($bList.Count -ne @($A).Count) {
                # Name the values, not just the counts. 'sent 2, stored 1' is where this
                # script stopped being useful on 2026-08-24: it proved the service drops
                # something without saying WHAT, and the answer decided whether the
                # converter could match the behaviour or only report it. A diff that
                # cannot be acted on is only half a diff.
                $describe = {
                    param([object[]]$Items)
                    $rendered = foreach ($item in @($Items)) {
                        if ($item -is [System.Collections.IDictionary]) {
                            (@($item.Keys | ForEach-Object { "$_=$($item[$_])" }) -join ' ')
                        }
                        elseif ($item -is [System.Management.Automation.PSCustomObject]) {
                            (@($item.PSObject.Properties | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join ' ')
                        }
                        else { [string]$item }
                    }
                    if (@($rendered).Count -eq 0) { '(none)' } else { '[' + (@($rendered) -join '] [') + ']' }
                }
                $differences.Add("$NodePath : sent $(@($A).Count) item(s) $(& $describe @($A)); " +
                    "stored $($bList.Count) $(& $describe $bList)")
                return
            }
            for ($i = 0; $i -lt @($A).Count; $i++) {
                Compare-Node -A @($A)[$i] -B $bList[$i] -NodePath "$NodePath[$i]"
            }
            return
        }

        # Scalar. KQL round-trips through JSON, so normalize line endings before comparing.
        $aText = ([string]$A) -replace "`r`n", "`n"
        $bText = ([string]$B) -replace "`r`n", "`n"
        if ($aText -ne $bText) {
            $shownA = if ($aText.Length -gt 60) { $aText.Substring(0, 60) + '…' } else { $aText }
            $shownB = if ($bText.Length -gt 60) { $bText.Substring(0, 60) + '…' } else { $bText }
            $differences.Add("$NodePath : sent '$shownA', stored '$shownB'")
        }
    }

    Compare-Node -A $Sent -B $Received -NodePath ''
    return $differences
}

Write-Host "Reading and assessing rules from '$Path'..." -ForegroundColor Cyan
$getParams = @{ Path = $Path; PassThruDetection = $true }
if ($Recurse) { $getParams['Recurse'] = $true }

# Assess rather than merely convert. The whole point of the round trip is to check the
# ASSESSMENT against reality, so every result has to carry the verdict it is testing:
# a NeedsWork rule that deploys cleanly is still NeedsWork, and a Ready rule the API
# rejects is the finding that matters most.
$assessed = @(Test-XDRMigrationReadiness @getParams -WarningAction SilentlyContinue)
if ($First -gt 0) { $assessed = @($assessed | Select-Object -First $First) }

$candidates = if ($IncludeBlocked) { $assessed } else { @($assessed | Where-Object { $_.Verdict -ne 'Blocked' }) }
$blockedCount = @($assessed | Where-Object { $_.Verdict -eq 'Blocked' }).Count

Write-Host ("$($assessed.Count) rule(s) assessed: " +
    (@('Ready', 'Review', 'NeedsWork', 'Blocked') |
        ForEach-Object { "$_ $(@($assessed | Where-Object Verdict -eq $_).Count)" }) -join ', ') -ForegroundColor Cyan
Write-Host ("$($candidates.Count) to deploy, $blockedCount blocked by the module" +
    $(if ($IncludeBlocked) { ' (attempting them anyway to confirm the API agrees)' } else { ' (skipped)' })) -ForegroundColor Cyan

$results = [System.Collections.Generic.List[object]]::new()
$created = [System.Collections.Generic.List[string]]::new()

try {
    foreach ($assessment in $candidates) {
        $detection = $assessment.Detection
        $wasBlocked = $assessment.Verdict -eq 'Blocked'

        # Did the assessment specifically predict the service would refuse this rule?
        # That is a different claim from 'this needs work', and a rejection confirms it
        # rather than contradicting it. See docs/API-Constraints.md.
        #
        # Two kinds of finding predict a refusal. The API-constraint findings (no entity
        # mapping, weak identifier, no asset entity) are the obvious ones. The other is a
        # query-dependency Warning - watchlist, ASIM parser, externaldata, workspace() -
        # because POST validates the KQL and refuses a query that cannot resolve. On
        # 2026-09-16 sample 21 (workspace operator) was refused with 'The query contains
        # syntax errors' and this script filed it under 'the module believed these were
        # convertible'. It did not: it had graded the rule NeedsWork for exactly that reason.
        $diagnostics = @($detection.Diagnostics)
        $predictedRefusal = (@($assessment.Findings |
                Where-Object { $_.Capability -eq 'Custom detection API requirements' }).Count -gt 0) -or
            (@($diagnostics | Where-Object { $_.Feature -eq 'Rule query' -and $_.Severity -eq 'Warning' }).Count -gt 0)

        # The saved-function heuristic is an Info finding graded Review: 'may call a
        # workspace-saved function; confirm it resolves'. When the API then answers
        # 'Unknown function', the module said confirm and the service said no. That is not
        # a false green and it is not a prediction either - it is the Review holding.
        $reviewOnQuery = (@($diagnostics | Where-Object { $_.Feature -eq 'Rule query' -and $_.Severity -eq 'Info' }).Count -gt 0)

        # A duplicate id in the batch predicts exactly one thing: a 409 on the second POST.
        # On 2026-09-16 sample 35 did precisely that and was filed as Rejected.
        $duplicateId = (@($diagnostics | Where-Object { $_.TargetValue -eq 'DuplicateId' }).Count -gt 0)
        $ruleName = [string]$assessment.RuleName
        $verdict = [string]$assessment.Verdict

        if ($wasBlocked -and -not $IncludeBlocked) { continue }

        $validationId = "$IdPrefix$($assessment.Id)"
        $payload = [ordered]@{}

        if ($wasBlocked) {
            # The module refused this rule. That refusal is a CLAIM, and the only way to
            # test it is to ask the API. A blocked rule has no converted payload, so build
            # the minimal one the converter would have produced had it not refused —
            # typically with an empty query, which is exactly why it was refused.
            #
            # A rejection confirms the claim. An ACCEPTANCE means the Blocked verdict is
            # wrong and the module is refusing rules the product would take, which is the
            # most valuable thing this script can find.
            $source = $assessment.SourceRule
            $validationId = "$IdPrefix" + $(if ($assessment.Id) { $assessment.Id } else { [guid]::NewGuid().ToString() })
            $payload['id'] = $validationId
            $payload['displayName'] = $ruleName
            $payload['description'] = [string]$source.Description
            $payload['status'] = 'disabled'
            $payload['queryCondition'] = [ordered]@{ queryText = [string]$source.Query }
            $payload['schedule'] = [ordered]@{ frequency = 'PT1H' }
        } else {
            # Copy the converted payload and give it a clearly-marked validation id.
            foreach ($key in $detection.Rule.Keys) { $payload[$key] = $detection.Rule[$key] }
            $payload['id'] = $validationId
            $payload['status'] = 'disabled'
        }

        if (-not $PSCmdlet.ShouldProcess("$ruleName (as $validationId)", 'Create, read back, compare, delete')) {
            $results.Add([PSCustomObject]@{
                RuleName = $ruleName; Id = $validationId; ModuleVerdict = $verdict
                Created = $false; ReadBack = $false; Updated = $false; Drift = 0; Outcome = 'WhatIf'; Detail = ''
            })
            continue
        }

        $outcome = 'Unknown'
        $detail  = ''
        $didCreate = $false
        $didRead = $false
        $didUpdate = $false
        $updateError = ''
        $drift = @()

        try {
            # Deploy through the PUBLIC cmdlet, not the private request helper. Two reasons,
            # and the first one bit on the very first live run: Invoke-S2XRestRequest is not
            # exported, so calling it from script scope fails before any HTTP request is
            # made — and -WhatIf never reaches this line, so the dry run looked perfect.
            #
            # The better reason is that this script exists to validate the path a USER
            # takes. Reaching past New-XDRCustomDetection into the transport would have
            # validated a code path nobody runs, and would have missed the id-in-PATCH-body
            # bug entirely.
            $createResult = New-XDRCustomDetection -Detection $payload -Force `
                -AccessToken $AccessToken -GraphEndpoint $GraphEndpoint -ErrorAction Stop
            if ($createResult.Status -ne 'Created') {
                throw "New-XDRCustomDetection returned '$($createResult.Status)': $($createResult.Error)"
            }
            $didCreate = $true
            $created.Add($validationId)

            $stored = Get-XDRCustomDetection -Id $validationId -AccessToken $AccessToken -GraphEndpoint $GraphEndpoint
            $didRead = $true

            # Re-apply the same rule over itself. This is the SECOND run of a migration —
            # the update path — and it is the one that matters, because the first run of
            # anything gets tested by hand and the second one gets trusted.
            #
            # It is also a different request from the create: PATCH accepts a closed set of
            # properties, so a module that PATCHes the whole object (id and all) creates
            # perfectly and fails to update. That failure is invisible to a create-only
            # round trip, which is how it survived until 1.0.0.
            if (-not $wasBlocked) {
                try {
                    $updateResult = Set-XDRCustomDetection -Detection $stored -Id $validationId `
                        -AccessToken $AccessToken -GraphEndpoint $GraphEndpoint -Force
                    $didUpdate = ($updateResult.Status -eq 'Updated')
                    if (-not $didUpdate) { $updateError = [string]$updateResult.Error }
                } catch {
                    $didUpdate = $false
                    $updateError = $_.Exception.Message
                }
            }

            if ($wasBlocked) {
                # The module said this was impossible and the API took it anyway.
                $outcome = 'BlockedButAccepted'
                $detail = 'The API accepted a rule the module refused. The Blocked verdict is wrong.'
                Write-Host ("  [BlockedButAccepted] {0} — the module was wrong to refuse this" -f $ruleName) -ForegroundColor Magenta
            } else {
                $drift = Compare-RoundTrip -Sent $payload -Received $stored
                $outcome = if ($drift.Count -eq 0) { 'Verified' } else { 'StoredWithDrift' }
                $detail = ($drift -join ' | ')

                # A rule that creates but cannot be updated is not verified. Say so, and
                # keep the reason: this is the failure the create-only round trip missed.
                if (-not $didUpdate) {
                    $outcome = 'UpdateFailed'
                    $detail = "Created and stored, but the update re-apply failed: $updateError"
                }

                Write-Host ("  [{0}] {1} ({2})" -f $outcome, $ruleName, $verdict) -ForegroundColor $(
                    if ($outcome -eq 'UpdateFailed') { 'Red' } elseif ($drift.Count -eq 0) { 'Green' } else { 'Yellow' })
            }
        } catch {
            $detail = $_.Exception.Message

            # Did this failure ever reach the wire? Every HTTP failure from this module
            # carries "failed with HTTP <code>". Anything else — a missing command, a bad
            # parameter, a typo in this script — happened locally, and calling that a
            # rejection is a lie with consequences: the first live run reported
            # "6 rules the assessment called READY were rejected... that is an assessment
            # bug", when the API had never been contacted and nothing had been created.
            # A validation script that misreports its own failure as a module failure is
            # worse than no validation script.
            $reachedTheApi = $detail -match 'failed with HTTP \d+'

            if (-not $reachedTheApi) {
                $outcome = 'ScriptError'
                $detail = "This never reached the API: $detail"
                Write-Host ("  [ScriptError] {0} — failed locally, before any request was made" -f $ruleName) -ForegroundColor Red
            }
            elseif ($wasBlocked) {
                # Refused by both the module and the API: the claim holds.
                $outcome = 'BlockedConfirmed'
                Write-Host ("  [BlockedConfirmed] {0} — the API refuses it too" -f $ruleName) -ForegroundColor Green
            }
            elseif ($duplicateId -and $detail -match 'HTTP 409') {
                $outcome = 'RefusalPredicted'
                Write-Host ("  [RefusalPredicted] {0} ({1}) — 409 on a duplicate id, exactly as the assessment said" -f $ruleName, $verdict) -ForegroundColor Green
            }
            elseif ($predictedRefusal) {
                # The module said this exact thing would happen. A rejection here is the
                # assessment being RIGHT, and lumping it in with Rejected would file four
                # correct predictions under 'the module believed these were convertible' -
                # the report reading worse than the truth is the same failure as it reading
                # better, and this script exists to be believed.
                $outcome = 'RefusalPredicted'
                Write-Host ("  [RefusalPredicted] {0} ({1}) — refused, exactly as the assessment said" -f $ruleName, $verdict) -ForegroundColor Green
            }
            elseif ($reviewOnQuery -and $verdict -eq 'Review' -and $detail -match 'Unknown function|semantic error') {
                $outcome = 'ReviewConfirmed'
                Write-Host ("  [ReviewConfirmed] {0} — the module said 'confirm this function resolves'; the API says it does not" -f $ruleName) -ForegroundColor Yellow
            } else {
                $outcome = 'Rejected'
                Write-Host ("  [Rejected] {0} ({1}): {2}" -f $ruleName, $verdict, $detail) -ForegroundColor Red
            }
        }

        $results.Add([PSCustomObject]@{
            RuleName = $ruleName; Id = $validationId; ModuleVerdict = $verdict
            Created = $didCreate; ReadBack = $didRead; Updated = $didUpdate; Drift = $drift.Count
            Outcome = $outcome; Detail = $detail
        })
    }
}
finally {
    # Cleanup runs even on Ctrl+C or an unhandled failure. Leaving detections behind in a
    # tenant is the one outcome this script must never produce by accident.
    if ($created.Count -gt 0 -and -not $KeepDetections) {
        Write-Host "`nCleaning up $($created.Count) detection(s)..." -ForegroundColor Cyan
        $failedCleanup = [System.Collections.Generic.List[string]]::new()
        foreach ($id in $created) {
            try {
                $removal = Remove-XDRCustomDetection -Id $id -Confirm:$false `
                    -AccessToken $AccessToken -GraphEndpoint $GraphEndpoint -ErrorAction Stop
                if ($removal.Status -ne 'Deleted') {
                    throw "Remove-XDRCustomDetection returned '$($removal.Status)': $($removal.Error)"
                }
            } catch {
                $failedCleanup.Add($id)
                Write-Warning "Could not delete '$id': $($_.Exception.Message)"
            }
        }
        # A successful DELETE is not evidence of deletion - but neither is a read-back.
        #
        # What the tenant actually does (measured 2026-09-15 and again 2026-09-16): DELETE
        # returns 2xx; GET and the list endpoint keep serving the rule for HOURS (five ids
        # spot-checked 70+ minutes after their DELETE were all still readable); and a SECOND
        # DELETE on the same id answers 404. The write path has applied the delete, the read
        # path lags. So the read-back poll that replaced 'Cleanup complete' on 2026-09-15
        # could never confirm anything inside its 90 seconds, and it said 'unconfirmed' on
        # every run.
        #
        # A second DELETE answers 404, which shows the service has TAKEN the delete - and
        # that is all it shows. On 2026-09-16 the portal listed all 30 rules of a run whose
        # every second DELETE had answered 404, and GET by id still returned them; the day
        # before, 33 such rules were gone by the next morning. Deletion here completes on
        # a scale of hours and NOTHING callable in this session observes it. So this
        # script reports three honest states: the DELETE was refused; the DELETE was taken
        # (second DELETE 404); and how many the read path still serves. It never says
        # 'clean'. Check the portal later, or delete there if you need it clean now.
        $confirmed = [System.Collections.Generic.List[string]]::new()
        $unconfirmed = [System.Collections.Generic.List[string]]::new()
        foreach ($id in $created) {
            if ($failedCleanup.Contains($id)) { continue }
            $second = Remove-XDRCustomDetection -Id $id -Confirm:$false -AccessToken $AccessToken -GraphEndpoint $GraphEndpoint -ErrorAction SilentlyContinue
            if ($second.Status -eq 'Failed' -and [string]$second.Error -match 'HTTP 404') { $confirmed.Add($id) }
            else { $unconfirmed.Add($id) }
        }
        $stillReadable = 0
        foreach ($id in $confirmed) {
            try { Get-XDRCustomDetection -Id $id -AccessToken $AccessToken -GraphEndpoint $GraphEndpoint -ErrorAction Stop | Out-Null; $stillReadable++ }
            catch { }
        }

        if ($unconfirmed.Count -gt 0) {
            Write-Warning ("$($unconfirmed.Count) detection(s) did not answer 404 to a second DELETE, so the service may not have taken the delete: " +
                ($unconfirmed -join ', '))
        }
        if ($stillReadable -gt 0) {
            Write-Host ("$stillReadable of $($confirmed.Count) detection(s) whose delete was taken are still returned by GET, and the portal will show them too. " +
                'Deletion completes hours later; verify in the portal tomorrow, or delete them there now.') -ForegroundColor Yellow
        }

        if ($failedCleanup.Count -gt 0) {
            Write-Warning ("$($failedCleanup.Count) detection(s) remain in the tenant and need removing by hand: " +
                ($failedCleanup -join ', '))
        } elseif ($unconfirmed.Count -gt 0) {
            Write-Host "Delete taken for most detections; $($unconfirmed.Count) not confirmed taken. Re-check in the portal." -ForegroundColor Yellow
        } else {
            Write-Host "Delete taken by the service for all $($confirmed.Count) detection(s) (second DELETE answers 404). Completion is asynchronous and can take hours; the tenant is NOT yet clean to look at." -ForegroundColor Yellow
        }
    } elseif ($created.Count -gt 0) {
        Write-Warning ("-KeepDetections was set: $($created.Count) DISABLED detection(s) remain in the tenant, " +
            "all prefixed '$IdPrefix'. Remove them with: " +
            "Get-XDRCustomDetection | Where-Object { `$_.id -like '$IdPrefix*' } | Remove-XDRCustomDetection")
    }
}

# ---------------------------------------------------------------------------------
# Summary.
#
# Everything below goes to the HOST, not the pipeline. Format-Table emits formatting
# objects into the output stream, so piping it normally would mix those with the
# results this script returns — which renders as an empty table and hands the caller
# 20 objects when 15 rules were tested.
# ---------------------------------------------------------------------------------
Write-Host "`n==== Round-trip validation ====" -ForegroundColor Cyan

$results |
    Group-Object Outcome |
    Sort-Object Count -Descending |
    Format-Table @{ N = 'Outcome'; E = { $_.Name } }, Count -AutoSize |
    Out-Host

# The cross-tab is the point of the exercise: it answers "did anything we called Ready
# get rejected?" in one glance.
Write-Host 'Assessment verdict against what the API actually did:' -ForegroundColor Cyan
$outcomes = @($results.Outcome | Sort-Object -Unique)
$crossTab = foreach ($verdict in @('Ready', 'Review', 'NeedsWork', 'Blocked')) {
    $forVerdict = @($results | Where-Object ModuleVerdict -eq $verdict)
    if ($forVerdict.Count -eq 0) { continue }
    $row = [ordered]@{ Verdict = $verdict }
    foreach ($outcome in $outcomes) {
        $row[$outcome] = @($forVerdict | Where-Object Outcome -eq $outcome).Count
    }
    [PSCustomObject]$row
}
$crossTab | Format-Table -AutoSize | Out-Host

# A script error is not a finding about the module, and reporting it as one sends the
# reader hunting for a conversion bug that does not exist. It comes first and loudly,
# because every other number below it is meaningless until it is fixed.
$scriptErrors = @($results | Where-Object Outcome -eq 'ScriptError')
if ($scriptErrors.Count -gt 0) {
    Write-Host ("`nTHIS RUN PROVED NOTHING: $($scriptErrors.Count) rule(s) failed before reaching the API.") -ForegroundColor Red
    Write-Host '  Nothing was created, so the tenant is unchanged. Fix the script and re-run.' -ForegroundColor Red
    Write-Host ("  First failure: {0}" -f $scriptErrors[0].Detail) -ForegroundColor Red
}

$predicted = @($results | Where-Object Outcome -eq 'RefusalPredicted')
if ($predicted.Count -gt 0) {
    Write-Host ("$($predicted.Count) rule(s) were refused exactly as the assessment predicted:") -ForegroundColor Green
    foreach ($row in $predicted) {
        Write-Host ("  {0} [{1}]" -f $row.RuleName, $row.ModuleVerdict) -ForegroundColor Green
    }
    Write-Host '  These are the undocumented API constraints. A refusal here is the verdict holding.' -ForegroundColor DarkGray
    Write-Host ''
}

$reviewConfirmed = @($results | Where-Object Outcome -eq 'ReviewConfirmed')
if ($reviewConfirmed.Count -gt 0) {
    Write-Host ("$($reviewConfirmed.Count) Review verdict(s) settled by the API: the query calls something this tenant does not have.") -ForegroundColor Yellow
    foreach ($row in $reviewConfirmed) { Write-Host ("  {0}" -f $row.RuleName) -ForegroundColor Yellow }
    Write-Host '  The module asked you to confirm the function resolves. It does not, here. Not a module bug; not deployable as written.' -ForegroundColor DarkGray
    Write-Host ''
}

$rejected = @($results | Where-Object Outcome -eq 'Rejected')
if ($rejected.Count -gt 0) {
    Write-Host "Rejected by the API (the module believed these were convertible):" -ForegroundColor Red
    foreach ($row in $rejected) {
        Write-Host ("  {0} [{1}]" -f $row.RuleName, $row.ModuleVerdict) -ForegroundColor Red
        Write-Host ("    {0}" -f $row.Detail)
    }
    $readyRejected = @($rejected | Where-Object ModuleVerdict -eq 'Ready')
    if ($readyRejected.Count -gt 0) {
        Write-Host ("`n  $($readyRejected.Count) rule(s) the assessment called READY were rejected. " +
            'That is an assessment bug, not a tenant problem.') -ForegroundColor Red
    }
}

$drifted = @($results | Where-Object Outcome -eq 'StoredWithDrift')
if ($drifted.Count -gt 0) {
    Write-Host "`nStored, but not as sent (the service altered or ignored fields):" -ForegroundColor Yellow
    foreach ($row in $drifted) {
        Write-Host ("  {0} [{1}]" -f $row.RuleName, $row.ModuleVerdict) -ForegroundColor Yellow
        Write-Host ("    {0}" -f $row.Detail)
    }
}

$wronglyBlocked = @($results | Where-Object Outcome -eq 'BlockedButAccepted')
if ($wronglyBlocked.Count -gt 0) {
    Write-Host "`nRefused by the module, ACCEPTED by the API — these Blocked verdicts are wrong:" -ForegroundColor Magenta
    foreach ($row in $wronglyBlocked) { Write-Host ("  {0}" -f $row.RuleName) -ForegroundColor Magenta }
}

$blockedConfirmed = @($results | Where-Object Outcome -eq 'BlockedConfirmed').Count
if ($blockedConfirmed -gt 0) {
    Write-Host "`n$blockedConfirmed Blocked verdict(s) confirmed: the API refuses them too." -ForegroundColor Green
}

$verified = @($results | Where-Object Outcome -eq 'Verified').Count
if ($verified -gt 0) {
    Write-Host "`n$verified rule(s) stored exactly as sent." -ForegroundColor Green
}

if ($ReportPath) {
    $results | Export-Csv -LiteralPath $ReportPath -NoTypeInformation -Encoding utf8
    Write-Host "`nReport written to '$ReportPath'." -ForegroundColor Cyan
}

# The only thing on the pipeline: the per-rule results.
$results
