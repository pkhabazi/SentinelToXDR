<#
.SYNOPSIS
    Round 3. Establishes which entity identifier combinations the service accepts.

.DESCRIPTION
    Round 2 hit "Entity mapping for 'User' is invalid. At least one mandatory field
    combination must have non-empty column values." on a mapping of {nameColumn} alone,
    while rules that deployed successfully carried {nameColumn, sidColumn} and
    {nameColumn, aadUserIdColumn}. Hosts deployed on {nameColumn} alone.

    So each entity type has its own set of SUFFICIENT identifier combinations, and the rule
    is stated in neither the Graph reference nor the product documentation. This module maps
    Sentinel identifiers to Graph columns one at a time with no notion of sufficiency, so a
    Sentinel rule mapping only Account/Name emits a detection the service refuses.

    Every probe below is identical except for its entity mapping, and all carry a valid
    single tactic with one technique so nothing else can confound the result.

    ROUND 4. Round 3 was confounded and four of its thirteen results were worthless. Two
    constraints nobody knew about at the time reached the probes first:

      - every entity mapping column must be PROJECTED by the query output, and the query
        was 'DeviceProcessEvents | take 1', which has no AccountUpnSuffix, no RemoteIP, no
        RecipientEmailAddress and no Url;
      - at least one asset entity (Machine, User, Mailbox) or an IP must be present, which
        a lone urls mapping is not.

    So four cases were refused for reasons that had nothing to do with the identifiers
    under test, and reading them as identifier failures would have put four wrong entries
    in the data file. That is the same lesson as round 1, learned twice: A PROBE MUST BE
    VALID IN EVERY RESPECT EXCEPT THE ONE UNDER TEST.

    Both confounds are now removed by construction. Every column the cases use is
    synthesised with 'extend' so it is always projected whatever the table holds, and
    every case carries a hosts mapping - confirmed accepted on its own - so the asset
    requirement is always satisfied. Entities are validated individually, so the baseline
    host does not rescue a bad mapping of another type.

    Everything is created disabled and prefixed 's2x-ent-'. Cleanup runs in a finally block.
#>
$ErrorActionPreference = 'Continue'

if (-not (Get-Module -Name SentinelToXDR)) {
    Import-Module -Name (Join-Path $PSScriptRoot '../../../src/SentinelToXDR.psd1') -Force
}

$context = Get-SentinelToXDRContext
if (-not $context.CanManageDetections) {
    Write-Host 'No Graph session in this process. Signing in...' -ForegroundColor Yellow
    try { Connect-SentinelToXDR -ErrorAction Stop } catch { Write-Host "Sign-in FAILED: $($_.Exception.Message)" -ForegroundColor Red; throw }
    $context = Get-SentinelToXDRContext
}
if (-not $context.CanManageDetections) { throw 'Cannot manage detections in this session.' }
Write-Host "Tenant: $($context.Account)`n" -ForegroundColor Cyan

$baselineHost = [ordered]@{ nameColumn = 'DeviceName' }

# Synthesised so that every column any case maps is projected by the query output,
# whatever the underlying table actually carries.
$query = @'
DeviceProcessEvents
| take 1
| extend AccountUpnSuffix = 'example.com', AccountDomain = 'CONTOSO', AccountDnsDomain = 'contoso.com',
         RemoteIP = '10.0.0.1', RecipientEmailAddress = 'a@example.com', Url = 'https://example.com',
         RegistryValueNameX = 'Run'
'@

# Each case is the entity under test. The hosts baseline is added to all of them below.
$cases = [ordered]@{
    'account-name-only'          = @{ accounts = @([ordered]@{ nameColumn = 'AccountName' }) }
    'account-sid-only'           = @{ accounts = @([ordered]@{ sidColumn = 'AccountSid' }) }
    'account-upn-only'           = @{ accounts = @([ordered]@{ upnColumn = 'AccountUpn' }) }
    'account-aaduserid-only'     = @{ accounts = @([ordered]@{ aadUserIdColumn = 'AccountObjectId' }) }
    'account-name-ntdomain'      = @{ accounts = @([ordered]@{ nameColumn = 'AccountName'; ntDomainColumn = 'AccountDomain' }) }
    'account-name-dnsdomain'     = @{ accounts = @([ordered]@{ nameColumn = 'AccountName'; dnsDomainColumn = 'AccountDnsDomain' }) }
    'account-name-upnsuffix'     = @{ accounts = @([ordered]@{ nameColumn = 'AccountName'; upnSuffixColumn = 'AccountUpnSuffix' }) }
    'account-upnsuffix-only'     = @{ accounts = @([ordered]@{ upnSuffixColumn = 'AccountUpnSuffix' }) }
    'account-ntdomain-only'      = @{ accounts = @([ordered]@{ ntDomainColumn = 'AccountDomain' }) }
    'host-netbios-only'          = @{ hosts    = @([ordered]@{ netBiosNameColumn = 'DeviceName' }) }
    'ip-address-only'            = @{ ips      = @([ordered]@{ addressColumn = 'RemoteIP' }) }
    'file-name-only'             = @{ files    = @([ordered]@{ nameColumn = 'FileName' }) }
    'file-sha256-only'           = @{ files    = @([ordered]@{ sha256Column = 'SHA256' }) }
    'file-name-sha256'           = @{ files    = @([ordered]@{ nameColumn = 'FileName'; sha256Column = 'SHA256' }) }
    'mailbox-primary-only'       = @{ mailboxes = @([ordered]@{ primaryAddressColumn = 'RecipientEmailAddress' }) }
    'url-address-only'           = @{ urls     = @([ordered]@{ addressColumn = 'Url' }) }
    'mailmessage-networkid-only' = @{ mailMessages = @([ordered]@{ networkMessageIdColumn = 'ReportId' }) }
    'mailmessage-recipient-only' = @{ mailMessages = @([ordered]@{ recipientColumn = 'RecipientEmailAddress' }) }
}

# Add the confirmed-good hosts mapping to every case that is not itself testing hosts,
# so the asset-entity requirement can never be what fails.
foreach ($name in @($cases.Keys)) {
    if (-not $cases[$name].ContainsKey('hosts')) {
        $cases[$name]['hosts'] = @($baselineHost)
    }
}

$results = [System.Collections.Generic.List[object]]::new()
$created = [System.Collections.Generic.List[string]]::new()
$index = 0

try {
    foreach ($name in $cases.Keys) {
        $index++
        $rule = [ordered]@{
            id              = "s2x-ent-$index"
            displayName     = "S2X entity probe $name"
            description     = 'SentinelToXDR constraint probe. Safe to delete.'
            status          = 'disabled'
            queryCondition  = [ordered]@{ queryText = $query }
            schedule        = [ordered]@{ frequency = 'PT1H' }
            detectionAction = [ordered]@{
                alertTemplate = [ordered]@{
                    title          = "S2X entity probe $name"
                    description    = 'SentinelToXDR constraint probe. Safe to delete.'
                    severity       = 'low'
                    tactics        = @([ordered]@{ tactic = 'Execution'; techniques = @([ordered]@{ technique = 'T1059' }) })
                    entityMappings = $cases[$name]
                }
            }
        }

        $status = 'Unknown'; $message = ''
        try {
            $result = $rule | New-XDRCustomDetection -Force -ErrorAction SilentlyContinue -ErrorVariable probeError
            $status = if ($result) { [string]$result.Status } else { 'NoResult' }
            $message = if ($result) { [string]$result.Error } else { ($probeError -join ' ') }
            if ($status -eq 'Created') { $created.Add([string]$rule.id) }
        } catch { $status = 'Threw'; $message = $_.Exception.Message }

        $apiMessage = ''
        if ($message -match '"message"\s*:\s*"([^"]+)"') { $apiMessage = $Matches[1] }

        $accepted = ($status -eq 'Created')
        Write-Host ("{0,-24} {1}" -f $name, $(if ($accepted) { 'ACCEPTED' } else { 'rejected' })) `
            -ForegroundColor $(if ($accepted) { 'Green' } else { 'Yellow' })
        if (-not $accepted -and $apiMessage) { Write-Host "                         $apiMessage" -ForegroundColor DarkGray }

        $results.Add([PSCustomObject]@{ Mapping = $name; Accepted = $accepted; ApiMessage = $apiMessage })
    }
}
finally {
    if ($created.Count -gt 0) {
        Write-Host "`nCleaning up $($created.Count) probe rule(s)..." -ForegroundColor Cyan
        foreach ($id in $created) {
            try { Remove-XDRCustomDetection -Id $id -Confirm:$false -ErrorAction Stop | Out-Null }
            catch { Write-Warning "Could not delete '$id': $($_.Exception.Message)" }
        }
    }
    # A second DELETE answering 404 shows the service TOOK the delete. GET and the portal
    # keep the rule for hours afterwards (measured 2026-09-16); nothing callable here
    # observes completion, so this says 'taken', not 'clean'.
    $strays = @(foreach ($id in $created) {
            $second = Remove-XDRCustomDetection -Id $id -Confirm:$false -ErrorAction SilentlyContinue
            if (-not ($second.Status -eq 'Failed' -and [string]$second.Error -match 'HTTP 404')) { $id }
        })
    if ($strays.Count -gt 0) {
        Write-Warning "Did not answer 404 to a second DELETE - the delete may not have been taken: $($strays -join ', ')"
    }
    else { Write-Host 'Delete taken by the service for every probe rule. Completion takes hours; the portal will show them until then.' -ForegroundColor Yellow }
}

Write-Host "`n==== Sufficient entity identifier combinations ====" -ForegroundColor Cyan
$results | Format-Table Mapping, Accepted -AutoSize | Out-Host
Write-Host 'ACCEPTED rows are combinations the converter may emit on their own.' -ForegroundColor DarkGray
Write-Host 'Every case also carried a hosts{nameColumn} mapping, so a rejection is about the entity under test.' -ForegroundColor DarkGray
Write-Host 'Rejected rows must be enriched, or the rule cannot deploy.' -ForegroundColor DarkGray
