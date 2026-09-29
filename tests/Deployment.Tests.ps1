Describe 'Deployment — what actually goes on the wire' {

    # Everything else in this suite proves the module builds the right object. These tests
    # prove it SENDS the right request. That distinction is not academic: a detection can be
    # converted perfectly, pass every schema check, and still be lost because it was PATCHed
    # to the wrong URI, or sent with a property the service refuses.
    #
    # Invoke-S2XRestRequest is the single HTTP chokepoint for the whole module, so mocking
    # it captures every request any cmdlet makes, in order, with its method and body.

    BeforeAll {
        $repoRoot = Split-Path -Path $PSScriptRoot -Parent
        Import-Module -Name (Join-Path $repoRoot 'src/SentinelToXDR.psd1') -Force

        $script:TestRoot = Join-Path ([System.IO.Path]::GetTempPath()) "s2x-deploy-$([System.Guid]::NewGuid())"
        New-Item -ItemType Directory -Path $script:TestRoot -Force | Out-Null

        $script:Base = 'https://graph.microsoft.com/beta/security/rules/detectionRules'

        # A raw Graph detection rule, in the shape the converter emits: no isEnabled and no
        # schedule.period, both of which Microsoft removes on 2026-10-01 (see
        # DeprecatedProperties in src/Data/GraphDetectionRule.psd1).
        function Get-GraphRuleFixture {
            param([string]$Id = 'rule-1', [string]$Name = 'Test Rule', [string]$Status = 'enabled')
            return [ordered]@{
                id              = $Id
                displayName     = $Name
                description     = 'A rule used to prove what goes on the wire.'
                status          = $Status
                queryCondition  = [ordered]@{ queryText = 'DeviceProcessEvents | take 1' }
                schedule        = [ordered]@{ frequency = 'PT1H' }
                detectionAction = [ordered]@{
                    alertTemplate = [ordered]@{ title = $Name; severity = 'high' }
                }
            }
        }
    }

    AfterAll {
        if ($script:TestRoot -and (Test-Path -LiteralPath $script:TestRoot)) {
            Remove-Item -LiteralPath $script:TestRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    BeforeEach {
        # One capture list per test, so a leaked call from a previous test cannot pass one.
        $script:Calls = [System.Collections.Generic.List[object]]::new()
    }

    # -------------------------------------------------------------------------------------
    Context 'New-XDRCustomDetection — the create request' {

        BeforeEach {
            Mock -ModuleName SentinelToXDR -CommandName Invoke-S2XRestRequest -MockWith {
                $script:Calls.Add([PSCustomObject]@{ Uri = $Uri; Method = $Method; Body = $Body; Paginate = [bool]$Paginate })
                [PSCustomObject]@{ id = 'rule-1'; displayName = 'Test Rule' }
            }
        }

        It 'Should POST to /security/rules/detectionRules' {
            Get-GraphRuleFixture | New-XDRCustomDetection -Force -AccessToken 'test-token' | Out-Null

            $script:Calls.Count | Should -Be 1
            $script:Calls[0].Method | Should -Be 'POST'
            $script:Calls[0].Uri    | Should -Be $script:Base
        }

        It 'Should send the rule verbatim, with nothing added or dropped' {
            $rule = Get-GraphRuleFixture
            $rule | New-XDRCustomDetection -Force -AccessToken 'test-token' | Out-Null

            $sent = $script:Calls[0].Body
            $sent.id                        | Should -Be 'rule-1'
            $sent.displayName               | Should -Be 'Test Rule'
            $sent.queryCondition.queryText  | Should -Be 'DeviceProcessEvents | take 1'
            $sent.schedule.frequency        | Should -Be 'PT1H'
            # Same key set, in the same order: a reordered or trimmed body is a silent change.
            @($sent.Keys) | Should -Be @($rule.Keys)
        }

        It 'Should honour -GraphEndpoint and trim a trailing slash' {
            Get-GraphRuleFixture | New-XDRCustomDetection -Force -AccessToken 'test-token' `
                -GraphEndpoint 'https://graph.microsoft.us/beta/' | Out-Null

            $script:Calls[0].Uri | Should -Be 'https://graph.microsoft.us/beta/security/rules/detectionRules'
        }

        It 'Should set status=disabled with -Disabled' {
            Get-GraphRuleFixture -Status 'enabled' | New-XDRCustomDetection -Disabled -Force -AccessToken 'test-token' | Out-Null

            $script:Calls[0].Body.status | Should -Be 'disabled'
        }

        It 'Should not mutate the caller''s object when -Disabled rewrites the status' {
            # The converter hands the same object to the reporter and the exporter. Mutating
            # it here would silently change what those write, which is the kind of bug that
            # only shows up as "the YAML on disk says disabled and I never asked for that".
            $rule = Get-GraphRuleFixture -Status 'enabled'
            $rule | New-XDRCustomDetection -Disabled -Force -AccessToken 'test-token' | Out-Null

            $rule.status | Should -Be 'enabled'
        }

        It 'Should send nothing at all under -WhatIf' {
            $results = @(Get-GraphRuleFixture | New-XDRCustomDetection -WhatIf -AccessToken 'test-token')

            $script:Calls.Count  | Should -Be 0
            $results[0].Status   | Should -Be 'WhatIf'
        }

        It 'Should keep deploying the rest of the batch after one rule fails' {
            Mock -ModuleName SentinelToXDR -CommandName Invoke-S2XRestRequest -MockWith {
                $script:Calls.Add([PSCustomObject]@{ Uri = $Uri; Method = $Method; Body = $Body })
                if ($Body.id -eq 'rule-2') { throw "POST $Uri failed with HTTP 400. Bad request." }
                [PSCustomObject]@{ id = $Body.id }
            }

            $rules = @('rule-1', 'rule-2', 'rule-3') | ForEach-Object { Get-GraphRuleFixture -Id $_ }
            $results = @($rules | New-XDRCustomDetection -Force -AccessToken 'test-token' -ErrorAction SilentlyContinue)

            $script:Calls.Count | Should -Be 3 -Because 'one bad rule must not cost the other two'
            @($results | Where-Object Status -eq 'Created').Count | Should -Be 2
            @($results | Where-Object Status -eq 'Failed').Count  | Should -Be 1
            ($results | Where-Object Status -eq 'Failed').Id      | Should -Be 'rule-2'
        }
    }

    # -------------------------------------------------------------------------------------
    Context 'New-XDRCustomDetection — what a failure tells the caller' {

        It 'Should carry the service sentence on the result and in the error, and the full response on Error' {
            $body = '{"error":{"code":"BadRequest","message":"The query has a semantic error: Unknown function: ''_MyOrgDeviceBaseline''. Fix semantic errors in your query."}}'
            Mock -ModuleName SentinelToXDR -CommandName Invoke-S2XRestRequest -MockWith {
                throw "POST $Uri failed with HTTP 400. Response status code does not indicate success: BadRequest (Bad Request). Response body: $body"
            }.GetNewClosure()

            $results = @(Get-GraphRuleFixture | New-XDRCustomDetection -Force -AccessToken 'test-token' -ErrorVariable deployErrors -ErrorAction SilentlyContinue)

            $results[0].Status         | Should -Be 'Failed'
            $results[0].ServiceMessage | Should -Be "The query has a semantic error: Unknown function: '_MyOrgDeviceBaseline'. Fix semantic errors in your query."
            $results[0].Error          | Should -Match 'HTTP 400' -Because 'the full response stays on the record'
            # The mock's own throw echoes through Pester's layers into -ErrorVariable too;
            # only the record the cmdlet wrote is under test.
            $written = @($deployErrors | Where-Object { [string]$_ -like 'Deploying custom detection*' })
            $written.Count             | Should -Be 1
            [string]$written[0]        | Should -Match "Unknown function: '_MyOrgDeviceBaseline'"
            [string]$written[0]        | Should -Not -Match 'Response body' -Because 'the error is the one line a person reads'
        }

        It 'Should carry the service sentence on a conflict too' {
            Mock -ModuleName SentinelToXDR -CommandName Invoke-S2XRestRequest -MockWith {
                throw 'POST failed with HTTP 409. Response body: {"error":{"code":"Conflict","message":"A detection rule with this name, title, or rule ID already exists."}}'
            }
            $results = @(Get-GraphRuleFixture | New-XDRCustomDetection -Force -AccessToken 'test-token' -WarningAction SilentlyContinue)
            $results[0].Status         | Should -Be 'Conflict'
            $results[0].ServiceMessage | Should -Be 'A detection rule with this name, title, or rule ID already exists.'
        }

        It 'Should fall back to the first line when there is no JSON body' {
            Mock -ModuleName SentinelToXDR -CommandName Invoke-S2XRestRequest -MockWith {
                throw "POST failed with HTTP 500. Internal Server Error.`nsecond line"
            }
            $results = @(Get-GraphRuleFixture | New-XDRCustomDetection -Force -AccessToken 'test-token' -ErrorAction SilentlyContinue)
            $results[0].ServiceMessage | Should -Be 'POST failed with HTTP 500. Internal Server Error.'
        }

        It 'Should unescape a JSON-escaped service sentence' {
            $sentence = InModuleScope SentinelToXDR {
                Get-S2XServiceMessage -Message 'POST failed with HTTP 400. Response body: {"error":{"message":"Column \"DeviceName\" is not projected.\nFix it."}}'
            }
            $sentence | Should -Be "Column `"DeviceName`" is not projected.`nFix it."
        }
    }

    # -------------------------------------------------------------------------------------
    Context 'New-XDRCustomDetection — the conflict path' {

        BeforeEach {
            # The service says "already there". Everything about whether a re-run is safe
            # hangs on what the module does next.
            Mock -ModuleName SentinelToXDR -CommandName Invoke-S2XRestRequest -MockWith {
                $script:Calls.Add([PSCustomObject]@{ Uri = $Uri; Method = $Method; Body = $Body })
                if ($Method -eq 'POST') { throw "POST $Uri failed with HTTP 409. Conflict." }
                [PSCustomObject]@{ id = $Body.id; displayName = 'Test Rule' }
            }
        }

        It 'Should report a conflict and stop, without -Update' {
            $results = @(Get-GraphRuleFixture | New-XDRCustomDetection -Force -AccessToken 'test-token' -WarningAction SilentlyContinue)

            $script:Calls.Count | Should -Be 1 -Because 'without -Update there must be no second, unasked-for write'
            $results[0].Status  | Should -Be 'Conflict'
        }

        It 'Should PATCH the existing rule with -Update' {
            $results = @(Get-GraphRuleFixture | New-XDRCustomDetection -Update -Force -AccessToken 'test-token')

            $script:Calls.Count      | Should -Be 2
            $script:Calls[1].Method  | Should -Be 'PATCH'
            $script:Calls[1].Uri     | Should -Be "$script:Base/rule-1"
            $results[0].Status       | Should -Be 'Updated'
            $results[0].Method       | Should -Be 'PATCH'
        }

        It 'Should not send a read-only id in the PATCH body' {
            # Graph rejects a read-only property in a PATCH body with HTTP 400. The rule id
            # is already in the URI; repeating it in the body is what breaks -Update, and
            # -Update is the switch that makes a second run of a migration safe.
            Get-GraphRuleFixture | New-XDRCustomDetection -Update -Force -AccessToken 'test-token' | Out-Null

            $patchBody = $script:Calls[1].Body
            @($patchBody.Keys) | Should -Not -Contain 'id'
            # ...and it must still carry the parts that actually change.
            $patchBody.queryCondition.queryText | Should -Be 'DeviceProcessEvents | take 1'
            $patchBody.displayName              | Should -Be 'Test Rule'
        }
    }

    # -------------------------------------------------------------------------------------
    Context 'New-XDRCustomDetection — deploying from exported files' {

        BeforeEach {
            Mock -ModuleName SentinelToXDR -CommandName Invoke-S2XRestRequest -MockWith {
                $script:Calls.Add([PSCustomObject]@{ Uri = $Uri; Method = $Method; Body = $Body })
                [PSCustomObject]@{ id = $Body.id }
            }
        }

        It 'Should deploy every rule in a combined JSON array' {
            $path = Join-Path $script:TestRoot 'combined.json'
            @('a', 'b', 'c') | ForEach-Object { Get-GraphRuleFixture -Id $_ } |
                ConvertTo-Json -Depth 20 -AsArray | Set-Content -LiteralPath $path -Encoding utf8NoBOM

            New-XDRCustomDetection -Path $path -Force -AccessToken 'test-token' | Out-Null

            $script:Calls.Count | Should -Be 3
            @($script:Calls.Body.id) | Should -Be @('a', 'b', 'c')
        }

        It 'Should deploy every .json file in a folder' {
            $dir = Join-Path $script:TestRoot 'folder'
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            foreach ($id in @('x', 'y')) {
                Get-GraphRuleFixture -Id $id | ConvertTo-Json -Depth 20 |
                    Set-Content -LiteralPath (Join-Path $dir "$id.json") -Encoding utf8NoBOM
            }

            New-XDRCustomDetection -Path $dir -Force -AccessToken 'test-token' | Out-Null

            $script:Calls.Count | Should -Be 2
            @($script:Calls.Body.id) | Sort-Object | Should -Be @('x', 'y')
        }

        It 'Should report a malformed file and carry on with the rest' {
            $dir = Join-Path $script:TestRoot 'mixed'
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            Set-Content -LiteralPath (Join-Path $dir 'broken.json') -Value '{ not json' -Encoding utf8NoBOM
            Get-GraphRuleFixture -Id 'good' | ConvertTo-Json -Depth 20 |
                Set-Content -LiteralPath (Join-Path $dir 'good.json') -Encoding utf8NoBOM

            $errors = @()
            New-XDRCustomDetection -Path $dir -Force -AccessToken 'test-token' `
                -ErrorVariable errors -ErrorAction SilentlyContinue | Out-Null

            $script:Calls.Count   | Should -Be 1
            $script:Calls[0].Body.id | Should -Be 'good'
            ($errors -join ' ')   | Should -Match 'not valid JSON'
        }

        It 'Should survive the round trip from Export-XDRCustomDetection unchanged' {
            # The seam where a shape quietly changes: converted object -> JSON on disk ->
            # parsed back -> request body. A detection that deploys from the pipeline but
            # not from the artifact a reviewer approved is the worst possible asymmetry.
            $rulePath = Join-Path $script:TestRoot 'source.yaml'
            Set-Content -LiteralPath $rulePath -Encoding utf8NoBOM -Value @'
id: 3f2b19a4-1111-2222-3333-444455556666
name: Round Trip Rule
description: Proves an exported artifact deploys identically to the pipeline.
severity: High
queryFrequency: 1h
queryPeriod: 1h
triggerOperator: gt
triggerThreshold: 0
tactics:
  - Execution
relevantTechniques:
  - T1059
query: |
  DeviceProcessEvents
  | where ProcessCommandLine has "whoami"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: AccountName
kind: Scheduled
'@
            $detection = Get-SentinelAnalyticsRule -Path $rulePath |
                ConvertTo-XDRCustomDetection -As Object -Force -WarningAction SilentlyContinue

            $exportDir = Join-Path $script:TestRoot 'roundtrip'
            $detection | Export-XDRCustomDetection -Path $exportDir -Format Json -Combine -Force

            # Deploy from the pipeline...
            $detection | New-XDRCustomDetection -Force -AccessToken 'test-token' | Out-Null
            $fromPipeline = $script:Calls[0].Body | ConvertTo-Json -Depth 20

            # ...and from the artifact on disk.
            $script:Calls.Clear()
            New-XDRCustomDetection -Path (Join-Path $exportDir 'customDetections.json') `
                -Force -AccessToken 'test-token' | Out-Null
            $fromFile = $script:Calls[0].Body | ConvertTo-Json -Depth 20

            $fromFile | Should -Be $fromPipeline
        }
    }

    # -------------------------------------------------------------------------------------
    Context 'New-XDRCustomDetection — what must never be sent' {

        BeforeEach {
            Mock -ModuleName SentinelToXDR -CommandName Invoke-S2XRestRequest -MockWith {
                $script:Calls.Add([PSCustomObject]@{ Uri = $Uri; Method = $Method; Body = $Body })
                [PSCustomObject]@{ id = 'x' }
            }
        }

        It 'Should never send a rule that conversion blocked' {
            $blocked = [PSCustomObject]@{
                PSTypeName  = 'SentinelToXDR.CustomDetection'
                RuleName    = 'Fusion rule'; Id = 'blocked-1'; Blocked = $true; Format = 'Graph'
                Diagnostics = @([PSCustomObject]@{ Severity = 'Blocking'; Reason = 'Fusion rules have no query.' })
                Rule        = [ordered]@{ id = 'blocked-1' }
            }

            $blocked | New-XDRCustomDetection -Force -AccessToken 'test-token' -WarningAction SilentlyContinue | Out-Null

            $script:Calls.Count | Should -Be 0
        }

        It 'Should never send the legacy XDRConverter shape' {
            $legacy = [PSCustomObject]@{
                PSTypeName = 'SentinelToXDR.CustomDetection'
                RuleName   = 'Legacy'; Id = 'legacy-1'; Blocked = $false; Format = 'XDRConverter'
                Rule       = [ordered]@{ id = 'legacy-1' }
            }

            $legacy | New-XDRCustomDetection -Force -AccessToken 'test-token' -WarningAction SilentlyContinue | Out-Null

            $script:Calls.Count | Should -Be 0
        }

        It 'Should never send an object that is not a detection rule' {
            [PSCustomObject]@{ name = 'not a rule'; value = 42 } |
                New-XDRCustomDetection -Force -AccessToken 'test-token' -WarningAction SilentlyContinue | Out-Null

            $script:Calls.Count | Should -Be 0
        }
    }

    # -------------------------------------------------------------------------------------
    Context 'Set-XDRCustomDetection' {

        BeforeEach {
            Mock -ModuleName SentinelToXDR -CommandName Invoke-S2XRestRequest -MockWith {
                $script:Calls.Add([PSCustomObject]@{ Uri = $Uri; Method = $Method; Body = $Body })
                [PSCustomObject]@{ id = 'rule-1'; displayName = 'Test Rule' }
            }
        }

        It 'Should PATCH the rule at its own id' {
            Get-GraphRuleFixture | Set-XDRCustomDetection -Force -AccessToken 'test-token' | Out-Null

            $script:Calls.Count     | Should -Be 1
            $script:Calls[0].Method | Should -Be 'PATCH'
            $script:Calls[0].Uri    | Should -Be "$script:Base/rule-1"
        }

        It 'Should not send a read-only id in the PATCH body' {
            Get-GraphRuleFixture | Set-XDRCustomDetection -Force -AccessToken 'test-token' | Out-Null

            @($script:Calls[0].Body.Keys) | Should -Not -Contain 'id'
            $script:Calls[0].Body.displayName | Should -Be 'Test Rule'
        }

        It 'Should strip every service-owned field from a rule read back off the wire' {
            # The real update path: read a rule with Get-XDRCustomDetection, change
            # something, PATCH it back. What comes off the wire is a PSCustomObject carrying
            # @odata.type, createdBy, createdDateTime, lastModifiedBy and
            # lastModifiedDateTime — none of which PATCH accepts. This is exactly what the
            # round-trip validation script now sends, so it has to be right.
            $fromGraph = [PSCustomObject]@{
                '@odata.type'          = '#microsoft.graph.security.detectionRule'
                id                     = 'rule-1'
                displayName            = 'Read back from Graph'
                description            = 'Stored by the service.'
                status                 = 'disabled'
                createdBy              = 'alice@contoso.com'
                createdDateTime        = '2026-05-25T10:15:00Z'
                lastModifiedBy         = 'alice@contoso.com'
                lastModifiedDateTime   = '2026-05-28T14:30:00Z'
                queryCondition         = [PSCustomObject]@{ queryText = 'DeviceEvents | take 1' }
                schedule               = [PSCustomObject]@{ frequency = 'PT1H' }
            }

            $fromGraph | Set-XDRCustomDetection -Force -AccessToken 'test-token' | Out-Null

            $sentKeys = @($script:Calls[0].Body.Keys)
            foreach ($forbidden in @('id', '@odata.type', 'createdBy', 'createdDateTime',
                                     'lastModifiedBy', 'lastModifiedDateTime')) {
                $sentKeys | Should -Not -Contain $forbidden
            }
            # ...and the things that legitimately change are still there.
            $script:Calls[0].Body.displayName              | Should -Be 'Read back from Graph'
            $script:Calls[0].Body.status                   | Should -Be 'disabled'
            $script:Calls[0].Body.queryCondition.queryText | Should -Be 'DeviceEvents | take 1'
        }

        It 'Should target -Id over the id on the object' {
            Get-GraphRuleFixture -Id 'from-object' | Set-XDRCustomDetection -Id 'from-parameter' -Force -AccessToken 'test-token' | Out-Null

            $script:Calls[0].Uri | Should -Be "$script:Base/from-parameter"
        }

        It 'Should refuse a rule with no id rather than guess one' {
            $noId = [ordered]@{ displayName = 'Nameless'; queryCondition = [ordered]@{ queryText = 'DeviceEvents' } }
            $errors = @()
            $noId | Set-XDRCustomDetection -Force -AccessToken 'test-token' -ErrorVariable errors -ErrorAction SilentlyContinue | Out-Null

            $script:Calls.Count | Should -Be 0
            ($errors -join ' ') | Should -Match 'no rule id'
        }

        It 'Should send only the status on a status-only change' {
            # A status flip must not resend the query. Resending it would quietly reapply a
            # stale query that the reviewer had since edited in the portal.
            Set-XDRCustomDetection -Id 'rule-1' -Status 'enabled' -Force -AccessToken 'test-token' | Out-Null

            $script:Calls[0].Method   | Should -Be 'PATCH'
            $script:Calls[0].Uri      | Should -Be "$script:Base/rule-1"
            @($script:Calls[0].Body.Keys) | Should -Be @('status')
            $script:Calls[0].Body.status  | Should -Be 'enabled'
        }

        It 'Should send nothing under -WhatIf' {
            Get-GraphRuleFixture | Set-XDRCustomDetection -WhatIf -AccessToken 'test-token' | Out-Null
            Set-XDRCustomDetection -Id 'rule-1' -Status 'disabled' -WhatIf -AccessToken 'test-token' | Out-Null

            $script:Calls.Count | Should -Be 0
        }
    }

    # -------------------------------------------------------------------------------------
    Context 'Remove-XDRCustomDetection' {

        BeforeEach {
            Mock -ModuleName SentinelToXDR -CommandName Invoke-S2XRestRequest -MockWith {
                $script:Calls.Add([PSCustomObject]@{ Uri = $Uri; Method = $Method; Body = $Body })
                $null
            }
        }

        It 'Should DELETE the rule at its id' {
            Remove-XDRCustomDetection -Id 'rule-1' -Confirm:$false -AccessToken 'test-token' | Out-Null

            $script:Calls.Count     | Should -Be 1
            $script:Calls[0].Method | Should -Be 'DELETE'
            $script:Calls[0].Uri    | Should -Be "$script:Base/rule-1"
        }

        It 'Should accept Get-XDRCustomDetection output straight off the pipeline' {
            # The documented cleanup path. Graph returns lowercase 'id' / 'displayName';
            # binding is case-insensitive, and this test is what keeps that true.
            $deployed = @(
                [PSCustomObject]@{ id = 'TEST-a'; displayName = 'Lab rule A' }
                [PSCustomObject]@{ id = 'TEST-b'; displayName = 'Lab rule B' }
            )

            $results = @($deployed | Remove-XDRCustomDetection -Confirm:$false -AccessToken 'test-token')

            @($script:Calls.Uri) | Should -Be @("$script:Base/TEST-a", "$script:Base/TEST-b")
            $results[0].RuleName | Should -Be 'Lab rule A'
            $results[0].Status   | Should -Be 'Deleted'
        }

        It 'Should send nothing under -WhatIf' {
            $results = @(Remove-XDRCustomDetection -Id 'rule-1' -WhatIf -AccessToken 'test-token')

            $script:Calls.Count | Should -Be 0
            $results[0].Status  | Should -Be 'WhatIf'
        }

        It 'Should report a 404 as AlreadyDeleted with a warning, not an error, and keep going' {
            # Seen 2026-09-17: the list endpoint served rules deleted in the previous
            # run for hours, so the cleanup pipeline deleted them again and the second
            # DELETE answered 404. That is the tenant catching up, not a failure.
            Mock -ModuleName SentinelToXDR -CommandName Invoke-S2XRestRequest -MockWith {
                $script:Calls.Add([PSCustomObject]@{ Uri = $Uri; Method = $Method; Body = $Body })
                if ($Uri -like '*/gone') {
                    throw ('DELETE {0} failed with HTTP 404. Response status code does not indicate success: 404 (Not Found). ' +
                        'Response body: {{"error":{{"code":"NotFound","message":"Custom detection rule with ID gone was not found."}}}}') -f $Uri
                }
                $null
            }
            $deployed = @(
                [PSCustomObject]@{ id = 'gone';  displayName = 'Deleted last run' }
                [PSCustomObject]@{ id = 'alive'; displayName = 'Still here' }
            )

            $results = @($deployed | Remove-XDRCustomDetection -Confirm:$false -AccessToken 'test-token' `
                -WarningVariable warnings -WarningAction SilentlyContinue -ErrorVariable errors -ErrorAction SilentlyContinue)

            $results.Count             | Should -Be 2
            $results[0].Status         | Should -Be 'AlreadyDeleted'
            $results[0].Error          | Should -BeNullOrEmpty
            $results[0].ServiceMessage | Should -Be 'Custom detection rule with ID gone was not found.'
            $results[1].Status         | Should -Be 'Deleted'
            # ErrorVariable also records the mock's own throw, so count the cmdlet's errors.
            @($errors | Where-Object { "$_" -match 'Deleting custom detection' }).Count | Should -Be 0
            # One summary warning for the pipeline, not one per rule: the Status column
            # already names each rule.
            @($warnings).Count         | Should -Be 1
            $warnings[0].Message       | Should -Match '^1 rule was reported as not found'
            # The warning states what was observed and does not assert a cause: the
            # hours-long list lag was the first explanation and the portal contradicts it.
            $warnings[0].Message       | Should -Not -Match 'hours'
        }

        It 'Should still report any other refusal as Failed with an error' {
            Mock -ModuleName SentinelToXDR -CommandName Invoke-S2XRestRequest -MockWith {
                throw 'DELETE x failed with HTTP 403. Response body: {"error":{"code":"Forbidden","message":"Insufficient role."}}'
            }

            $results = @(Remove-XDRCustomDetection -Id 'rule-1' -Confirm:$false -AccessToken 'test-token' `
                -ErrorVariable errors -ErrorAction SilentlyContinue)

            $results[0].Status         | Should -Be 'Failed'
            $results[0].ServiceMessage | Should -Be 'Insufficient role.'
            @($errors | Where-Object { "$_" -match 'Deleting custom detection' }).Count | Should -Be 1
        }
    }

    # -------------------------------------------------------------------------------------
    Context 'Get-XDRCustomDetection' {

        It 'Should GET the collection and follow paging' {
            Mock -ModuleName SentinelToXDR -CommandName Invoke-S2XRestRequest -MockWith {
                $script:Calls.Add([PSCustomObject]@{ Uri = $Uri; Method = $Method; Paginate = [bool]$Paginate })
                [PSCustomObject]@{ id = 'a' }
            }

            Get-XDRCustomDetection -AccessToken 'test-token' | Out-Null

            $script:Calls[0].Uri      | Should -Be $script:Base
            $script:Calls[0].Paginate | Should -BeTrue -Because 'a tenant with more than one page must not silently return one'
        }

        It 'Should GET a single rule by id, without paging' {
            Mock -ModuleName SentinelToXDR -CommandName Invoke-S2XRestRequest -MockWith {
                $script:Calls.Add([PSCustomObject]@{ Uri = $Uri; Method = $Method; Paginate = [bool]$Paginate })
                [PSCustomObject]@{ id = 'rule-1' }
            }

            Get-XDRCustomDetection -Id 'rule-1' -AccessToken 'test-token' | Out-Null

            $script:Calls[0].Uri      | Should -Be "$script:Base/rule-1"
            $script:Calls[0].Paginate | Should -BeFalse
        }

        It 'Should return every rule across an @odata.nextLink boundary' {
            # Exercises the real paging code in Invoke-S2XRestRequest by mocking one layer
            # lower. A tenant with 60 detections pages at 50; returning 50 of them looks
            # exactly like success and quietly makes a comparison against a conversion wrong.
            Mock -ModuleName SentinelToXDR -CommandName Invoke-RestMethod -MockWith {
                $script:Calls.Add([PSCustomObject]@{ Uri = $Uri; Method = $Method })
                if ($Uri -match 'skiptoken') {
                    return [PSCustomObject]@{ value = @([PSCustomObject]@{ id = 'c' }) }
                }
                return [PSCustomObject]@{
                    value            = @([PSCustomObject]@{ id = 'a' }, [PSCustomObject]@{ id = 'b' })
                    '@odata.nextLink' = "$script:Base?`$skiptoken=page2"
                }
            }

            $all = @(Get-XDRCustomDetection -AccessToken 'test-token')

            $script:Calls.Count      | Should -Be 2 -Because 'the second page has to be fetched'
            @($all.id)               | Should -Be @('a', 'b', 'c')
            @($script:Calls.Method)  | Should -Be @('GET', 'GET') -Because 'reading detections must never be anything but a read'
        }
    }

    # -------------------------------------------------------------------------------------
    Context 'Test-XDRDetectionQuery' {

        It 'Should POST the query to runHuntingQuery with a timespan' {
            Mock -ModuleName SentinelToXDR -CommandName Invoke-S2XRestRequest -MockWith {
                $script:Calls.Add([PSCustomObject]@{ Uri = $Uri; Method = $Method; Body = $Body })
                [PSCustomObject]@{ results = @([PSCustomObject]@{ x = 1 }) }
            }

            $result = Test-XDRDetectionQuery -Query 'DeviceEvents | take 1' -Timespan 'PT10M' -AccessToken 'test-token'

            $script:Calls[0].Uri           | Should -Be 'https://graph.microsoft.com/beta/security/runHuntingQuery'
            $script:Calls[0].Method        | Should -Be 'POST'
            $script:Calls[0].Body.query    | Should -Be 'DeviceEvents | take 1'
            $script:Calls[0].Body.timespan | Should -Be 'PT10M'
            $result.QueryValid             | Should -BeTrue
            $result.ResultCount            | Should -Be 1
        }

        It 'Should classify <Kind> from the service error' -ForEach @(
            @{ Kind = 'UnresolvedName';       Message = "Failed to resolve table or column expression named 'SigninLogs'" }
            @{ Kind = 'WatchlistDependency';  Message = "Failed to resolve function '_GetWatchlist'" }
            @{ Kind = 'AsimParserDependency'; Message = "Unknown function: '_Im_ProcessCreate'" }
            @{ Kind = 'SyntaxError';          Message = 'Syntax error: unexpected token' }
            @{ Kind = 'Timeout';              Message = 'The query timed out.' }
            @{ Kind = 'Other';                Message = '{"error":{"message":"The request had some invalid properties. ."}}' }
        ) {
            # The kind is what makes a batch result actionable: 200 rules failing on
            # UnresolvedName is one onboarding conversation; 200 on SyntaxError is our bug.
            $failure = $Message
            Mock -ModuleName SentinelToXDR -CommandName Invoke-S2XRestRequest -MockWith {
                throw "POST failed with HTTP 400. Response body: $failure"
            }.GetNewClosure()

            $result = Test-XDRDetectionQuery -Query 'X' -AccessToken 'test-token'

            $result.QueryValid  | Should -BeFalse
            $result.FailureKind | Should -Be $Kind
        }

        It 'Should name a workspace() dependency when the service only says invalid properties' {
            # Observed 2026-09-16: runHuntingQuery answers a workspace('x') reference with
            # 'The request had some invalid properties. .' and nothing else. Classifying
            # that as Other threw away what the query itself says.
            Mock -ModuleName SentinelToXDR -CommandName Invoke-S2XRestRequest -MockWith {
                throw 'POST failed with HTTP 400. Response body: {"error":{"code":"BadRequest","message":"The request had some invalid properties. ."}}'
            }
            $result = Test-XDRDetectionQuery -Query "DeviceLogonEvents | join (workspace('other').SecurityEvent) on DeviceName" -AccessToken 'test-token'
            $result.FailureKind    | Should -Be 'CrossWorkspaceDependency'
            $result.ServiceMessage | Should -Be 'The request had some invalid properties. .'
        }

        It 'Should abandon the batch after a permission failure instead of burning quota' {
            $script:Attempts = 0
            Mock -ModuleName SentinelToXDR -CommandName Invoke-S2XRestRequest -MockWith {
                $script:Attempts++
                throw 'POST failed with HTTP 403. Forbidden.'
            }
            Mock -ModuleName SentinelToXDR -CommandName Start-Sleep -MockWith { }

            $detections = 1..4 | ForEach-Object {
                [PSCustomObject]@{
                    PSTypeName = 'SentinelToXDR.CustomDetection'
                    RuleName   = "Rule $_"; Id = "id-$_"; Blocked = $false
                    Rule       = [ordered]@{ id = "id-$_"; queryCondition = @{ queryText = 'DeviceEvents' } }
                }
            }

            $results = @($detections | Test-XDRDetectionQuery -AccessToken 'test-token' -ErrorAction SilentlyContinue)

            $script:Attempts | Should -Be 1 -Because 'four identical 403s teach nothing and still cost quota'
            $results[0].FailureKind | Should -Be 'Permission'
            @($results[1..3].FailureKind) | Should -Be @('NotAttempted', 'NotAttempted', 'NotAttempted')
        }

        It 'Should report a detection that carries no query without calling the service' {
            Mock -ModuleName SentinelToXDR -CommandName Invoke-S2XRestRequest -MockWith {
                $script:Calls.Add([PSCustomObject]@{ Uri = $Uri })
                [PSCustomObject]@{ results = @() }
            }

            $empty = [PSCustomObject]@{
                PSTypeName = 'SentinelToXDR.CustomDetection'
                RuleName   = 'Empty'; Id = 'empty-1'; Blocked = $false
                Rule       = [ordered]@{ id = 'empty-1'; queryCondition = @{ queryText = '' } }
            }

            $result = $empty | Test-XDRDetectionQuery -AccessToken 'test-token'

            $script:Calls.Count | Should -Be 0
            $result.FailureKind | Should -Be 'NoQuery'
        }
    }

    # -------------------------------------------------------------------------------------
    Context 'Invoke-S2XRestRequest — transport behaviour' {

        It 'Should retry a 429 and then succeed' {
            $script:Attempts = 0
            Mock -ModuleName SentinelToXDR -CommandName Start-Sleep -MockWith { }
            Mock -ModuleName SentinelToXDR -CommandName Invoke-RestMethod -MockWith {
                $script:Attempts++
                if ($script:Attempts -lt 3) {
                    $response = [System.Net.Http.HttpResponseMessage]::new([System.Net.HttpStatusCode]::TooManyRequests)
                    throw [Microsoft.PowerShell.Commands.HttpResponseException]::new('Too Many Requests', $response)
                }
                [PSCustomObject]@{ id = 'ok' }
            }

            $result = InModuleScope SentinelToXDR {
                Invoke-S2XRestRequest -Uri 'https://graph.microsoft.com/beta/x' -Audience 'Graph' -AccessToken 'test-token'
            }

            $script:Attempts | Should -Be 3 -Because 'custom detection writes are rate limited; a batch must survive a 429'
            $result.id       | Should -Be 'ok'
        }

        It 'Should not retry a 400, and should surface the response body' {
            $script:Attempts = 0
            Mock -ModuleName SentinelToXDR -CommandName Start-Sleep -MockWith { }
            Mock -ModuleName SentinelToXDR -CommandName Invoke-RestMethod -MockWith {
                $script:Attempts++
                $response = [System.Net.Http.HttpResponseMessage]::new([System.Net.HttpStatusCode]::BadRequest)
                throw [Microsoft.PowerShell.Commands.HttpResponseException]::new('Bad Request', $response)
            }

            {
                InModuleScope SentinelToXDR {
                    Invoke-S2XRestRequest -Uri 'https://graph.microsoft.com/beta/x' -Audience 'Graph' -AccessToken 'test-token'
                }
            } | Should -Throw -ExpectedMessage '*HTTP 400*'

            $script:Attempts | Should -Be 1 -Because 'a 400 will never succeed on a retry'
        }

        It 'Should keep only the body when the Graph SDK hands over the raw HTTP response' {
            # Observed 2026-09-16: Invoke-MgGraphRequest puts the status line and every
            # header in ErrorDetails, fifteen deprecation links before the JSON body.
            Mock -ModuleName SentinelToXDR -CommandName Start-Sleep -MockWith { }
            Mock -ModuleName SentinelToXDR -CommandName Invoke-RestMethod -MockWith {
                $response = [System.Net.Http.HttpResponseMessage]::new([System.Net.HttpStatusCode]::BadRequest)
                $exception = [Microsoft.PowerShell.Commands.HttpResponseException]::new('Bad Request', $response)
                $record = [System.Management.Automation.ErrorRecord]::new($exception, 'BadRequest', 'InvalidOperation', $null)
                $raw = "POST https://graph.microsoft.com/beta/x HTTP/1.1 400 Bad Request`r`nTransfer-Encoding: chunked`r`n" +
                    "Link: <https://developer.microsoft-tst.com/en-us/graph/changes>;rel=`"deprecation`"`r`n" +
                    "Content-Type: application/json`r`n`r`n" +
                    '{"error":{"code":"BadRequest","message":"Unknown function: ''_MyOrgDeviceBaseline''."}}'
                $record.ErrorDetails = [System.Management.Automation.ErrorDetails]::new($raw)
                throw $record
            }

            $thrown = $null
            try {
                InModuleScope SentinelToXDR {
                    Invoke-S2XRestRequest -Uri 'https://graph.microsoft.com/beta/x' -Audience 'Graph' -AccessToken 'test-token'
                }
            } catch { $thrown = $_.Exception.Message }

            $thrown | Should -Match 'HTTP 400'
            $thrown | Should -Match 'Response body: \{"error"'
            $thrown | Should -Not -Match 'deprecation' -Because 'the headers say nothing about why the call failed'
            $thrown | Should -Not -Match 'Transfer-Encoding'
        }

        It 'Should explain a missing scope rather than leave the caller to decode a 403' {
            Mock -ModuleName SentinelToXDR -CommandName Start-Sleep -MockWith { }
            Mock -ModuleName SentinelToXDR -CommandName Invoke-RestMethod -MockWith {
                $response = [System.Net.Http.HttpResponseMessage]::new([System.Net.HttpStatusCode]::Forbidden)
                $exception = [Microsoft.PowerShell.Commands.HttpResponseException]::new('Forbidden', $response)
                $record = [System.Management.Automation.ErrorRecord]::new($exception, 'Forbidden', 'InvalidOperation', $null)
                $record.ErrorDetails = [System.Management.Automation.ErrorDetails]::new('{"error":{"message":"Missing application scopes"}}')
                throw $record
            }

            {
                InModuleScope SentinelToXDR {
                    Invoke-S2XRestRequest -Uri 'https://graph.microsoft.com/beta/x' -Audience 'Graph' -AccessToken 'test-token'
                }
            } | Should -Throw -ExpectedMessage '*Connect-SentinelToXDR*'
        }
    }
}
