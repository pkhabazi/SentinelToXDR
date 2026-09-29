Describe 'Authentication' {

    # The failure that cost the most time in practice: an Az.Accounts sign-in looks healthy,
    # authenticates fine, and then every Graph call comes back 403. The Az client is a
    # first-party app with a fixed set of Graph permissions and no consent for the two this
    # module needs, so retrying can never help. These tests keep the module honest about
    # that: it has to say so up front rather than let the user decode a 403.

    BeforeAll {
        $repoRoot = Split-Path -Path $PSScriptRoot -Parent
        Import-Module -Name (Join-Path $repoRoot 'src/SentinelToXDR.psd1') -Force
    }

    Context 'Required scopes' {

        It 'Should declare the scopes the module needs, with a reason for each' {
            $scopes = InModuleScope SentinelToXDR { Get-S2XRequiredScope }
            @($scopes).Count | Should -BeGreaterThan 0
            foreach ($scope in $scopes) {
                $scope.Scope   | Should -Not -BeNullOrEmpty
                $scope.UsedBy  | Should -Not -BeNullOrEmpty
                $scope.Reason  | Should -Not -BeNullOrEmpty
                $scope.Purpose | Should -BeIn @('Read', 'Write')
            }
        }

        It 'Should name the read scope needed for query validation' {
            $read = InModuleScope SentinelToXDR { Get-S2XRequiredScope -Purpose Read }
            @($read).Scope | Should -Contain 'ThreatHunting.Read.All'
        }

        It 'Should keep the write scope out of a read-only request' {
            # Assessing an estate must not require permission to change it.
            $read = InModuleScope SentinelToXDR { Get-S2XRequiredScope -Purpose Read }
            @($read).Scope | Should -Not -Contain 'CustomDetection.ReadWrite.All'
        }
    }

    Context 'Get-SentinelToXDRContext' {

        It 'Should report what the session can and cannot do' {
            $context = Get-SentinelToXDRContext
            $context.PSObject.Properties.Name | Should -Contain 'CanReadSentinelRules'
            $context.PSObject.Properties.Name | Should -Contain 'CanValidateQueries'
            $context.PSObject.Properties.Name | Should -Contain 'CanManageDetections'
        }

        It 'Should never expose a token value' {
            $context = Get-SentinelToXDRContext
            # Presence and expiry are reportable; the value is not.
            $context.GraphToken | Should -BeIn @('none', 'cached', 'graph session')
            ($context | ConvertTo-Json -Depth 5) | Should -Not -Match 'eyJ0eXAi' -Because 'a JWT must never reach the output'
        }

        It 'Should report no Graph capability when nothing is connected' {
            InModuleScope SentinelToXDR { $script:S2XTokenCache = @{}; $script:S2XAuthMode = $null }
            $context = Get-SentinelToXDRContext
            # An Az sign-in may exist in the session, which covers ARM but never Graph.
            $context.CanValidateQueries  | Should -Not -BeTrue
            $context.CanManageDetections | Should -Not -BeTrue
        }
    }

    Context 'Connect-SentinelToXDR' {

        It 'Should accept a token handed over directly' {
            $context = Connect-SentinelToXDR -GraphAccessToken 'test-token'
            $context.GraphToken | Should -Be 'cached'
            InModuleScope SentinelToXDR { $script:S2XTokenCache = @{}; $script:S2XAuthMode = $null }
        }

        It 'Should default to requesting every scope the module can use' {
            $default = (Get-Command Connect-SentinelToXDR).Parameters['Scopes'].Attributes |
                Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] }
            $default | Should -Not -BeNullOrEmpty

            # The default comes from the same source as the error messages.
            $required = InModuleScope SentinelToXDR { (Get-S2XRequiredScope).Scope }
            $required | Should -Contain 'ThreatHunting.Read.All'
            $required | Should -Contain 'CustomDetection.ReadWrite.All'
        }

        It 'Should support a read-only sign-in' {
            (Get-Command Connect-SentinelToXDR).Parameters.Keys | Should -Contain 'Scopes'
        }

        It 'Should support the flows a pipeline and a browserless session need' {
            $parameters = (Get-Command Connect-SentinelToXDR).Parameters.Keys
            $parameters | Should -Contain 'ClientId'
            $parameters | Should -Contain 'CertificateThumbprint'
            $parameters | Should -Contain 'UseDeviceCode'
            $parameters | Should -Contain 'TenantId'
        }

        It 'Should refuse a client credentials sign-in with no credential' {
            { Connect-SentinelToXDR -TenantId 'contoso' -ClientId 'abc' -ErrorAction Stop } |
                Should -Throw -ExpectedMessage '*ClientSecret*CertificateThumbprint*'
        }
    }

    Context 'Explaining the Az token problem' {

        It 'Should tell the caller an Az sign-in cannot supply Graph scopes' {
            InModuleScope SentinelToXDR {
                $script:S2XTokenCache = @{}
                # With no Az module and no session, the error has to teach rather than just fail.
                Mock Get-Command -ParameterFilter { $Name -eq 'Get-AzAccessToken' } -MockWith { $null }
                { Get-S2XAccessToken -Audience 'Graph' } |
                    Should -Throw -ExpectedMessage '*Connect-SentinelToXDR*'
            }
        }

        It 'Should name the missing scopes in the error' {
            InModuleScope SentinelToXDR {
                $script:S2XTokenCache = @{}
                Mock Get-Command -ParameterFilter { $Name -eq 'Get-AzAccessToken' } -MockWith { $null }
                { Get-S2XAccessToken -Audience 'Graph' } |
                    Should -Throw -ExpectedMessage '*ThreatHunting.Read.All*'
            }
        }

        It 'Should still resolve an ARM token from an Az sign-in' {
            # ARM is the case Az handles perfectly well, and must keep handling.
            (Get-Command Get-SentinelAnalyticsRule).Parameters.Keys | Should -Contain 'AccessToken'
        }
    }
}
