Describe 'SentinelToXDR Module' {

    BeforeAll {
        $repoRoot = Split-Path -Path $PSScriptRoot -Parent
        $ModulePath = Join-Path -Path $repoRoot -ChildPath 'src' -AdditionalChildPath 'SentinelToXDR.psd1'
        Import-Module -Name $ModulePath -Force -ErrorAction Stop
    }

    AfterAll {
        Remove-Module -Name SentinelToXDR -Force -ErrorAction SilentlyContinue
    }

    Context 'Module Loading' {

        It 'Should load the module successfully' {
            Get-Module -Name 'SentinelToXDR' | Should -Not -BeNullOrEmpty
        }

        It 'Should export exactly the documented public surface' {
            $module = Get-Module -Name 'SentinelToXDR'
            $exportedFunctions = @($module.ExportedFunctions.Keys)

            # Source -> assess -> convert -> export -> deploy, plus the connect helper.
            $expected = @(
                'Connect-SentinelToXDR'
                'ConvertTo-XDRCustomDetection'
                'Export-XDRCustomDetection'
                'Export-XDRMigrationReport'
                'Get-SentinelAnalyticsRule'
                'Get-SentinelToXDRContext'
                'Get-XDRCustomDetection'
                'Invoke-SentinelToXDRMigration'
                'New-XDRCustomDetection'
                'Remove-XDRCustomDetection'
                'Set-XDRCustomDetection'
                'Test-XDRDetectionQuery'
                'Test-XDRMigrationReadiness'
            )

            foreach ($name in $expected) {
                $exportedFunctions | Should -Contain $name
            }

            # Nothing private leaks out.
            ($exportedFunctions | Sort-Object) -join ',' | Should -Be (($expected | Sort-Object) -join ',')
        }

        It 'Should require powershell-yaml module' {
            $moduleInfo = Get-Module -Name 'SentinelToXDR'
            $requiredModules = $moduleInfo.RequiredModules.Name
            $requiredModules | Should -Contain 'powershell-yaml'
        }

        It 'ConvertTo-XDRCustomDetection should exist and be callable' {
            $cmd = Get-Command -Name 'ConvertTo-XDRCustomDetection' -ErrorAction SilentlyContinue
            $cmd | Should -Not -BeNullOrEmpty
            $cmd.CommandType | Should -Be 'Function'
        }

        It 'ConvertTo-XDRCustomDetection should support -WhatIf' {
            $cmd = Get-Command -Name 'ConvertTo-XDRCustomDetection'
            $cmd.Parameters.ContainsKey('WhatIf') | Should -Be $true
        }

        It 'ConvertTo-XDRCustomDetection should support -Force' {
            $cmd = Get-Command -Name 'ConvertTo-XDRCustomDetection'
            $cmd.Parameters.ContainsKey('Force') | Should -Be $true
        }
    }
}
