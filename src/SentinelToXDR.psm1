<#
.SYNOPSIS
PowerShell module for converting Microsoft Sentinel analytics rules to XDR custom detection format.

.DESCRIPTION
The SentinelToXDR module provides cmdlets to convert Microsoft Sentinel Scheduled and NRT
analytics rules (community YAML format or ARM template JSON format) into XDR custom detection
YAML files that conform to the XDR custom detection schema.

Conversion gaps (multiple tactics, query compatibility, frequency rounding, trigger threshold,
unsupported entity types) are handled automatically with warnings and interactive confirmations
where appropriate.
#>

# Get module root directory
$script:ModuleRoot = $PSScriptRoot

# Dot-source private then public functions via auto-discovery
foreach ($scope in 'Private', 'Public') {
    $scopePath = Join-Path -Path $script:ModuleRoot -ChildPath $scope
    if (Test-Path -Path $scopePath) {
        Get-ChildItem -Path $scopePath -Filter '*.ps1' -File | ForEach-Object {
            . $_.FullName
        }
    }
}

# Export only public functions (match filenames without extension)
$publicFunctions = (Get-ChildItem -Path (Join-Path $script:ModuleRoot 'Public') -Filter '*.ps1' -File).BaseName
Export-ModuleMember -Function $publicFunctions
