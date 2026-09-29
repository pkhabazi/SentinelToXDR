function Get-S2XRequiredScope {
    <#
    .SYNOPSIS
        The Microsoft Graph permissions this module needs, and what each one is for.

    .DESCRIPTION
        Kept in one place so the connect cmdlet, the error messages and the documentation
        cannot drift apart. When a call fails with "missing application scopes", the message
        the user sees is generated from this list.

    .PARAMETER Purpose
        Filter to the scopes needed for a particular job:
          Read   - assess and validate queries, nothing written
          Write  - deploy, update and remove custom detections
          All    - everything (default)
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter()]
        [ValidateSet('Read', 'Write', 'All')]
        [string]$Purpose = 'All'
    )

    $scopes = @(
        [PSCustomObject]@{
            Scope   = 'ThreatHunting.Read.All'
            Purpose = 'Read'
            UsedBy  = 'Test-XDRDetectionQuery'
            Reason  = 'Runs a converted rule''s KQL through advanced hunting to prove it executes.'
        }
        [PSCustomObject]@{
            Scope   = 'CustomDetection.ReadWrite.All'
            Purpose = 'Write'
            UsedBy  = 'Get/New/Set/Remove-XDRCustomDetection'
            Reason  = 'Reads and manages custom detection rules.'
        }
    )

    if ($Purpose -eq 'All') { return $scopes }
    if ($Purpose -eq 'Read') { return @($scopes | Where-Object { $_.Purpose -eq 'Read' }) }
    return $scopes
}
