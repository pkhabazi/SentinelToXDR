function Get-SentinelToXDRContext {
    <#
    .SYNOPSIS
        Reports how the module will authenticate, and whether it has what it needs.

    .DESCRIPTION
        Answers "am I connected, to what, and can I actually do the thing I am about to do"
        before a call fails with a 403 that takes ten minutes to interpret.

        It reports the sign-in in use, the tenant and account, the Graph scopes granted, and
        which of this module's operations those scopes permit. Token VALUES are never
        returned or displayed.

        The check worth paying attention to is CanValidateQueries / CanManageDetections. A
        sign-in that looks healthy can still be missing the one scope you need, and an
        Az.Accounts sign-in is always missing both.

    .EXAMPLE
        Get-SentinelToXDRContext

        What am I connected as, and what can I do?

    .EXAMPLE
        (Get-SentinelToXDRContext).CanManageDetections

        Gate a deployment script on having write access.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    $mode = if ($script:S2XAuthMode) { $script:S2XAuthMode } else { 'None' }
    $account = ''
    $tenantId = ''
    $grantedScopes = @()

    # A Graph SDK session is authoritative about who is signed in and what was granted.
    if (Get-Command -Name 'Get-MgContext' -ErrorAction SilentlyContinue) {
        $context = $null
        try { $context = Get-MgContext -ErrorAction SilentlyContinue } catch { $context = $null }
        if ($context) {
            $account = [string]$context.Account
            $tenantId = [string]$context.TenantId
            $grantedScopes = @($context.Scopes)
            if ($mode -eq 'None') { $mode = 'MgGraph' }
        }
    }

    # A cached token from Connect-SentinelToXDR: we know it exists and when it expires, but
    # not what is inside it, and this cmdlet does not crack tokens open to find out.
    $graphCached = [bool]($script:S2XTokenCache -and $script:S2XTokenCache['Graph'])
    $armCached   = [bool]($script:S2XTokenCache -and $script:S2XTokenCache['Arm'])
    $expiresOn   = if ($graphCached) { $script:S2XTokenCache['Graph'].Expires } else { $null }

    # Fall back to reporting the Az sign-in, which covers ARM and never covers Graph.
    $azAccount = ''
    if (Get-Command -Name 'Get-AzContext' -ErrorAction SilentlyContinue) {
        $azContext = $null
        try { $azContext = Get-AzContext -ErrorAction SilentlyContinue } catch { $azContext = $null }
        if ($azContext) { $azAccount = [string]$azContext.Account.Id }
    }

    $required = Get-S2XRequiredScope
    $readScope  = ($required | Where-Object Purpose -eq 'Read').Scope
    $writeScope = ($required | Where-Object Purpose -eq 'Write').Scope

    # With an opaque cached token we cannot enumerate scopes, so we report "unknown" as
    # $null rather than claiming a capability the token may not have.
    $canRead  = if ($grantedScopes.Count -gt 0) { $readScope  -in $grantedScopes } elseif ($graphCached) { $null } else { $false }
    $canWrite = if ($grantedScopes.Count -gt 0) { $writeScope -in $grantedScopes } elseif ($graphCached) { $null } else { $false }

    [PSCustomObject]@{
        PSTypeName          = 'SentinelToXDR.Context'
        AuthMode            = $mode
        Account             = if ($account) { $account } else { $azAccount }
        TenantId            = $tenantId
        GraphScopes         = $grantedScopes
        GraphToken          = if ($graphCached) { 'cached' } elseif ($grantedScopes.Count -gt 0) { 'graph session' } else { 'none' }
        ArmToken            = if ($armCached) { 'cached' } elseif ($azAccount) { 'az sign-in' } else { 'none' }
        ExpiresOn           = $expiresOn
        CanReadSentinelRules = [bool]($armCached -or $azAccount)
        CanValidateQueries  = $canRead
        CanManageDetections = $canWrite
        MissingScopes       = @($required.Scope | Where-Object { $grantedScopes.Count -gt 0 -and $_ -notin $grantedScopes })
    }
}
