function Get-S2XAccessToken {
    <#
    .SYNOPSIS
        Resolves an OAuth access token for an audience, without taking a hard module dependency.

    .DESCRIPTION
        The module talks to two APIs, and they have very different auth stories.

        Azure Resource Manager (reading Sentinel analytics rules) is easy: an Az.Accounts
        sign-in already carries what is needed.

        Microsoft Graph (custom detections and advanced hunting) is not. The Az PowerShell
        client is a first-party app with a FIXED set of Graph permissions, and neither
        ThreatHunting.Read.All nor CustomDetection.ReadWrite.All is among them. No amount of
        re-running Get-AzAccessToken will produce a token that carries them: the app has no
        consent for those scopes, so the request comes back 403 "Missing application scopes"
        listing the ones it does have. That is a property of the Az client, not a bug here.

        So Graph tokens come from a source that can actually hold the scopes:
          1. An explicit -AccessToken from the caller. Always wins. This is the CI path.
          2. A token cached by Connect-SentinelToXDR.
          3. A Microsoft.Graph.Authentication session (Connect-MgGraph), used through
             Invoke-MgGraphRequest so no raw token is ever handled. Resolved by the request
             layer rather than here.
          4. Az.Accounts, as a last resort, with an error that explains the scope problem
             rather than letting the caller rediscover it from a 403.

        No token is written to disk, and none is logged.

    .PARAMETER Audience
        Which API the token is for: 'Arm' or 'Graph'.

    .PARAMETER AccessToken
        An explicit bearer token supplied by the caller. Accepts a SecureString or a plain
        string; a plain string is converted immediately and not retained.

    .OUTPUTS
        String bearer token.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Arm', 'Graph')]
        [string]$Audience,

        [Parameter()]
        [AllowNull()]
        [object]$AccessToken
    )

    $resourceUrl = switch ($Audience) {
        'Arm'   { 'https://management.azure.com' }
        'Graph' { 'https://graph.microsoft.com' }
    }

    # 1. Explicit token.
    if ($null -ne $AccessToken -and '' -ne $AccessToken) {
        if ($AccessToken -is [securestring]) {
            return [System.Net.NetworkCredential]::new('', $AccessToken).Password
        }
        return [string]$AccessToken
    }

    # 2. Session cache from Connect-SentinelToXDR.
    if ($script:S2XTokenCache -and $script:S2XTokenCache[$Audience]) {
        $cached = $script:S2XTokenCache[$Audience]
        if ($cached.Expires -gt (Get-Date).AddMinutes(2)) {
            return $cached.Token
        }
        Write-Verbose "Cached $Audience token has expired or is about to; falling through."
    }

    # 3. Az.Accounts context, only if the module is already installed.
    $azCommand = Get-Command -Name 'Get-AzAccessToken' -ErrorAction SilentlyContinue
    if ($azCommand) {
        try {
            # Az 12+ returns the token as a SecureString by default.
            $azToken = Get-AzAccessToken -ResourceUrl $resourceUrl -ErrorAction Stop
            if ($Audience -eq 'Graph') {
                Write-Verbose ('Using an Az.Accounts Graph token. The Az client cannot hold ' +
                    'ThreatHunting.Read.All or CustomDetection.ReadWrite.All, so this will 403 ' +
                    'unless the operation needs neither. Run Connect-SentinelToXDR instead.')
            }
            if ($azToken.Token -is [securestring]) {
                return [System.Net.NetworkCredential]::new('', $azToken.Token).Password
            }
            return [string]$azToken.Token
        } catch {
            Write-Verbose "Get-AzAccessToken failed for $resourceUrl : $($_.Exception.Message)"
        }
    }

    if ($Audience -eq 'Arm') {
        throw ("No access token available for Azure Resource Manager ($resourceUrl). " +
            'Sign in with Connect-AzAccount, or pass -AccessToken.')
    }

    $scopeList = (Get-S2XRequiredScope).Scope -join ', '
    throw ("No Microsoft Graph token available. Run Connect-SentinelToXDR to sign in with the " +
        "scopes this module needs ($scopeList), or pass -AccessToken with a token that already " +
        "carries them. Note that an Az.Accounts sign-in cannot supply these scopes: the Az " +
        'client application has no consent for them.')
}
