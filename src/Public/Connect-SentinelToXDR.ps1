function Connect-SentinelToXDR {
    <#
    .SYNOPSIS
        Signs in to Microsoft Graph with the scopes this module needs.

    .DESCRIPTION
        Reading Sentinel rules over ARM works fine from a Connect-AzAccount sign-in. Talking
        to Microsoft Graph does not, and this is the cmdlet that fixes that.

        The Az PowerShell client is a first-party application with a FIXED set of Graph
        permissions, and neither ThreatHunting.Read.All nor CustomDetection.ReadWrite.All is
        among them. An Az Graph token therefore comes back 403 "Missing application scopes"
        no matter how many times you retry — the client has no consent for those permissions,
        so there is nothing to re-acquire. That is a property of the Az client, not something
        this module can work around.

        Three ways in, in order of how most people will use it:

          Interactive (default)
            Signs in through Microsoft.Graph.Authentication with the required scopes. The
            module then talks to Graph through that session, so it never handles a raw
            token. Needs the Microsoft.Graph.Authentication module.

          Application
            Client credentials for CI: tenant, application id, and a client secret or a
            certificate. Acquires a token directly from the tenant's token endpoint. The
            application needs the scopes granted as APPLICATION permissions with admin
            consent.

          Token
            You already have tokens from somewhere else and just want to hand them over.

        Nothing is written to disk. Tokens are held in memory for this session only, and
        Get-SentinelToXDRContext reports the audience, scopes and expiry — never a value.

    .PARAMETER Scopes
        Graph scopes to request when signing in interactively. Defaults to everything the
        module can use. Pass a subset if you only intend to assess: ThreatHunting.Read.All
        alone is enough for Test-XDRDetectionQuery, and grants no write access at all.

    .PARAMETER TenantId
        Directory to sign in to. Worth setting explicitly when your account exists in more
        than one, which is exactly the case when a dev tenant sits beside a production one.

    .PARAMETER UseDeviceCode
        Sign in with the device code flow, for a session with no browser.

    .PARAMETER ClientId
        Application (client) id, for the client credentials flow.

    .PARAMETER ClientSecret
        Client secret for the application, as a SecureString.

    .PARAMETER CertificateThumbprint
        Certificate thumbprint for the application, as an alternative to a secret.

    .PARAMETER GraphAccessToken
        A Graph bearer token you already hold.

    .PARAMETER ArmAccessToken
        An Azure Resource Manager bearer token you already hold. Rarely needed: an
        Az.Accounts sign-in covers ARM without help.

    .PARAMETER ExpiresOn
        When supplied tokens expire, so a stale one is refused rather than failing mid-batch.
        Defaults to one hour from now.

    .EXAMPLE
        Connect-SentinelToXDR

        Interactive sign-in with every scope the module can use.

    .EXAMPLE
        Connect-SentinelToXDR -Scopes ThreatHunting.Read.All -TenantId $devTenant

        Read-only sign-in to a specific tenant: enough to validate queries, and incapable of
        writing a detection.

    .EXAMPLE
        Connect-SentinelToXDR -TenantId $tenant -ClientId $app -ClientSecret $secret

        Client credentials, for a pipeline.

    .EXAMPLE
        Connect-SentinelToXDR -GraphAccessToken $token

        Hand over a token acquired elsewhere.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Interactive')]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(ParameterSetName = 'Interactive')]
        [string[]]$Scopes = ((Get-S2XRequiredScope).Scope),

        [Parameter(ParameterSetName = 'Interactive')]
        [Parameter(ParameterSetName = 'Application')]
        [string]$TenantId,

        [Parameter(ParameterSetName = 'Interactive')]
        [switch]$UseDeviceCode,

        [Parameter(Mandatory, ParameterSetName = 'Application')]
        [string]$ClientId,

        [Parameter(ParameterSetName = 'Application')]
        [securestring]$ClientSecret,

        [Parameter(ParameterSetName = 'Application')]
        [string]$CertificateThumbprint,

        [Parameter(Mandatory, ParameterSetName = 'Token')]
        [AllowNull()]
        [object]$GraphAccessToken,

        [Parameter(ParameterSetName = 'Token')]
        [AllowNull()]
        [object]$ArmAccessToken,

        [Parameter(ParameterSetName = 'Token')]
        [datetime]$ExpiresOn = (Get-Date).AddHours(1)
    )

    if (-not $script:S2XTokenCache) { $script:S2XTokenCache = @{} }

    function ConvertTo-PlainToken {
        param([object]$Value)
        if ($Value -is [securestring]) {
            return [System.Net.NetworkCredential]::new('', $Value).Password
        }
        return [string]$Value
    }

    switch ($PSCmdlet.ParameterSetName) {

        'Token' {
            if ($GraphAccessToken) {
                $script:S2XTokenCache['Graph'] = @{ Token = (ConvertTo-PlainToken -Value $GraphAccessToken); Expires = $ExpiresOn }
            }
            if ($ArmAccessToken) {
                $script:S2XTokenCache['Arm'] = @{ Token = (ConvertTo-PlainToken -Value $ArmAccessToken); Expires = $ExpiresOn }
            }
            $script:S2XAuthMode = 'Token'
            break
        }

        'Application' {
            if (-not $TenantId) {
                throw 'The client credentials flow needs -TenantId.'
            }
            if (-not $ClientSecret -and -not $CertificateThumbprint) {
                throw 'Supply either -ClientSecret or -CertificateThumbprint for the client credentials flow.'
            }
            if ($CertificateThumbprint) {
                # Certificate auth means building and signing a client assertion, which is
                # the Graph SDK's job rather than this module's. Hand off to it.
                if (-not (Get-Command -Name 'Connect-MgGraph' -ErrorAction SilentlyContinue)) {
                    throw ('Certificate authentication needs the Microsoft.Graph.Authentication module. ' +
                        'Install it with: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser')
                }
                Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $CertificateThumbprint -NoWelcome -ErrorAction Stop
                $script:S2XAuthMode = 'MgGraph'
                break
            }

            # Client secret: a plain token request against the tenant's endpoint. The secret
            # is converted at the last moment and never stored.
            $body = @{
                client_id     = $ClientId
                scope         = 'https://graph.microsoft.com/.default'
                grant_type    = 'client_credentials'
                client_secret = [System.Net.NetworkCredential]::new('', $ClientSecret).Password
            }
            try {
                $response = Invoke-RestMethod -Method POST -ErrorAction Stop `
                    -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
                    -ContentType 'application/x-www-form-urlencoded' -Body $body
            } finally {
                $body['client_secret'] = $null
            }
            $script:S2XTokenCache['Graph'] = @{
                Token   = [string]$response.access_token
                Expires = (Get-Date).AddSeconds([int]$response.expires_in)
            }
            $script:S2XAuthMode = 'Application'
            break
        }

        default {
            if (-not (Get-Command -Name 'Connect-MgGraph' -ErrorAction SilentlyContinue)) {
                throw ('Interactive sign-in needs the Microsoft.Graph.Authentication module. ' +
                    'Install it with: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser' + "`n" +
                    'Alternatively, pass a token you already hold with -GraphAccessToken.')
            }

            $connectParams = @{ Scopes = $Scopes; NoWelcome = $true; ErrorAction = 'Stop' }
            if ($TenantId)      { $connectParams['TenantId'] = $TenantId }
            if ($UseDeviceCode) { $connectParams['UseDeviceCode'] = $true }

            Connect-MgGraph @connectParams

            # A sign-in can succeed while silently granting less than was asked for, which
            # then fails later as a 403 that looks like a module bug. Check now.
            $context = Get-MgContext
            $granted = @($context.Scopes)
            $missing = @($Scopes | Where-Object { $_ -notin $granted })
            if ($missing.Count -gt 0) {
                Write-Warning ("Signed in, but these scope(s) were not granted: $($missing -join ', '). " +
                    'Calls that need them will fail with 403. An administrator may need to consent.')
            }

            # Clear any stale cached token so the fresh session is what gets used.
            $script:S2XTokenCache.Remove('Graph')
            $script:S2XAuthMode = 'MgGraph'
            break
        }
    }

    Get-SentinelToXDRContext
}
