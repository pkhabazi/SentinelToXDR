function Invoke-S2XRestRequest {
    <#
    .SYNOPSIS
        Issues a REST request against ARM or Microsoft Graph, with paging and retry.

    .DESCRIPTION
        A thin wrapper over Invoke-RestMethod that adds the three things every caller in
        this module needs and none of them should reimplement:

          - Bearer auth resolved through Get-S2XAccessToken.
          - Automatic paging. ARM pages with 'nextLink', Graph with '@odata.nextLink'.
            With -Paginate the function follows both and emits every item from the
            'value' array as it goes.
          - Retry with backoff on 429 and 5xx, honouring a Retry-After header when the
            service supplies one. Custom detection writes are rate limited, so a batch
            deployment without this fails partway through a large run.

        Errors are rethrown with the response body attached, because the Graph error body
        is where the actual reason lives (an invalid entity column name, for example).

    .PARAMETER Uri
        Absolute request URI.

    .PARAMETER Method
        HTTP method. Defaults to GET.

    .PARAMETER Body
        Request body object. Serialized to JSON with sufficient depth for the nested
        detectionRule shape.

    .PARAMETER Audience
        Token audience: 'Arm' or 'Graph'.

    .PARAMETER AccessToken
        Explicit bearer token, passed through to Get-S2XAccessToken.

    .PARAMETER Paginate
        Follow nextLink / @odata.nextLink and emit every item in each page's value array.

    .PARAMETER MaxRetry
        How many times to retry a throttled or transient failure. Default 5.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Uri,

        [Parameter()]
        [ValidateSet('GET', 'POST', 'PATCH', 'PUT', 'DELETE')]
        [string]$Method = 'GET',

        [Parameter()]
        [AllowNull()]
        [object]$Body,

        [Parameter(Mandatory)]
        [ValidateSet('Arm', 'Graph')]
        [string]$Audience,

        [Parameter()]
        [AllowNull()]
        [object]$AccessToken,

        [Parameter()]
        [switch]$Paginate,

        [Parameter()]
        [int]$MaxRetry = 5
    )

    # Prefer a Microsoft.Graph.Authentication session for Graph calls: Invoke-MgGraphRequest
    # attaches the auth itself, so a delegated sign-in with the right scopes works without
    # this module ever touching a raw token. An explicit -AccessToken or a token cached by
    # Connect-SentinelToXDR still wins, because the caller asked for it by name.
    $useGraphSdk = $false
    if ($Audience -eq 'Graph' -and -not $AccessToken -and
        -not ($script:S2XTokenCache -and $script:S2XTokenCache['Graph'])) {
        $mgContext = $null
        if (Get-Command -Name 'Get-MgContext' -ErrorAction SilentlyContinue) {
            try { $mgContext = Get-MgContext -ErrorAction SilentlyContinue } catch { $mgContext = $null }
        }
        if ($mgContext -and (Get-Command -Name 'Invoke-MgGraphRequest' -ErrorAction SilentlyContinue)) {
            $useGraphSdk = $true
            Write-Verbose "Using the Microsoft Graph session signed in as $($mgContext.Account)."
        }
    }

    $headers = @{ Accept = 'application/json' }
    if (-not $useGraphSdk) {
        $token = Get-S2XAccessToken -Audience $Audience -AccessToken $AccessToken
        $headers['Authorization'] = "Bearer $token"
    }

    $jsonBody = if ($null -ne $Body) {
        if ($Body -is [string]) { $Body } else { $Body | ConvertTo-Json -Depth 20 }
    } else {
        $null
    }

    $nextUri = $Uri
    while ($nextUri) {
        $attempt = 0
        $response = $null

        while ($true) {
            $attempt++
            try {
                if ($useGraphSdk) {
                    $params = @{
                        Uri         = $nextUri
                        Method      = $Method
                        OutputType  = 'PSObject'
                        ErrorAction = 'Stop'
                    }
                    if ($null -ne $jsonBody) {
                        $params['Body']        = $jsonBody
                        $params['ContentType'] = 'application/json; charset=utf-8'
                    }
                    $response = Invoke-MgGraphRequest @params
                } else {
                    $params = @{
                        Uri         = $nextUri
                        Method      = $Method
                        Headers     = $headers
                        ErrorAction = 'Stop'
                    }
                    if ($null -ne $jsonBody) {
                        $params['Body']        = $jsonBody
                        $params['ContentType'] = 'application/json; charset=utf-8'
                    }
                    $response = Invoke-RestMethod @params
                }
                break
            } catch {
                $statusCode = 0
                if ($_.Exception.PSObject.Properties['Response'] -and $_.Exception.Response) {
                    $statusCode = [int]$_.Exception.Response.StatusCode
                }

                $isRetryable = $statusCode -eq 429 -or ($statusCode -ge 500 -and $statusCode -le 599)
                if ($isRetryable -and $attempt -le $MaxRetry) {
                    $delay = [Math]::Pow(2, $attempt)
                    if ($_.Exception.Response -and $_.Exception.Response.Headers) {
                        $retryAfter = $_.Exception.Response.Headers | Where-Object { $_.Key -ieq 'Retry-After' } | Select-Object -First 1
                        if ($retryAfter -and $retryAfter.Value) {
                            $parsed = 0
                            if ([int]::TryParse(@($retryAfter.Value)[0], [ref]$parsed) -and $parsed -gt 0) { $delay = $parsed }
                        }
                    }
                    Write-Verbose "HTTP $statusCode from $nextUri; retry $attempt of $MaxRetry in ${delay}s."
                    Start-Sleep -Seconds $delay
                    continue
                }

                # Surface the response body: for Graph it names the offending property.
                $detail = ''
                try {
                    if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $detail = $_.ErrorDetails.Message }
                } catch { $detail = '' }

                # Invoke-MgGraphRequest puts the whole raw response in ErrorDetails: the
                # status line and every header (fifteen deprecation links, observed
                # 2026-09-16) before the body. Only the body says why the call failed.
                if ($detail -match '^\s*(GET|POST|PATCH|PUT|DELETE)\s+\S+\s+HTTP/\d') {
                    $bodyStart = $detail.IndexOfAny([char[]]@('{', '['))
                    $detail = if ($bodyStart -ge 0) { $detail.Substring($bodyStart).Trim() } else { '' }
                }

                $message = "$Method $nextUri failed with HTTP $statusCode. $($_.Exception.Message)"
                if ($detail) { $message += " Response body: $detail" }

                # The single most common failure, and the least self-explanatory: a token
                # that authenticated fine but carries none of the scopes this module needs.
                # Usually an Az.Accounts token, whose client app cannot hold them at all.
                if ($Audience -eq 'Graph' -and $detail -match 'Missing application scopes|insufficient privileges|Authorization_RequestDenied') {
                    $needed = (Get-S2XRequiredScope).Scope -join ', '
                    $message += ("`n`nThe token authenticated but lacks the required scope(s): $needed. " +
                        'If this came from Connect-AzAccount, that is expected and cannot be fixed by ' +
                        'retrying: the Az client application has no consent for these permissions. ' +
                        'Run Connect-SentinelToXDR to sign in with them, or pass -AccessToken with a ' +
                        'token that already carries them.')
                }

                throw $message
            }
        }

        if (-not $Paginate) {
            return $response
        }

        if ($null -ne $response -and $response.PSObject.Properties['value']) {
            foreach ($item in $response.value) { $item }
        } elseif ($null -ne $response) {
            $response
        }

        $nextUri = $null
        if ($null -ne $response) {
            if ($response.PSObject.Properties['nextLink'] -and $response.nextLink) {
                $nextUri = [string]$response.nextLink
            } elseif ($response.PSObject.Properties['@odata.nextLink'] -and $response.'@odata.nextLink') {
                $nextUri = [string]$response.'@odata.nextLink'
            }
        }
        # Paging is always a GET, and the body must not be resent on the next page.
        $Method = 'GET'
        $jsonBody = $null
    }
}
