<#
.SYNOPSIS
    Authentication module for Microsoft Graph API.

.DESCRIPTION
    Provides functions to authenticate to Microsoft Graph using either
    interactive (delegated) or app-only (client credentials) flows.
    Returns an access token and headers ready for Graph REST calls.
#>

function Connect-GraphInteractive {
    <#
    .SYNOPSIS
        Authenticates to Microsoft Graph using interactive (delegated) sign-in.

    .DESCRIPTION
        Uses the Microsoft.Graph PowerShell SDK to authenticate interactively.
        Requires the user to sign in via browser. Suitable for ad-hoc runs.

    .PARAMETER TenantId
        The Azure AD tenant ID. Optional for interactive auth.

    .PARAMETER Scopes
        Graph permission scopes to request.

    .OUTPUTS
        A hashtable containing the authorization headers for Graph REST calls.

    .EXAMPLE
        $headers = Connect-GraphInteractive -TenantId "contoso.onmicrosoft.com"
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$TenantId,

        [Parameter()]
        [string[]]$Scopes = @(
            "DeviceManagementManagedDevices.ReadWrite.All",
            "Device.ReadWrite.All",
            "Directory.ReadWrite.All"
        )
    )

    try {
        $connectParams = @{ Scopes = $Scopes }
        if ($TenantId) { $connectParams.TenantId = $TenantId }

        Write-Verbose "Connecting to Microsoft Graph interactively..."
        Connect-MgGraph @connectParams -ErrorAction Stop

        $context = Get-MgContext
        if (-not $context) {
            throw "Failed to establish Graph context after interactive sign-in."
        }

        Write-Verbose "Authenticated as $($context.Account) in tenant $($context.TenantId)."

        # Build headers using the SDK's token
        $token = (Get-MgContext).AuthType
        $headers = @{ "ConsistencyLevel" = "eventual" }

        return @{
            Headers   = $headers
            AuthType  = "Interactive"
            TenantId  = $context.TenantId
            Account   = $context.Account
            UseSdk    = $true
        }
    }
    catch {
        Write-Error "Interactive authentication failed: $_"
        throw
    }
}

function Connect-GraphAppOnly {
    <#
    .SYNOPSIS
        Authenticates to Microsoft Graph using client credentials (app-only).

    .DESCRIPTION
        Obtains an OAuth2 access token using client_id and client_secret
        against the Microsoft identity platform token endpoint.
        Suitable for unattended / scheduled runs.

    .PARAMETER TenantId
        The Azure AD tenant ID (required).

    .PARAMETER ClientId
        The app registration client ID (required).

    .PARAMETER ClientSecret
        The app registration client secret (required).

    .OUTPUTS
        A hashtable containing the authorization headers for Graph REST calls.

    .EXAMPLE
        $auth = Connect-GraphAppOnly -TenantId $tid -ClientId $cid -ClientSecret $sec
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$TenantId,

        [Parameter(Mandatory)]
        [string]$ClientId,

        [Parameter(Mandatory)]
        [string]$ClientSecret
    )

    $tokenUrl = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"

    $body = @{
        grant_type    = "client_credentials"
        client_id     = $ClientId
        client_secret = $ClientSecret
        scope         = "https://graph.microsoft.com/.default"
    }

    try {
        Write-Verbose "Requesting app-only token from $tokenUrl..."
        $response = Invoke-RestMethod -Method Post -Uri $tokenUrl -Body $body -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop

        if (-not $response.access_token) {
            throw "Token response did not contain an access_token."
        }

        $headers = @{
            "Authorization"    = "Bearer $($response.access_token)"
            "Content-Type"     = "application/json"
            "ConsistencyLevel" = "eventual"
        }

        # Calculate token expiry
        $expiresOn = (Get-Date).AddSeconds($response.expires_in)
        Write-Verbose "App-only token acquired. Expires at $expiresOn."

        return @{
            Headers    = $headers
            AuthType   = "AppOnly"
            TenantId   = $TenantId
            ExpiresOn  = $expiresOn
            UseSdk     = $false
        }
    }
    catch {
        Write-Error "App-only authentication failed: $_"
        throw
    }
}

function Invoke-GraphRequest {
    <#
    .SYNOPSIS
        Sends a request to Microsoft Graph with automatic retry on throttling.

    .DESCRIPTION
        Wraps Invoke-RestMethod with retry logic for HTTP 429 (Too Many Requests)
        and transient 5xx errors. Uses exponential backoff with jitter.

    .PARAMETER Uri
        The full Graph API URI.

    .PARAMETER Method
        HTTP method (GET, POST, PATCH, DELETE).

    .PARAMETER Headers
        Authorization and content-type headers.

    .PARAMETER Body
        Request body (for POST/PATCH). Will be serialized to JSON if a hashtable.

    .PARAMETER MaxRetries
        Maximum number of retry attempts. Default is 5.

    .OUTPUTS
        The deserialized response from Graph API.

    .EXAMPLE
        $devices = Invoke-GraphRequest -Uri $uri -Method GET -Headers $headers
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Uri,

        [Parameter()]
        [ValidateSet("GET", "POST", "PATCH", "DELETE")]
        [string]$Method = "GET",

        [Parameter(Mandatory)]
        [hashtable]$Headers,

        [Parameter()]
        $Body,

        [Parameter()]
        [int]$MaxRetries = 5
    )

    $attempt = 0

    while ($true) {
        $attempt++
        try {
            $requestParams = @{
                Uri         = $Uri
                Method      = $Method
                Headers     = $Headers
                ErrorAction = "Stop"
            }

            if ($Body) {
                if ($Body -is [hashtable] -or $Body -is [pscustomobject]) {
                    $requestParams.Body = ($Body | ConvertTo-Json -Depth 10)
                }
                else {
                    $requestParams.Body = $Body
                }
                if (-not $Headers.ContainsKey("Content-Type")) {
                    $requestParams.ContentType = "application/json"
                }
            }

            Write-Verbose "Graph API $Method $Uri (attempt $attempt)"
            $response = Invoke-RestMethod @requestParams
            return $response
        }
        catch {
            $statusCode = $null
            if ($_.Exception.Response) {
                $statusCode = [int]$_.Exception.Response.StatusCode
            }

            $isThrottled = $statusCode -eq 429
            $isTransient = $statusCode -ge 500 -and $statusCode -lt 600

            if (($isThrottled -or $isTransient) -and $attempt -le $MaxRetries) {
                # Check for Retry-After header
                $retryAfter = $null
                if ($_.Exception.Response.Headers) {
                    $retryHeader = $_.Exception.Response.Headers | Where-Object { $_.Key -eq "Retry-After" }
                    if ($retryHeader) {
                        $retryAfter = [int]$retryHeader.Value[0]
                    }
                }

                if (-not $retryAfter) {
                    # Exponential backoff with jitter: 2^attempt + random(0-1) seconds
                    $retryAfter = [math]::Pow(2, $attempt) + (Get-Random -Minimum 0 -Maximum 1000) / 1000
                }

                $reasonText = if ($isThrottled) { "throttled (429)" } else { "server error ($statusCode)" }
                Write-Warning "Graph API $reasonText. Retrying in $([math]::Round($retryAfter, 1))s (attempt $attempt/$MaxRetries)..."
                Start-Sleep -Seconds $retryAfter
                continue
            }

            # Parse error body for better diagnostics
            $errorDetail = $_.ErrorDetails.Message
            if ($errorDetail) {
                try {
                    $parsed = $errorDetail | ConvertFrom-Json
                    $graphError = $parsed.error
                    Write-Error "Graph API error ($statusCode): [$($graphError.code)] $($graphError.message)"
                }
                catch {
                    Write-Error "Graph API error ($statusCode): $errorDetail"
                }
            }
            else {
                Write-Error "Graph API request failed: $_"
            }
            throw
        }
    }
}

Export-ModuleMember -Function Connect-GraphInteractive, Connect-GraphAppOnly, Invoke-GraphRequest
