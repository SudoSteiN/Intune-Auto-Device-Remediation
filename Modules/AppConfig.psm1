<#
.SYNOPSIS
    Azure App Configuration module for centralized settings management.

.DESCRIPTION
    Retrieves application settings from Azure App Configuration and resolves
    Key Vault references for secrets. Supports both connection string and
    managed identity authentication.
#>

function Get-AppConfiguration {
    <#
    .SYNOPSIS
        Retrieves all settings from Azure App Configuration under a given prefix.

    .DESCRIPTION
        Connects to Azure App Configuration using either a connection string or
        an endpoint URL (managed identity). Reads all key-value pairs under the
        specified prefix and returns them as a hashtable. Key Vault references
        are automatically resolved.

    .PARAMETER Endpoint
        The App Configuration endpoint URL (e.g., https://myconfig.azconfig.io).
        Used with managed identity authentication.

    .PARAMETER ConnectionString
        The App Configuration connection string. Used for local or non-MI scenarios.

    .PARAMETER Prefix
        The key prefix to filter on. Default is "IntuneRemediation:".

    .PARAMETER AccessToken
        Optional pre-acquired access token for App Configuration. If not provided,
        one will be obtained via managed identity (Endpoint) or parsed from
        the connection string.

    .OUTPUTS
        Hashtable of configuration key-value pairs with the prefix stripped.

    .EXAMPLE
        $cfg = Get-AppConfiguration -ConnectionString $connStr
    #>
    [CmdletBinding()]
    param(
        [Parameter(ParameterSetName = "Endpoint")]
        [string]$Endpoint,

        [Parameter(ParameterSetName = "ConnectionString")]
        [string]$ConnectionString,

        [Parameter()]
        [string]$Prefix = "IntuneRemediation:",

        [Parameter()]
        [string]$AccessToken
    )

    # Determine base URL and auth headers
    if ($PSCmdlet.ParameterSetName -eq "ConnectionString" -or $ConnectionString) {
        $parsed = ConvertFrom-AppConfigConnectionString -ConnectionString $ConnectionString
        $baseUrl = $parsed.Endpoint.TrimEnd("/")
        $authHeaders = Get-HmacAuthHeaders -Credential $parsed.Credential -Secret $parsed.Secret -BaseUrl $baseUrl -Prefix $Prefix
    }
    else {
        $baseUrl = $Endpoint.TrimEnd("/")
        if (-not $AccessToken) {
            $AccessToken = Get-ManagedIdentityToken -Resource "https://azconfig.io"
        }
        $authHeaders = @{ "Authorization" = "Bearer $AccessToken" }
    }

    # Query all key-values under the prefix
    $uri = "$baseUrl/kv?key=$($Prefix)*&api-version=2023-11-01"
    Write-Verbose "Fetching App Configuration keys from: $uri"

    $response = Invoke-RestMethod -Uri $uri -Headers $authHeaders -Method GET -ErrorAction Stop

    $settings = @{}
    foreach ($item in $response.items) {
        $key = $item.key
        if ($key.StartsWith($Prefix)) {
            $key = $key.Substring($Prefix.Length)
        }

        $value = $item.value

        # Resolve Key Vault references
        $contentType = $item.content_type
        if ($contentType -and $contentType -like "*keyvaultref*") {
            Write-Verbose "Resolving Key Vault reference for '$key'..."
            $kvRef = $value | ConvertFrom-Json
            $value = Resolve-KeyVaultReference -SecretUri $kvRef.uri
        }

        $settings[$key] = $value
    }

    Write-Verbose "Loaded $($settings.Count) setting(s) from App Configuration."
    return $settings
}

function Resolve-KeyVaultReference {
    <#
    .SYNOPSIS
        Resolves a Key Vault secret URI to its actual value.

    .DESCRIPTION
        Fetches a secret from Azure Key Vault using the provided secret URI.
        Authenticates via managed identity or the current Az context.

    .PARAMETER SecretUri
        The full Key Vault secret URI (e.g., https://myvault.vault.azure.net/secrets/MySecret).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SecretUri
    )

    try {
        # Get a token for Key Vault
        $kvToken = Get-ManagedIdentityToken -Resource "https://vault.azure.net"

        # Ensure the URI has an API version
        $apiUri = $SecretUri
        if ($apiUri -notmatch "\?") {
            $apiUri = "$apiUri`?api-version=7.4"
        }

        $headers = @{ "Authorization" = "Bearer $kvToken" }
        $secret = Invoke-RestMethod -Uri $apiUri -Headers $headers -Method GET -ErrorAction Stop
        return $secret.value
    }
    catch {
        Write-Error "Failed to resolve Key Vault reference '$SecretUri': $_"
        throw
    }
}

function Get-ManagedIdentityToken {
    <#
    .SYNOPSIS
        Obtains an access token using managed identity or Azure CLI fallback.

    .PARAMETER Resource
        The resource URI to request a token for.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Resource
    )

    # Try Azure Instance Metadata Service (IMDS) for managed identity
    $imdsUrl = "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2019-06-01&resource=$Resource"
    try {
        $response = Invoke-RestMethod -Uri $imdsUrl -Headers @{ "Metadata" = "true" } -Method GET -TimeoutSec 3 -ErrorAction Stop
        return $response.access_token
    }
    catch {
        Write-Verbose "Managed identity (IMDS) not available. Falling back to Azure CLI..."
    }

    # Fallback: use az CLI token
    try {
        $tokenJson = az account get-access-token --resource $Resource 2>$null | ConvertFrom-Json
        if ($tokenJson.accessToken) {
            return $tokenJson.accessToken
        }
    }
    catch {
        Write-Verbose "Azure CLI token acquisition failed."
    }

    throw "Unable to obtain access token for '$Resource'. Ensure managed identity is configured or 'az login' has been run."
}

function ConvertFrom-AppConfigConnectionString {
    <#
    .SYNOPSIS
        Parses an Azure App Configuration connection string into its components.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ConnectionString
    )

    $parts = @{}
    foreach ($segment in $ConnectionString.Split(";")) {
        if ($segment -match "^(.+?)=(.+)$") {
            $parts[$Matches[1]] = $Matches[2]
        }
    }

    if (-not $parts.Endpoint -or -not $parts.Id -or -not $parts.Secret) {
        throw "Invalid App Configuration connection string. Expected Endpoint, Id, and Secret fields."
    }

    return @{
        Endpoint   = $parts.Endpoint
        Credential = $parts.Id
        Secret     = $parts.Secret
    }
}

function Get-HmacAuthHeaders {
    <#
    .SYNOPSIS
        Generates HMAC-SHA256 authentication headers for Azure App Configuration REST API.

    .DESCRIPTION
        Constructs the signed headers required when authenticating to App Configuration
        using a connection string (credential + secret) per the HMAC signing scheme.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Credential,

        [Parameter(Mandatory)]
        [string]$Secret,

        [Parameter(Mandatory)]
        [string]$BaseUrl,

        [Parameter()]
        [string]$Prefix = "IntuneRemediation:"
    )

    $uri = [System.Uri]"$BaseUrl/kv?key=$($Prefix)*&api-version=2023-11-01"
    $host_ = $uri.Authority
    $pathAndQuery = $uri.PathAndQuery

    $utcNow = [System.DateTimeOffset]::UtcNow.ToString("r")

    # Build the string to sign
    # Content hash is empty for GET requests
    $contentHash = [System.Convert]::ToBase64String(
        [System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes(""))
    )

    $stringToSign = "GET`n$pathAndQuery`n$utcNow;$host_;$contentHash"

    # Compute HMAC-SHA256 signature
    $secretBytes = [System.Convert]::FromBase64String($Secret)
    $hmac = [System.Security.Cryptography.HMACSHA256]::new($secretBytes)
    $signatureBytes = $hmac.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($stringToSign))
    $signature = [System.Convert]::ToBase64String($signatureBytes)

    return @{
        "x-ms-date"         = $utcNow
        "x-ms-content-sha256" = $contentHash
        "Authorization"     = "HMAC-SHA256 Credential=$Credential&SignedHeaders=x-ms-date;host;x-ms-content-sha256&Signature=$signature"
        "Host"              = $host_
    }
}

function Merge-Configuration {
    <#
    .SYNOPSIS
        Merges App Configuration settings into the local config object.

    .DESCRIPTION
        Takes settings from App Configuration (hashtable) and a local config (PSCustomObject)
        and returns a merged PSCustomObject. App Configuration values take precedence.
        Boolean strings ("true"/"false") are converted to actual booleans.
        Numeric strings are converted to integers.

    .PARAMETER AppConfigSettings
        Hashtable from Get-AppConfiguration.

    .PARAMETER LocalConfig
        PSCustomObject from thresholds.json.

    .OUTPUTS
        PSCustomObject with merged configuration.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$AppConfigSettings,

        [Parameter(Mandatory)]
        $LocalConfig
    )

    # Start with a copy of local config
    $merged = $LocalConfig.PSObject.Copy()

    # Map App Config keys to local config property names
    $keyMap = @{
        "StaleDays_Warning"  = "staleDays_Warning"
        "StaleDays_Critical" = "staleDays_Critical"
        "StaleDays_Abandoned" = "staleDays_Abandoned"
        "EnableSyncNudge"    = "enableSyncNudge"
        "EnableDisable"      = "enableDisable"
        "EnableRetire"       = "enableRetire"
        "EnableDelete"       = "enableDelete"
        "MaxDevicesPerRun"   = "maxDevicesPerRun"
        "BatchSize"          = "batchSize"
    }

    foreach ($appKey in $keyMap.Keys) {
        if ($AppConfigSettings.ContainsKey($appKey)) {
            $localKey = $keyMap[$appKey]
            $value = $AppConfigSettings[$appKey]

            # Type coercion: boolean strings
            if ($value -is [string] -and $value -in @("true", "false")) {
                $value = [System.Convert]::ToBoolean($value)
            }
            # Type coercion: numeric strings
            elseif ($value -is [string] -and $value -match '^\d+$') {
                $value = [int]$value
            }

            $merged.$localKey = $value
            Write-Verbose "  App Config override: $localKey = $value"
        }
    }

    return $merged
}

Export-ModuleMember -Function Get-AppConfiguration, Resolve-KeyVaultReference, Merge-Configuration
