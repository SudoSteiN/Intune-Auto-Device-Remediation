<#
.SYNOPSIS
    Intune Device Lifecycle Automation — Azure Automation Runbook.

.DESCRIPTION
    Connects to Microsoft Graph API via certificate-based authentication to detect,
    classify, remediate, and clean up non-compliant and stale devices in Microsoft
    Intune. Configuration and exclusions are loaded from Azure Automation variables.

    Runs in DRY-RUN mode by default. Use the -Execute switch to apply changes.

.PARAMETER Execute
    Switch to enable live execution. Without this, all actions are dry-run only.

.PARAMETER Scope
    Filter which devices to process: All, StaleOnly, or NonCompliantOnly.

.PARAMETER GenerateHtmlReport
    Switch to generate an HTML dashboard report in the job output.
#>

[CmdletBinding()]
param(
    [switch]$Execute,

    [ValidateSet("All", "StaleOnly", "NonCompliantOnly")]
    [string]$Scope = "All",

    [switch]$GenerateHtmlReport
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Add System.Web for HTML encoding in reports
Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue

$runStart = [datetime]::UtcNow
$runTimestamp = $runStart.ToString("yyyyMMdd_HHmmss")

# ─────────────────────────────────────────────────────────────
# Logging — Run Banner
# ─────────────────────────────────────────────────────────────
Write-Output "=== Intune Device Lifecycle Automation ==="
if ($Execute) {
    Write-Output "  Mode: LIVE EXECUTION"
} else {
    Write-Output "  Mode: DRY RUN"
}
Write-Output "  Scope: $Scope"
Write-Output "  Run started: $($runStart.ToString('yyyy-MM-dd HH:mm:ss')) UTC"

# ─────────────────────────────────────────────────────────────
# Authentication — Azure Automation Certificate
# ─────────────────────────────────────────────────────────────
$TenantId = Get-AutomationVariable -Name 'IntuneLifecycle_TenantId'
$ClientId = Get-AutomationVariable -Name 'IntuneLifecycle_ClientId'
$Cert = Get-AutomationCertificate -Name 'IntuneLifecycle-Cert'

if (-not $Cert) {
    Write-Error "Certificate 'IntuneLifecycle-Cert' not found."
    throw "Missing certificate"
}

Write-Output "Connecting to Microsoft Graph..."
Write-Output "  TenantId: $TenantId"
Write-Output "  ClientId: $ClientId"
Write-Output "  Thumbprint: $($Cert.Thumbprint)"

try {
    Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -Certificate $Cert -NoWelcome -ErrorAction Stop
    $ctx = Get-MgContext
    Write-Output "  Connected. Scopes: $($ctx.Scopes -join ', ')"
} catch {
    Write-Error "Graph connection failed: $_"
    throw
}

# Build auth context for downstream functions
$authContext = @{
    Headers  = @{ "ConsistencyLevel" = "eventual" }
    AuthType = "Certificate"
    TenantId = $TenantId
    UseSdk   = $true
}

# ─────────────────────────────────────────────────────────────
# Config Loading — Azure Automation Variables
# ─────────────────────────────────────────────────────────────
$ConfigJson = Get-AutomationVariable -Name 'IntuneLifecycle_Config'
$Config = $ConfigJson | ConvertFrom-Json

$ExclusionsCsv = Get-AutomationVariable -Name 'IntuneLifecycle_Exclusions'
$Exclusions = $ExclusionsCsv | ConvertFrom-Csv

Write-Output "  Config: Warning=$($Config.staleDays_Warning)d, Critical=$($Config.staleDays_Critical)d, Abandoned=$($Config.staleDays_Abandoned)d"
Write-Output "  Actions: SyncNudge=$($Config.enableSyncNudge), Disable=$($Config.enableDisable), Retire=$($Config.enableRetire), Delete=$($Config.enableDelete)"
Write-Output "  Exclusions loaded: $(@($Exclusions).Count) entries"

# ═════════════════════════════════════════════════════════════
# INLINED FUNCTIONS
# ═════════════════════════════════════════════════════════════

# ─────────────────────────────────────────────────────────────
# Auth — Invoke-GraphRequest (retry logic with exponential backoff)
# ─────────────────────────────────────────────────────────────

function Invoke-GraphRequest {
    <#
    .SYNOPSIS
        Sends a request to Microsoft Graph with automatic retry on throttling.
    .DESCRIPTION
        Wraps Invoke-RestMethod with retry logic for HTTP 429 (Too Many Requests)
        and transient 5xx errors. Uses exponential backoff with jitter.
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

# ─────────────────────────────────────────────────────────────
# DeviceDiscovery Functions
# ─────────────────────────────────────────────────────────────

# Properties to select from the managedDevices endpoint
$script:DeviceSelectProperties = @(
    "id",
    "deviceName",
    "azureADDeviceId",
    "userPrincipalName",
    "complianceState",
    "lastSyncDateTime",
    "enrolledDateTime",
    "operatingSystem",
    "osVersion",
    "managementAgent",
    "deviceEnrollmentType",
    "model",
    "manufacturer"
) -join ","

function Get-AllManagedDevices {
    <#
    .SYNOPSIS
        Retrieves all Intune managed devices with automatic paging.
    .DESCRIPTION
        Queries the Graph API managedDevices endpoint and follows @odata.nextLink
        tokens to retrieve the full device inventory.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$AuthContext,

        [Parameter()]
        [int]$BatchSize = 200,

        [Parameter()]
        [int]$MaxDevices = 0
    )

    $baseUri = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices"
    $uri = "${baseUri}?`$top=${BatchSize}&`$select=${script:DeviceSelectProperties}"

    $allDevices = [System.Collections.Generic.List[object]]::new()
    $pageCount = 0

    Write-Verbose "Fetching managed devices from Intune (batch size: $BatchSize)..."

    while ($uri) {
        $pageCount++
        Write-Verbose "Fetching page $pageCount..."

        $response = Invoke-GraphRequest -Uri $uri -Method GET -Headers $AuthContext.Headers
        $devices = $response.value

        if ($devices) {
            $allDevices.AddRange($devices)
            Write-Verbose "Retrieved $($devices.Count) devices (total: $($allDevices.Count))."
        }

        # Check max limit
        if ($MaxDevices -gt 0 -and $allDevices.Count -ge $MaxDevices) {
            Write-Warning "Reached maximum device limit ($MaxDevices). Stopping pagination."
            $allDevices = [System.Collections.Generic.List[object]]::new(
                $allDevices | Select-Object -First $MaxDevices
            )
            break
        }

        # Follow pagination link
        $uri = $response.'@odata.nextLink'
    }

    Write-Verbose "Total devices retrieved: $($allDevices.Count) across $pageCount page(s)."
    return $allDevices
}

function Get-DeviceTier {
    <#
    .SYNOPSIS
        Classifies a single device into a lifecycle tier.
    .DESCRIPTION
        Evaluates a device's lastSyncDateTime and complianceState against
        configurable thresholds and returns the appropriate tier classification.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Device,

        [Parameter(Mandatory)]
        $Config,

        [Parameter()]
        [datetime]$ReferenceDate = [datetime]::UtcNow
    )

    $lastSync = $null
    if ($Device.lastSyncDateTime) {
        $lastSync = [datetime]::Parse($Device.lastSyncDateTime)
    }

    # If we have no sync date at all, treat as abandoned
    if (-not $lastSync) {
        Write-Verbose "Device '$($Device.deviceName)' has no lastSyncDateTime -> Abandoned."
        return "Abandoned"
    }

    $daysSinceSync = ($ReferenceDate - $lastSync).TotalDays

    # Check if device has no primary user assigned (also counts as abandoned if stale enough)
    $hasUser = -not [string]::IsNullOrWhiteSpace($Device.userPrincipalName)

    # Tier classification in priority order
    if ($daysSinceSync -ge $Config.staleDays_Abandoned) {
        return "Abandoned"
    }

    if (-not $hasUser -and $daysSinceSync -ge $Config.staleDays_Warning) {
        # No primary user and stale beyond warning threshold -> Abandoned
        return "Abandoned"
    }

    if ($daysSinceSync -ge $Config.staleDays_Critical) {
        return "StaleCritical"
    }

    if ($daysSinceSync -ge $Config.staleDays_Warning) {
        return "StaleWarning"
    }

    # Device is syncing within the warning threshold — check compliance
    if ($Device.complianceState -ne "compliant") {
        return "ActiveNonCompliant"
    }

    return "Healthy"
}

function Get-ClassifiedDevices {
    <#
    .SYNOPSIS
        Retrieves and classifies all managed devices into lifecycle tiers.
    .DESCRIPTION
        Combines device retrieval (with paging) and tier classification into
        a single pipeline. Returns enriched device objects with tier assignments.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$AuthContext,

        [Parameter(Mandatory)]
        $Config,

        [Parameter()]
        [array]$ExclusionList = @(),

        [Parameter()]
        [ValidateSet("All", "StaleOnly", "NonCompliantOnly")]
        [string]$Scope = "All"
    )

    $maxDevices = if ($Config.maxDevicesPerRun) { $Config.maxDevicesPerRun } else { 0 }
    $batchSize = if ($Config.batchSize) { [math]::Max($Config.batchSize, 20) } else { 200 }

    # Fetch all devices
    $rawDevices = Get-AllManagedDevices -AuthContext $AuthContext -BatchSize $batchSize -MaxDevices $maxDevices

    if (-not $rawDevices -or $rawDevices.Count -eq 0) {
        Write-Warning "No managed devices found in Intune."
        return @()
    }

    Write-Verbose "Classifying $($rawDevices.Count) devices..."

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    $excludedCount = 0
    $healthyCount = 0
    $now = [datetime]::UtcNow

    foreach ($device in $rawDevices) {
        # Check exclusion list
        $isExcluded = Test-DeviceExcluded -Device $device -ExclusionList $ExclusionList
        if ($isExcluded) {
            $excludedCount++
            $results.Add([PSCustomObject]@{
                DeviceId            = $device.id
                DeviceName          = $device.deviceName
                AzureADDeviceId     = $device.azureADDeviceId
                UserPrincipalName   = $device.userPrincipalName
                ComplianceState     = $device.complianceState
                LastSyncDateTime    = $device.lastSyncDateTime
                EnrolledDateTime    = $device.enrolledDateTime
                OperatingSystem     = $device.operatingSystem
                OsVersion           = $device.osVersion
                ManagementAgent     = $device.managementAgent
                DeviceEnrollmentType = $device.deviceEnrollmentType
                Model               = $device.model
                Manufacturer        = $device.manufacturer
                Tier                = "Excluded"
                DaysSinceSync       = if ($device.lastSyncDateTime) { [math]::Round(($now - [datetime]::Parse($device.lastSyncDateTime)).TotalDays, 1) } else { -1 }
                Action              = "Skipped (Exclusion List)"
            })
            continue
        }

        # Classify
        $tier = Get-DeviceTier -Device $device -Config $Config -ReferenceDate $now
        $daysSinceSync = if ($device.lastSyncDateTime) {
            [math]::Round(($now - [datetime]::Parse($device.lastSyncDateTime)).TotalDays, 1)
        }
        else { -1 }

        # Apply scope filter
        if ($Scope -eq "StaleOnly" -and $tier -notin @("StaleWarning", "StaleCritical", "Abandoned")) {
            continue
        }
        if ($Scope -eq "NonCompliantOnly" -and $tier -ne "ActiveNonCompliant") {
            continue
        }

        # Skip healthy devices from the actionable results but count them
        if ($tier -eq "Healthy") {
            $healthyCount++
            continue
        }

        $results.Add([PSCustomObject]@{
            DeviceId            = $device.id
            DeviceName          = $device.deviceName
            AzureADDeviceId     = $device.azureADDeviceId
            UserPrincipalName   = $device.userPrincipalName
            ComplianceState     = $device.complianceState
            LastSyncDateTime    = $device.lastSyncDateTime
            EnrolledDateTime    = $device.enrolledDateTime
            OperatingSystem     = $device.operatingSystem
            OsVersion           = $device.osVersion
            ManagementAgent     = $device.managementAgent
            DeviceEnrollmentType = $device.deviceEnrollmentType
            Model               = $device.model
            Manufacturer        = $device.manufacturer
            Tier                = $tier
            DaysSinceSync       = $daysSinceSync
            Action              = ""
        })
    }

    Write-Verbose "Classification complete: $($results.Count) actionable, $healthyCount healthy, $excludedCount excluded."
    return $results
}

function Test-DeviceExcluded {
    <#
    .SYNOPSIS
        Checks whether a device matches any entry in the exclusion list.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Device,

        [Parameter()]
        [array]$ExclusionList = @()
    )

    foreach ($exclusion in $ExclusionList) {
        # Match by Device ID
        if ($exclusion.DeviceId -and $exclusion.DeviceId -eq $Device.id) {
            Write-Verbose "Device '$($Device.deviceName)' excluded by DeviceId."
            return $true
        }

        # Match by Device Name (case-insensitive)
        if ($exclusion.DeviceName -and $exclusion.DeviceName -eq $Device.deviceName) {
            Write-Verbose "Device '$($Device.deviceName)' excluded by DeviceName."
            return $true
        }

        # Match by UPN (case-insensitive)
        if ($exclusion.UserPrincipalName -and $exclusion.UserPrincipalName -eq $Device.userPrincipalName) {
            Write-Verbose "Device '$($Device.deviceName)' excluded by UserPrincipalName."
            return $true
        }
    }

    return $false
}

# ─────────────────────────────────────────────────────────────
# Remediation Functions
# ─────────────────────────────────────────────────────────────

function Invoke-DeviceSyncNudge {
    <#
    .SYNOPSIS
        Triggers a sync on a managed device in Intune.
    .DESCRIPTION
        Sends a POST to /deviceManagement/managedDevices/{id}/syncDevice
        to force the device to check in. Used for active non-compliant devices.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$DeviceId,

        [Parameter()]
        [string]$DeviceName = "",

        [Parameter(Mandatory)]
        [hashtable]$AuthContext,

        [Parameter()]
        [switch]$Execute
    )

    $action = "SyncNudge"
    $uri = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/$DeviceId/syncDevice"

    if (-not $Execute) {
        Write-Verbose "DRY RUN: Would send sync nudge to device '$DeviceName' ($DeviceId)."
        return [PSCustomObject]@{
            DeviceId   = $DeviceId
            DeviceName = $DeviceName
            Action     = $action
            Status     = "DryRun"
            Detail     = "Would trigger sync via POST $uri"
            Timestamp  = [datetime]::UtcNow.ToString("o")
        }
    }

    try {
        Write-Verbose "Sending sync nudge to device '$DeviceName' ($DeviceId)..."
        Invoke-GraphRequest -Uri $uri -Method POST -Headers $AuthContext.Headers
        Write-Verbose "Sync nudge sent successfully to '$DeviceName'."

        return [PSCustomObject]@{
            DeviceId   = $DeviceId
            DeviceName = $DeviceName
            Action     = $action
            Status     = "Success"
            Detail     = "Sync triggered"
            Timestamp  = [datetime]::UtcNow.ToString("o")
        }
    }
    catch {
        Write-Warning "Failed to sync device '$DeviceName' ($DeviceId): $_"
        return [PSCustomObject]@{
            DeviceId   = $DeviceId
            DeviceName = $DeviceName
            Action     = $action
            Status     = "Failed"
            Detail     = $_.Exception.Message
            Timestamp  = [datetime]::UtcNow.ToString("o")
        }
    }
}

function Invoke-DeviceReboot {
    <#
    .SYNOPSIS
        Triggers a reboot on a managed device for compliance re-evaluation.
    .DESCRIPTION
        Sends a POST to /deviceManagement/managedDevices/{id}/rebootNow.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$DeviceId,

        [Parameter()]
        [string]$DeviceName = "",

        [Parameter(Mandatory)]
        [hashtable]$AuthContext,

        [Parameter()]
        [switch]$Execute
    )

    $action = "RebootNow"
    $uri = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/$DeviceId/rebootNow"

    if (-not $Execute) {
        Write-Verbose "DRY RUN: Would reboot device '$DeviceName' ($DeviceId)."
        return [PSCustomObject]@{
            DeviceId   = $DeviceId
            DeviceName = $DeviceName
            Action     = $action
            Status     = "DryRun"
            Detail     = "Would trigger reboot via POST $uri"
            Timestamp  = [datetime]::UtcNow.ToString("o")
        }
    }

    try {
        Write-Verbose "Sending reboot command to device '$DeviceName' ($DeviceId)..."
        Invoke-GraphRequest -Uri $uri -Method POST -Headers $AuthContext.Headers
        Write-Verbose "Reboot command sent successfully to '$DeviceName'."

        return [PSCustomObject]@{
            DeviceId   = $DeviceId
            DeviceName = $DeviceName
            Action     = $action
            Status     = "Success"
            Detail     = "Reboot triggered"
            Timestamp  = [datetime]::UtcNow.ToString("o")
        }
    }
    catch {
        Write-Warning "Failed to reboot device '$DeviceName' ($DeviceId): $_"
        return [PSCustomObject]@{
            DeviceId   = $DeviceId
            DeviceName = $DeviceName
            Action     = $action
            Status     = "Failed"
            Detail     = $_.Exception.Message
            Timestamp  = [datetime]::UtcNow.ToString("o")
        }
    }
}

function Disable-EntraDevice {
    <#
    .SYNOPSIS
        Disables a device in Entra ID (Azure AD).
    .DESCRIPTION
        Sends a PATCH to /devices/{azureADDeviceId} setting accountEnabled to false.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AzureADDeviceId,

        [Parameter()]
        [string]$DeviceName = "",

        [Parameter(Mandatory)]
        [hashtable]$AuthContext,

        [Parameter()]
        [switch]$Execute
    )

    $action = "DisableEntraDevice"
    $uri = "https://graph.microsoft.com/v1.0/devices(deviceId='$AzureADDeviceId')"

    if ([string]::IsNullOrWhiteSpace($AzureADDeviceId)) {
        Write-Warning "Cannot disable device '$DeviceName': No AzureADDeviceId available."
        return [PSCustomObject]@{
            DeviceId   = ""
            DeviceName = $DeviceName
            Action     = $action
            Status     = "Skipped"
            Detail     = "No AzureADDeviceId available"
            Timestamp  = [datetime]::UtcNow.ToString("o")
        }
    }

    $body = @{ accountEnabled = $false }

    if (-not $Execute) {
        Write-Verbose "DRY RUN: Would disable Entra device '$DeviceName' ($AzureADDeviceId)."
        return [PSCustomObject]@{
            DeviceId   = $AzureADDeviceId
            DeviceName = $DeviceName
            Action     = $action
            Status     = "DryRun"
            Detail     = "Would set accountEnabled=false via PATCH $uri"
            Timestamp  = [datetime]::UtcNow.ToString("o")
        }
    }

    try {
        Write-Verbose "Disabling Entra device '$DeviceName' ($AzureADDeviceId)..."
        Invoke-GraphRequest -Uri $uri -Method PATCH -Headers $AuthContext.Headers -Body $body
        Write-Verbose "Device '$DeviceName' disabled in Entra ID."

        return [PSCustomObject]@{
            DeviceId   = $AzureADDeviceId
            DeviceName = $DeviceName
            Action     = $action
            Status     = "Success"
            Detail     = "accountEnabled set to false"
            Timestamp  = [datetime]::UtcNow.ToString("o")
        }
    }
    catch {
        Write-Warning "Failed to disable Entra device '$DeviceName' ($AzureADDeviceId): $_"
        return [PSCustomObject]@{
            DeviceId   = $AzureADDeviceId
            DeviceName = $DeviceName
            Action     = $action
            Status     = "Failed"
            Detail     = $_.Exception.Message
            Timestamp  = [datetime]::UtcNow.ToString("o")
        }
    }
}

function Invoke-DeviceRetire {
    <#
    .SYNOPSIS
        Retires a managed device from Intune.
    .DESCRIPTION
        Sends a POST to /deviceManagement/managedDevices/{id}/retire.
        Removes company data but leaves personal data.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$DeviceId,

        [Parameter()]
        [string]$DeviceName = "",

        [Parameter(Mandatory)]
        [hashtable]$AuthContext,

        [Parameter()]
        [switch]$Execute
    )

    $action = "Retire"
    $uri = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/$DeviceId/retire"

    if (-not $Execute) {
        Write-Verbose "DRY RUN: Would retire device '$DeviceName' ($DeviceId)."
        return [PSCustomObject]@{
            DeviceId   = $DeviceId
            DeviceName = $DeviceName
            Action     = $action
            Status     = "DryRun"
            Detail     = "Would retire via POST $uri"
            Timestamp  = [datetime]::UtcNow.ToString("o")
        }
    }

    try {
        Write-Verbose "Retiring device '$DeviceName' ($DeviceId)..."
        Invoke-GraphRequest -Uri $uri -Method POST -Headers $AuthContext.Headers
        Write-Verbose "Device '$DeviceName' retired successfully."

        return [PSCustomObject]@{
            DeviceId   = $DeviceId
            DeviceName = $DeviceName
            Action     = $action
            Status     = "Success"
            Detail     = "Device retired from Intune"
            Timestamp  = [datetime]::UtcNow.ToString("o")
        }
    }
    catch {
        Write-Warning "Failed to retire device '$DeviceName' ($DeviceId): $_"
        return [PSCustomObject]@{
            DeviceId   = $DeviceId
            DeviceName = $DeviceName
            Action     = $action
            Status     = "Failed"
            Detail     = $_.Exception.Message
            Timestamp  = [datetime]::UtcNow.ToString("o")
        }
    }
}

function Remove-ManagedDevice {
    <#
    .SYNOPSIS
        Deletes a managed device from Intune.
    .DESCRIPTION
        Sends a DELETE to /deviceManagement/managedDevices/{id}.
        This is a destructive action — the device record is removed entirely.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$DeviceId,

        [Parameter()]
        [string]$DeviceName = "",

        [Parameter(Mandatory)]
        [hashtable]$AuthContext,

        [Parameter()]
        [switch]$Execute
    )

    $action = "Delete"
    $uri = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/$DeviceId"

    if (-not $Execute) {
        Write-Verbose "DRY RUN: Would DELETE device '$DeviceName' ($DeviceId)."
        return [PSCustomObject]@{
            DeviceId   = $DeviceId
            DeviceName = $DeviceName
            Action     = $action
            Status     = "DryRun"
            Detail     = "Would delete via DELETE $uri"
            Timestamp  = [datetime]::UtcNow.ToString("o")
        }
    }

    try {
        Write-Verbose "DELETING device '$DeviceName' ($DeviceId)..."
        Invoke-GraphRequest -Uri $uri -Method DELETE -Headers $AuthContext.Headers
        Write-Verbose "Device '$DeviceName' deleted successfully."

        return [PSCustomObject]@{
            DeviceId   = $DeviceId
            DeviceName = $DeviceName
            Action     = $action
            Status     = "Success"
            Detail     = "Device deleted from Intune"
            Timestamp  = [datetime]::UtcNow.ToString("o")
        }
    }
    catch {
        Write-Warning "Failed to delete device '$DeviceName' ($DeviceId): $_"
        return [PSCustomObject]@{
            DeviceId   = $DeviceId
            DeviceName = $DeviceName
            Action     = $action
            Status     = "Failed"
            Detail     = $_.Exception.Message
            Timestamp  = [datetime]::UtcNow.ToString("o")
        }
    }
}

function Invoke-TierRemediation {
    <#
    .SYNOPSIS
        Applies the appropriate remediation action based on a device's tier.
    .DESCRIPTION
        Routes each device to the correct remediation function based on its
        classified tier and the enabled actions in the configuration.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Device,

        [Parameter(Mandatory)]
        [hashtable]$AuthContext,

        [Parameter(Mandatory)]
        $Config,

        [Parameter()]
        [switch]$Execute
    )

    switch ($Device.Tier) {
        "ActiveNonCompliant" {
            if ($Config.enableSyncNudge) {
                return Invoke-DeviceSyncNudge -DeviceId $Device.DeviceId -DeviceName $Device.DeviceName -AuthContext $AuthContext -Execute:$Execute
            }
            else {
                Write-Verbose "Sync nudge disabled in config. Skipping '$($Device.DeviceName)'."
                return [PSCustomObject]@{
                    DeviceId   = $Device.DeviceId
                    DeviceName = $Device.DeviceName
                    Action     = "SyncNudge"
                    Status     = "Disabled"
                    Detail     = "enableSyncNudge is false in config"
                    Timestamp  = [datetime]::UtcNow.ToString("o")
                }
            }
        }

        "StaleWarning" {
            # Flag and notify — no destructive action, just record it
            Write-Verbose "Device '$($Device.DeviceName)' is Stale-Warning. Flagging for notification."
            return [PSCustomObject]@{
                DeviceId   = $Device.DeviceId
                DeviceName = $Device.DeviceName
                Action     = "FlagForNotification"
                Status     = if ($Execute) { "Success" } else { "DryRun" }
                Detail     = "Stale $($Device.DaysSinceSync) days — flagged for user/manager notification"
                Timestamp  = [datetime]::UtcNow.ToString("o")
            }
        }

        "StaleCritical" {
            if ($Config.enableDisable) {
                return Disable-EntraDevice -AzureADDeviceId $Device.AzureADDeviceId -DeviceName $Device.DeviceName -AuthContext $AuthContext -Execute:$Execute
            }
            else {
                Write-Verbose "Disable action disabled in config. Skipping '$($Device.DeviceName)'."
                return [PSCustomObject]@{
                    DeviceId   = $Device.DeviceId
                    DeviceName = $Device.DeviceName
                    Action     = "DisableEntraDevice"
                    Status     = "Disabled"
                    Detail     = "enableDisable is false in config"
                    Timestamp  = [datetime]::UtcNow.ToString("o")
                }
            }
        }

        "Abandoned" {
            if ($Config.enableDelete) {
                return Remove-ManagedDevice -DeviceId $Device.DeviceId -DeviceName $Device.DeviceName -AuthContext $AuthContext -Execute:$Execute
            }
            elseif ($Config.enableRetire) {
                return Invoke-DeviceRetire -DeviceId $Device.DeviceId -DeviceName $Device.DeviceName -AuthContext $AuthContext -Execute:$Execute
            }
            else {
                Write-Verbose "Retire/Delete disabled in config. Queuing '$($Device.DeviceName)' for approval."
                return [PSCustomObject]@{
                    DeviceId   = $Device.DeviceId
                    DeviceName = $Device.DeviceName
                    Action     = "QueuedForApproval"
                    Status     = if ($Execute) { "Success" } else { "DryRun" }
                    Detail     = "Abandoned $($Device.DaysSinceSync) days — added to approval report"
                    Timestamp  = [datetime]::UtcNow.ToString("o")
                }
            }
        }

        "Excluded" {
            return [PSCustomObject]@{
                DeviceId   = $Device.DeviceId
                DeviceName = $Device.DeviceName
                Action     = "Skipped"
                Status     = "Excluded"
                Detail     = "Device is on the exclusion list"
                Timestamp  = [datetime]::UtcNow.ToString("o")
            }
        }

        default {
            Write-Verbose "No action defined for tier '$($Device.Tier)' on device '$($Device.DeviceName)'."
            return [PSCustomObject]@{
                DeviceId   = $Device.DeviceId
                DeviceName = $Device.DeviceName
                Action     = "None"
                Status     = "NoAction"
                Detail     = "Tier '$($Device.Tier)' requires no action"
                Timestamp  = [datetime]::UtcNow.ToString("o")
            }
        }
    }
}

# ─────────────────────────────────────────────────────────────
# Reporting Functions
# ─────────────────────────────────────────────────────────────

function Export-DeviceReport {
    <#
    .SYNOPSIS
        Outputs classified device data and action results as a formatted table.
    .DESCRIPTION
        Creates a detailed report with one row per device, showing its
        tier classification, action taken (or dry-run), and metadata.
        Output goes to Write-Output for the Azure Automation job log.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [array]$Devices,

        [Parameter()]
        [array]$ActionResults = @(),

        [Parameter()]
        [string]$RunTimestamp = (Get-Date -Format "yyyyMMdd_HHmmss")
    )

    # Merge action results into device records
    $resultLookup = @{}
    foreach ($result in $ActionResults) {
        $resultLookup[$result.DeviceId] = $result
    }

    $reportData = foreach ($device in $Devices) {
        $actionResult = $resultLookup[$device.DeviceId]
        [PSCustomObject]@{
            DeviceName          = $device.DeviceName
            DeviceId            = $device.DeviceId
            AzureADDeviceId     = $device.AzureADDeviceId
            UserPrincipalName   = $device.UserPrincipalName
            OperatingSystem     = $device.OperatingSystem
            OsVersion           = $device.OsVersion
            Model               = $device.Model
            Manufacturer        = $device.Manufacturer
            ComplianceState     = $device.ComplianceState
            LastSyncDateTime    = $device.LastSyncDateTime
            DaysSinceSync       = $device.DaysSinceSync
            EnrolledDateTime    = $device.EnrolledDateTime
            ManagementAgent     = $device.ManagementAgent
            Tier                = $device.Tier
            Action              = if ($actionResult) { $actionResult.Action } else { $device.Action }
            ActionStatus        = if ($actionResult) { $actionResult.Status } else { "N/A" }
            ActionDetail        = if ($actionResult) { $actionResult.Detail } else { "" }
            ActionTimestamp     = if ($actionResult) { $actionResult.Timestamp } else { "" }
        }
    }

    Write-Output ""
    Write-Output "--- Device Lifecycle Report ($RunTimestamp) ---"
    $reportData | Format-Table -Property DeviceName, UserPrincipalName, OperatingSystem, ComplianceState, DaysSinceSync, Tier, Action, ActionStatus -AutoSize | Out-String | Write-Output
    Write-Output "Total devices in report: $($reportData.Count)"
}

function Export-ApprovalReport {
    <#
    .SYNOPSIS
        Outputs an approval report for abandoned devices requiring manual review.
    .DESCRIPTION
        Filters devices queued for destructive actions and outputs them as a
        formatted table for review.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [array]$Devices,

        [Parameter()]
        [string]$RunTimestamp = (Get-Date -Format "yyyyMMdd_HHmmss")
    )

    $approvalDevices = $Devices | Where-Object { $_.Tier -eq "Abandoned" }

    if (-not $approvalDevices -or @($approvalDevices).Count -eq 0) {
        Write-Verbose "No devices require approval. Skipping approval report."
        return
    }

    $approvalData = foreach ($device in $approvalDevices) {
        [PSCustomObject]@{
            DeviceName          = $device.DeviceName
            DeviceId            = $device.DeviceId
            UserPrincipalName   = $device.UserPrincipalName
            OperatingSystem     = $device.OperatingSystem
            Model               = $device.Model
            LastSyncDateTime    = $device.LastSyncDateTime
            DaysSinceSync       = $device.DaysSinceSync
            EnrolledDateTime    = $device.EnrolledDateTime
            SuggestedAction     = "Retire/Delete"
        }
    }

    Write-Output ""
    Write-Output "--- Approval Report ($RunTimestamp) — $(@($approvalDevices).Count) abandoned devices require review ---"
    $approvalData | Format-Table -AutoSize | Out-String | Write-Output
}

function Export-HtmlReport {
    <#
    .SYNOPSIS
        Generates a self-contained HTML dashboard report.
    .DESCRIPTION
        Creates an HTML report with inline CSS showing a summary dashboard
        with tier counts, action results, and a detailed device table.
        Returns the HTML content as a string variable.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [array]$Devices,

        [Parameter()]
        [array]$ActionResults = @(),

        [Parameter()]
        [string]$RunTimestamp = (Get-Date -Format "yyyyMMdd_HHmmss"),

        [Parameter()]
        [switch]$DryRun
    )

    # Build summary statistics
    $tierCounts = @{
        StaleWarning     = @($Devices | Where-Object { $_.Tier -eq "StaleWarning" }).Count
        StaleCritical    = @($Devices | Where-Object { $_.Tier -eq "StaleCritical" }).Count
        Abandoned        = @($Devices | Where-Object { $_.Tier -eq "Abandoned" }).Count
        ActiveNonCompliant = @($Devices | Where-Object { $_.Tier -eq "ActiveNonCompliant" }).Count
        Excluded         = @($Devices | Where-Object { $_.Tier -eq "Excluded" }).Count
    }
    $totalActionable = $tierCounts.StaleWarning + $tierCounts.StaleCritical + $tierCounts.Abandoned + $tierCounts.ActiveNonCompliant

    # Action result summary
    $actionCounts = @{
        Success = @($ActionResults | Where-Object { $_.Status -eq "Success" }).Count
        DryRun  = @($ActionResults | Where-Object { $_.Status -eq "DryRun" }).Count
        Failed  = @($ActionResults | Where-Object { $_.Status -eq "Failed" }).Count
        Skipped = @($ActionResults | Where-Object { $_.Status -in @("Disabled", "Excluded", "NoAction", "Skipped") }).Count
    }

    # Merge action results into device table
    $resultLookup = @{}
    foreach ($result in $ActionResults) {
        $resultLookup[$result.DeviceId] = $result
    }

    # Build table rows
    $tableRows = ""
    foreach ($device in ($Devices | Sort-Object Tier, DaysSinceSync -Descending)) {
        $actionResult = $resultLookup[$device.DeviceId]
        $actionText = if ($actionResult) { $actionResult.Action } else { $device.Action }
        $statusText = if ($actionResult) { $actionResult.Status } else { "N/A" }
        $detailText = if ($actionResult) { $actionResult.Detail } else { "" }

        $tierClass = switch ($device.Tier) {
            "Abandoned"          { "tier-abandoned" }
            "StaleCritical"      { "tier-critical" }
            "StaleWarning"       { "tier-warning" }
            "ActiveNonCompliant" { "tier-noncompliant" }
            "Excluded"           { "tier-excluded" }
            default              { "" }
        }

        $statusClass = switch ($statusText) {
            "Success" { "status-success" }
            "Failed"  { "status-failed" }
            "DryRun"  { "status-dryrun" }
            default   { "" }
        }

        $tableRows += @"
            <tr>
                <td>$([System.Web.HttpUtility]::HtmlEncode($device.DeviceName))</td>
                <td>$([System.Web.HttpUtility]::HtmlEncode($device.UserPrincipalName))</td>
                <td>$([System.Web.HttpUtility]::HtmlEncode($device.OperatingSystem))</td>
                <td>$([System.Web.HttpUtility]::HtmlEncode($device.ComplianceState))</td>
                <td>$($device.DaysSinceSync)</td>
                <td class="$tierClass">$([System.Web.HttpUtility]::HtmlEncode($device.Tier))</td>
                <td>$([System.Web.HttpUtility]::HtmlEncode($actionText))</td>
                <td class="$statusClass">$([System.Web.HttpUtility]::HtmlEncode($statusText))</td>
                <td>$([System.Web.HttpUtility]::HtmlEncode($detailText))</td>
            </tr>
"@
    }

    $modeText = if ($DryRun) { '<span class="mode-dryrun">DRY RUN</span>' } else { '<span class="mode-live">LIVE EXECUTION</span>' }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Intune Device Lifecycle Report - $RunTimestamp</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f5f5; color: #333; padding: 20px; }
        .container { max-width: 1400px; margin: 0 auto; }
        .header { background: linear-gradient(135deg, #0078d4, #005a9e); color: white; padding: 30px; border-radius: 8px 8px 0 0; }
        .header h1 { font-size: 24px; margin-bottom: 5px; }
        .header .subtitle { font-size: 14px; opacity: 0.9; }
        .mode-dryrun { background: #fff3cd; color: #856404; padding: 4px 12px; border-radius: 4px; font-weight: 600; font-size: 12px; }
        .mode-live { background: #d4edda; color: #155724; padding: 4px 12px; border-radius: 4px; font-weight: 600; font-size: 12px; }
        .dashboard { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; padding: 20px; background: white; border-bottom: 1px solid #ddd; }
        .card { background: #f8f9fa; border-radius: 8px; padding: 20px; text-align: center; border-left: 4px solid #ccc; }
        .card .count { font-size: 36px; font-weight: 700; }
        .card .label { font-size: 13px; color: #666; margin-top: 5px; }
        .card-warning { border-left-color: #ffc107; }
        .card-warning .count { color: #856404; }
        .card-critical { border-left-color: #fd7e14; }
        .card-critical .count { color: #c25400; }
        .card-abandoned { border-left-color: #dc3545; }
        .card-abandoned .count { color: #dc3545; }
        .card-noncompliant { border-left-color: #6f42c1; }
        .card-noncompliant .count { color: #6f42c1; }
        .card-excluded { border-left-color: #6c757d; }
        .card-excluded .count { color: #6c757d; }
        .card-total { border-left-color: #0078d4; }
        .card-total .count { color: #0078d4; }
        .actions-summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 10px; padding: 15px 20px; background: white; border-bottom: 1px solid #ddd; }
        .action-badge { display: inline-block; padding: 6px 14px; border-radius: 20px; font-size: 13px; font-weight: 600; }
        .action-badge.success { background: #d4edda; color: #155724; }
        .action-badge.dryrun { background: #cce5ff; color: #004085; }
        .action-badge.failed { background: #f8d7da; color: #721c24; }
        .action-badge.skipped { background: #e2e3e5; color: #383d41; }
        .table-container { background: white; padding: 0; border-radius: 0 0 8px 8px; overflow-x: auto; }
        .section-header { padding: 15px 20px; background: #f8f9fa; border-bottom: 1px solid #ddd; font-weight: 600; font-size: 14px; }
        table { width: 100%; border-collapse: collapse; font-size: 13px; }
        th { background: #e9ecef; padding: 10px 12px; text-align: left; font-weight: 600; border-bottom: 2px solid #dee2e6; position: sticky; top: 0; }
        td { padding: 8px 12px; border-bottom: 1px solid #eee; }
        tr:hover { background: #f8f9fa; }
        .tier-abandoned { color: #dc3545; font-weight: 600; }
        .tier-critical { color: #c25400; font-weight: 600; }
        .tier-warning { color: #856404; font-weight: 600; }
        .tier-noncompliant { color: #6f42c1; font-weight: 600; }
        .tier-excluded { color: #6c757d; font-style: italic; }
        .status-success { color: #155724; font-weight: 600; }
        .status-failed { color: #721c24; font-weight: 600; }
        .status-dryrun { color: #004085; font-style: italic; }
        .footer { text-align: center; padding: 15px; color: #999; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Intune Device Lifecycle Report</h1>
            <div class="subtitle">Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss") UTC &nbsp;|&nbsp; $modeText</div>
        </div>

        <div class="dashboard">
            <div class="card card-total">
                <div class="count">$totalActionable</div>
                <div class="label">Total Actionable</div>
            </div>
            <div class="card card-warning">
                <div class="count">$($tierCounts.StaleWarning)</div>
                <div class="label">Stale - Warning</div>
            </div>
            <div class="card card-critical">
                <div class="count">$($tierCounts.StaleCritical)</div>
                <div class="label">Stale - Critical</div>
            </div>
            <div class="card card-abandoned">
                <div class="count">$($tierCounts.Abandoned)</div>
                <div class="label">Abandoned</div>
            </div>
            <div class="card card-noncompliant">
                <div class="count">$($tierCounts.ActiveNonCompliant)</div>
                <div class="label">Active Non-Compliant</div>
            </div>
            <div class="card card-excluded">
                <div class="count">$($tierCounts.Excluded)</div>
                <div class="label">Excluded</div>
            </div>
        </div>

        <div class="actions-summary">
            <div><span class="action-badge success">Succeeded: $($actionCounts.Success)</span></div>
            <div><span class="action-badge dryrun">Dry Run: $($actionCounts.DryRun)</span></div>
            <div><span class="action-badge failed">Failed: $($actionCounts.Failed)</span></div>
            <div><span class="action-badge skipped">Skipped: $($actionCounts.Skipped)</span></div>
        </div>

        <div class="table-container">
            <div class="section-header">Device Details ($($Devices.Count) devices)</div>
            <table>
                <thead>
                    <tr>
                        <th>Device Name</th>
                        <th>User (UPN)</th>
                        <th>OS</th>
                        <th>Compliance</th>
                        <th>Days Since Sync</th>
                        <th>Tier</th>
                        <th>Action</th>
                        <th>Status</th>
                        <th>Detail</th>
                    </tr>
                </thead>
                <tbody>
                    $tableRows
                </tbody>
            </table>
        </div>

        <div class="footer">
            Intune Device Lifecycle Automation &mdash; Report generated by automated remediation pipeline
        </div>
    </div>
</body>
</html>
"@

    return $html
}

function Write-RunSummary {
    <#
    .SYNOPSIS
        Writes a summary of the remediation run to the job output.
    .DESCRIPTION
        Displays a formatted summary showing tier counts, action results.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [array]$Devices,

        [Parameter()]
        [array]$ActionResults = @(),

        [Parameter()]
        [switch]$DryRun
    )

    $separator = "=" * 60

    Write-Output ""
    Write-Output $separator
    Write-Output "  INTUNE DEVICE LIFECYCLE - RUN SUMMARY"
    if ($DryRun) {
        Write-Output "  MODE: DRY RUN (no changes applied)"
    }
    else {
        Write-Output "  MODE: LIVE EXECUTION"
    }
    Write-Output $separator
    Write-Output ""

    # Tier breakdown
    Write-Output "  Device Classification:"
    $tiers = @("StaleWarning", "StaleCritical", "Abandoned", "ActiveNonCompliant", "Excluded")
    foreach ($tier in $tiers) {
        $count = @($Devices | Where-Object { $_.Tier -eq $tier }).Count
        Write-Output ("    {0,-22} {1,5}" -f $tier, $count)
    }
    Write-Output ""

    # Action results
    if ($ActionResults.Count -gt 0) {
        Write-Output "  Action Results:"
        $statuses = $ActionResults | Group-Object Status
        foreach ($group in $statuses) {
            Write-Output ("    {0,-22} {1,5}" -f $group.Name, $group.Count)
        }

        # Show failures detail
        $failures = $ActionResults | Where-Object { $_.Status -eq "Failed" }
        if ($failures) {
            Write-Output ""
            Write-Output "  Failed Actions:"
            foreach ($fail in $failures) {
                Write-Output "    - $($fail.DeviceName): $($fail.Detail)"
            }
        }
    }

    Write-Output ""
    Write-Output $separator
}

# ═════════════════════════════════════════════════════════════
# MAIN EXECUTION BLOCK
# ═════════════════════════════════════════════════════════════

try {
    # ─────────────────────────────────────────────────────────
    # Device Discovery & Classification
    # ─────────────────────────────────────────────────────────
    Write-Output "Querying Intune managed devices..."

    $classifiedDevices = Get-ClassifiedDevices `
        -AuthContext $authContext `
        -Config $Config `
        -ExclusionList $Exclusions `
        -Scope $Scope

    if (-not $classifiedDevices -or @($classifiedDevices).Count -eq 0) {
        Write-Output "No actionable devices found. Exiting."
        return
    }

    $deviceCount = @($classifiedDevices).Count
    Write-Output "  Retrieved $deviceCount devices"

    # Tier summary
    $warningCount = @($classifiedDevices | Where-Object { $_.Tier -eq "StaleWarning" }).Count
    $criticalCount = @($classifiedDevices | Where-Object { $_.Tier -eq "StaleCritical" }).Count
    $abandonedCount = @($classifiedDevices | Where-Object { $_.Tier -eq "Abandoned" }).Count
    $nonCompliantCount = @($classifiedDevices | Where-Object { $_.Tier -eq "ActiveNonCompliant" }).Count
    $healthyCount = @($classifiedDevices | Where-Object { $_.Tier -eq "Healthy" }).Count
    Write-Output "  Tier summary: $warningCount Warning, $criticalCount Critical, $abandonedCount Abandoned, $nonCompliantCount Active Non-Compliant, $healthyCount Healthy"

    # ─────────────────────────────────────────────────────────
    # Remediation
    # ─────────────────────────────────────────────────────────
    Write-Output "Processing remediation actions..."

    $actionResults = [System.Collections.Generic.List[PSCustomObject]]::new()
    $processed = 0
    $total = @($classifiedDevices).Count

    foreach ($device in $classifiedDevices) {
        $processed++

        # Skip excluded devices
        if ($device.Tier -eq "Excluded") {
            Write-Verbose "[$processed/$total] Skipping excluded device '$($device.DeviceName)'."
            $actionResults.Add([PSCustomObject]@{
                DeviceId   = $device.DeviceId
                DeviceName = $device.DeviceName
                Action     = "Skipped"
                Status     = "Excluded"
                Detail     = "Device is on the exclusion list"
                Timestamp  = [datetime]::UtcNow.ToString("o")
            })
            continue
        }

        Write-Verbose "[$processed/$total] Processing '$($device.DeviceName)' (Tier: $($device.Tier), Sync: $($device.DaysSinceSync)d ago)..."

        $result = Invoke-TierRemediation `
            -Device $device `
            -AuthContext $authContext `
            -Config $Config `
            -Execute:$Execute

        $actionResults.Add($result)

        # Update device action field for reporting
        $device.Action = $result.Action
    }

    $succeededCount = @($actionResults | Where-Object { $_.Status -eq "Success" }).Count
    $failedCount = @($actionResults | Where-Object { $_.Status -eq "Failed" }).Count
    $skippedCount = @($actionResults | Where-Object { $_.Status -in @("Disabled", "Excluded", "NoAction", "Skipped", "DryRun") }).Count
    Write-Output "  Actions completed. $succeededCount succeeded, $failedCount failed, $skippedCount skipped"

    # ─────────────────────────────────────────────────────────
    # Reporting
    # ─────────────────────────────────────────────────────────
    Write-Output "Generating reports..."

    # CSV-style detail report (formatted table to output)
    Export-DeviceReport `
        -Devices $classifiedDevices `
        -ActionResults $actionResults `
        -RunTimestamp $runTimestamp

    # Approval report for abandoned devices
    Export-ApprovalReport `
        -Devices $classifiedDevices `
        -RunTimestamp $runTimestamp

    # HTML dashboard
    if ($GenerateHtmlReport) {
        $HtmlReportContent = Export-HtmlReport `
            -Devices $classifiedDevices `
            -ActionResults $actionResults `
            -RunTimestamp $runTimestamp `
            -DryRun:(-not $Execute)
        Write-Output "HTML report generated (length: $($HtmlReportContent.Length) chars)"
    }

    # ─────────────────────────────────────────────────────────
    # Summary
    # ─────────────────────────────────────────────────────────
    Write-RunSummary `
        -Devices $classifiedDevices `
        -ActionResults $actionResults `
        -DryRun:(-not $Execute)

    $runEnd = [datetime]::UtcNow
    $durationMinutes = [math]::Round(($runEnd - $runStart).TotalMinutes, 2)
    Write-Output "=== Run complete. Duration: $durationMinutes minutes ==="
}
finally {
    # ─────────────────────────────────────────────────────────
    # Cleanup — Disconnect Graph session
    # ─────────────────────────────────────────────────────────
    try {
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        Write-Output "Disconnected from Microsoft Graph."
    }
    catch {
        Write-Warning "Failed to disconnect from Graph: $_"
    }
}
