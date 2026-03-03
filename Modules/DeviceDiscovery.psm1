<#
.SYNOPSIS
    Device discovery and classification module for Intune managed devices.

.DESCRIPTION
    Queries all managed devices from Microsoft Intune via Graph API,
    handles paging for large inventories, and classifies each device
    into lifecycle tiers based on sync age and compliance state.
#>

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
        tokens to retrieve the full device inventory. Uses $top for batch sizing
        and $select to limit returned properties.

    .PARAMETER AuthContext
        Authentication context hashtable from Connect-GraphInteractive or Connect-GraphAppOnly.

    .PARAMETER BatchSize
        Number of devices to fetch per page. Default 200 (Graph max is typically 1000).

    .PARAMETER MaxDevices
        Maximum total devices to retrieve. 0 = no limit.

    .OUTPUTS
        An array of managed device objects.

    .EXAMPLE
        $devices = Get-AllManagedDevices -AuthContext $auth -BatchSize 100
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

    .PARAMETER Device
        A managed device object from the Graph API.

    .PARAMETER Config
        Configuration object with staleDays_Warning, staleDays_Critical,
        and staleDays_Abandoned thresholds.

    .PARAMETER ReferenceDate
        The date to calculate sync age from. Defaults to current UTC time.

    .OUTPUTS
        A string: "Healthy", "ActiveNonCompliant", "StaleWarning", "StaleCritical", or "Abandoned".

    .EXAMPLE
        $tier = Get-DeviceTier -Device $device -Config $config
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
        Excludes devices that match the exclusion list.

    .PARAMETER AuthContext
        Authentication context hashtable.

    .PARAMETER Config
        Configuration object with thresholds.

    .PARAMETER ExclusionList
        Array of exclusion entries (DeviceId, DeviceName, UserPrincipalName).

    .PARAMETER Scope
        Filter scope: "All", "StaleOnly", or "NonCompliantOnly".

    .OUTPUTS
        An array of PSCustomObjects with device properties plus Tier and DaysSinceSync.

    .EXAMPLE
        $classified = Get-ClassifiedDevices -AuthContext $auth -Config $config -ExclusionList $exclusions
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

    .PARAMETER Device
        A managed device object.

    .PARAMETER ExclusionList
        Array of exclusion entries with DeviceId, DeviceName, and/or UserPrincipalName.

    .OUTPUTS
        $true if the device should be excluded, $false otherwise.
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

function Get-ExclusionList {
    <#
    .SYNOPSIS
        Loads the exclusion list from a CSV file.

    .PARAMETER Path
        Path to the exclusions CSV file.

    .OUTPUTS
        An array of exclusion entries.

    .EXAMPLE
        $exclusions = Get-ExclusionList -Path "./Config/exclusions.csv"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if (-not (Test-Path $Path)) {
        Write-Warning "Exclusion file not found at '$Path'. No devices will be excluded."
        return @()
    }

    try {
        $exclusions = Import-Csv -Path $Path -ErrorAction Stop
        Write-Verbose "Loaded $($exclusions.Count) exclusion entries from '$Path'."
        return $exclusions
    }
    catch {
        Write-Warning "Failed to load exclusion file '$Path': $_"
        return @()
    }
}

Export-ModuleMember -Function Get-AllManagedDevices, Get-DeviceTier, Get-ClassifiedDevices, Test-DeviceExcluded, Get-ExclusionList
