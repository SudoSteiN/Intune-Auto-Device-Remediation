<#
.SYNOPSIS
    Remediation actions module for Intune device lifecycle management.

.DESCRIPTION
    Provides functions to take corrective actions on non-compliant or stale
    devices: sync nudge, compliance re-evaluation, disable in Entra ID,
    retire from Intune, and delete/wipe. All functions support dry-run mode.
#>

function Invoke-DeviceSyncNudge {
    <#
    .SYNOPSIS
        Triggers a sync on a managed device in Intune.

    .DESCRIPTION
        Sends a POST to /deviceManagement/managedDevices/{id}/syncDevice
        to force the device to check in. Used for active non-compliant devices.

    .PARAMETER DeviceId
        The Intune managed device ID.

    .PARAMETER DeviceName
        The device name (for logging).

    .PARAMETER AuthContext
        Authentication context hashtable.

    .PARAMETER Execute
        If $false (default), performs a dry run and logs what would happen.

    .OUTPUTS
        A PSCustomObject with action result details.

    .EXAMPLE
        Invoke-DeviceSyncNudge -DeviceId $id -DeviceName "LAPTOP-01" -AuthContext $auth -Execute
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
        This is an optional/configurable action for non-compliant devices.

    .PARAMETER DeviceId
        The Intune managed device ID.

    .PARAMETER DeviceName
        The device name (for logging).

    .PARAMETER AuthContext
        Authentication context hashtable.

    .PARAMETER Execute
        If $false (default), performs a dry run.

    .OUTPUTS
        A PSCustomObject with action result details.

    .EXAMPLE
        Invoke-DeviceReboot -DeviceId $id -DeviceName "LAPTOP-01" -AuthContext $auth -Execute
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
        Used for stale-critical devices that haven't synced in 60-90 days.

    .PARAMETER AzureADDeviceId
        The Azure AD device ID (not the Intune device ID).

    .PARAMETER DeviceName
        The device name (for logging).

    .PARAMETER AuthContext
        Authentication context hashtable.

    .PARAMETER Execute
        If $false (default), performs a dry run.

    .OUTPUTS
        A PSCustomObject with action result details.

    .EXAMPLE
        Disable-EntraDevice -AzureADDeviceId $aadId -DeviceName "LAPTOP-01" -AuthContext $auth -Execute
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
        Removes company data but leaves personal data. Used for abandoned devices.

    .PARAMETER DeviceId
        The Intune managed device ID.

    .PARAMETER DeviceName
        The device name (for logging).

    .PARAMETER AuthContext
        Authentication context hashtable.

    .PARAMETER Execute
        If $false (default), performs a dry run.

    .OUTPUTS
        A PSCustomObject with action result details.

    .EXAMPLE
        Invoke-DeviceRetire -DeviceId $id -DeviceName "LAPTOP-01" -AuthContext $auth -Execute
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
        Only used for abandoned-tier devices with explicit approval.

    .PARAMETER DeviceId
        The Intune managed device ID.

    .PARAMETER DeviceName
        The device name (for logging).

    .PARAMETER AuthContext
        Authentication context hashtable.

    .PARAMETER Execute
        If $false (default), performs a dry run.

    .OUTPUTS
        A PSCustomObject with action result details.

    .EXAMPLE
        Remove-ManagedDevice -DeviceId $id -DeviceName "LAPTOP-01" -AuthContext $auth -Execute
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

    .PARAMETER Device
        A classified device PSCustomObject (with Tier property).

    .PARAMETER AuthContext
        Authentication context hashtable.

    .PARAMETER Config
        Configuration object with action enable/disable flags.

    .PARAMETER Execute
        If $false (default), performs a dry run.

    .OUTPUTS
        A PSCustomObject with action result details.

    .EXAMPLE
        $result = Invoke-TierRemediation -Device $device -AuthContext $auth -Config $config
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

Export-ModuleMember -Function Invoke-DeviceSyncNudge, Invoke-DeviceReboot, Disable-EntraDevice, Invoke-DeviceRetire, Remove-ManagedDevice, Invoke-TierRemediation
