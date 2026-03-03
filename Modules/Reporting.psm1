<#
.SYNOPSIS
    Reporting module for Intune device lifecycle automation.

.DESCRIPTION
    Generates CSV detail reports, approval reports for destructive actions,
    and self-contained HTML dashboard reports suitable for email distribution.
#>

function Export-DeviceReport {
    <#
    .SYNOPSIS
        Exports classified device data and action results to a CSV file.

    .DESCRIPTION
        Creates a detailed CSV report with one row per device, showing its
        tier classification, action taken (or dry-run), and metadata.

    .PARAMETER Devices
        Array of classified device PSCustomObjects.

    .PARAMETER ActionResults
        Array of action result PSCustomObjects from remediation functions.

    .PARAMETER OutputPath
        Directory to write the report to.

    .PARAMETER RunTimestamp
        Timestamp string to include in the filename.

    .OUTPUTS
        The full path to the generated CSV file.

    .EXAMPLE
        $csvPath = Export-DeviceReport -Devices $classified -ActionResults $results -OutputPath "./Output"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [array]$Devices,

        [Parameter()]
        [array]$ActionResults = @(),

        [Parameter(Mandatory)]
        [string]$OutputPath,

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

    $fileName = "DeviceLifecycleReport_$RunTimestamp.csv"
    $filePath = Join-Path $OutputPath $fileName

    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }

    $reportData | Export-Csv -Path $filePath -NoTypeInformation -Encoding UTF8
    Write-Verbose "CSV report written to '$filePath' ($($reportData.Count) records)."
    return $filePath
}

function Export-ApprovalReport {
    <#
    .SYNOPSIS
        Generates an approval report for destructive actions (Retire/Delete).

    .DESCRIPTION
        Filters devices queued for destructive actions and exports them to a
        separate CSV for review before executing a second pass.

    .PARAMETER Devices
        Array of classified device PSCustomObjects.

    .PARAMETER OutputPath
        Directory to write the report to.

    .PARAMETER RunTimestamp
        Timestamp string for the filename.

    .OUTPUTS
        The full path to the generated approval CSV, or $null if no devices need approval.

    .EXAMPLE
        $approvalPath = Export-ApprovalReport -Devices $classified -OutputPath "./Output"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [array]$Devices,

        [Parameter(Mandatory)]
        [string]$OutputPath,

        [Parameter()]
        [string]$RunTimestamp = (Get-Date -Format "yyyyMMdd_HHmmss")
    )

    $approvalDevices = $Devices | Where-Object { $_.Tier -eq "Abandoned" }

    if (-not $approvalDevices -or @($approvalDevices).Count -eq 0) {
        Write-Verbose "No devices require approval. Skipping approval report."
        return $null
    }

    $approvalData = foreach ($device in $approvalDevices) {
        [PSCustomObject]@{
            Approved            = ""    # Blank column for reviewer to fill Yes/No
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

    $fileName = "ApprovalReport_$RunTimestamp.csv"
    $filePath = Join-Path $OutputPath $fileName

    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }

    $approvalData | Export-Csv -Path $filePath -NoTypeInformation -Encoding UTF8
    Write-Verbose "Approval report written to '$filePath' ($(@($approvalDevices).Count) devices)."
    return $filePath
}

function Export-HtmlReport {
    <#
    .SYNOPSIS
        Generates a self-contained HTML dashboard report.

    .DESCRIPTION
        Creates an HTML report with inline CSS showing a summary dashboard
        with tier counts, action results, and a detailed device table.
        Suitable for emailing to leadership.

    .PARAMETER Devices
        Array of classified device PSCustomObjects.

    .PARAMETER ActionResults
        Array of action result PSCustomObjects.

    .PARAMETER OutputPath
        Directory to write the report to.

    .PARAMETER RunTimestamp
        Timestamp string for the filename.

    .PARAMETER DryRun
        Whether this was a dry-run execution.

    .OUTPUTS
        The full path to the generated HTML file.

    .EXAMPLE
        $htmlPath = Export-HtmlReport -Devices $classified -ActionResults $results -OutputPath "./Output" -DryRun
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [array]$Devices,

        [Parameter()]
        [array]$ActionResults = @(),

        [Parameter(Mandatory)]
        [string]$OutputPath,

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

    $fileName = "DeviceLifecycleReport_$RunTimestamp.html"
    $filePath = Join-Path $OutputPath $fileName

    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }

    $html | Out-File -FilePath $filePath -Encoding UTF8
    Write-Verbose "HTML report written to '$filePath'."
    return $filePath
}

function Write-RunSummary {
    <#
    .SYNOPSIS
        Writes a summary of the remediation run to the console.

    .DESCRIPTION
        Displays a formatted summary showing tier counts, action results,
        and paths to generated reports.

    .PARAMETER Devices
        Array of classified device PSCustomObjects.

    .PARAMETER ActionResults
        Array of action result PSCustomObjects.

    .PARAMETER ReportPaths
        Hashtable of report type to file path.

    .PARAMETER DryRun
        Whether this was a dry-run execution.

    .EXAMPLE
        Write-RunSummary -Devices $classified -ActionResults $results -ReportPaths $paths -DryRun
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [array]$Devices,

        [Parameter()]
        [array]$ActionResults = @(),

        [Parameter()]
        [hashtable]$ReportPaths = @{},

        [Parameter()]
        [switch]$DryRun
    )

    $separator = "=" * 60

    Write-Host ""
    Write-Host $separator -ForegroundColor Cyan
    Write-Host "  INTUNE DEVICE LIFECYCLE - RUN SUMMARY" -ForegroundColor Cyan
    if ($DryRun) {
        Write-Host "  MODE: DRY RUN (no changes applied)" -ForegroundColor Yellow
    }
    else {
        Write-Host "  MODE: LIVE EXECUTION" -ForegroundColor Green
    }
    Write-Host $separator -ForegroundColor Cyan
    Write-Host ""

    # Tier breakdown
    Write-Host "  Device Classification:" -ForegroundColor White
    $tiers = @("StaleWarning", "StaleCritical", "Abandoned", "ActiveNonCompliant", "Excluded")
    foreach ($tier in $tiers) {
        $count = @($Devices | Where-Object { $_.Tier -eq $tier }).Count
        $color = switch ($tier) {
            "StaleWarning"       { "Yellow" }
            "StaleCritical"      { "DarkYellow" }
            "Abandoned"          { "Red" }
            "ActiveNonCompliant" { "Magenta" }
            "Excluded"           { "Gray" }
        }
        Write-Host ("    {0,-22} {1,5}" -f $tier, $count) -ForegroundColor $color
    }
    Write-Host ""

    # Action results
    if ($ActionResults.Count -gt 0) {
        Write-Host "  Action Results:" -ForegroundColor White
        $statuses = $ActionResults | Group-Object Status
        foreach ($group in $statuses) {
            $color = switch ($group.Name) {
                "Success"  { "Green" }
                "DryRun"   { "Cyan" }
                "Failed"   { "Red" }
                default    { "Gray" }
            }
            Write-Host ("    {0,-22} {1,5}" -f $group.Name, $group.Count) -ForegroundColor $color
        }

        # Show failures detail
        $failures = $ActionResults | Where-Object { $_.Status -eq "Failed" }
        if ($failures) {
            Write-Host ""
            Write-Host "  Failed Actions:" -ForegroundColor Red
            foreach ($fail in $failures) {
                Write-Host "    - $($fail.DeviceName): $($fail.Detail)" -ForegroundColor Red
            }
        }
    }

    Write-Host ""

    # Reports
    if ($ReportPaths.Count -gt 0) {
        Write-Host "  Reports Generated:" -ForegroundColor White
        foreach ($key in $ReportPaths.Keys) {
            if ($ReportPaths[$key]) {
                Write-Host "    $($key): $($ReportPaths[$key])" -ForegroundColor Gray
            }
        }
    }

    Write-Host ""
    Write-Host $separator -ForegroundColor Cyan
}

Export-ModuleMember -Function Export-DeviceReport, Export-ApprovalReport, Export-HtmlReport, Write-RunSummary
