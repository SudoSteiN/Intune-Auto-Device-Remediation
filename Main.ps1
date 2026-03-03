<#
.SYNOPSIS
    Intune Non-Compliant Device Lifecycle Automation.

.DESCRIPTION
    Connects to Microsoft Graph API to detect, classify, remediate, and clean up
    non-compliant devices in Microsoft Intune. Distinguishes between stale devices
    (not checking in) and actively non-compliant devices, taking appropriate action
    for each category.

    Runs in DRY-RUN mode by default. Use the -Execute switch to apply changes.

.PARAMETER Execute
    Switch to enable live execution. Without this, all actions are dry-run only.

.PARAMETER ConfigPath
    Path to the thresholds.json configuration file.

.PARAMETER ExclusionPath
    Path to the exclusions.csv file with devices/users to skip.

.PARAMETER OutputPath
    Directory for generated reports.

.PARAMETER Scope
    Filter which devices to process: All, StaleOnly, or NonCompliantOnly.

.PARAMETER TenantId
    Azure AD tenant ID for app-only authentication.

.PARAMETER ClientId
    App registration client ID for app-only authentication.

.PARAMETER ClientSecret
    App registration client secret for app-only authentication.

.PARAMETER GenerateHtmlReport
    Switch to generate an HTML dashboard report in addition to CSV.

.EXAMPLE
    # Dry-run scan of all devices (interactive auth)
    .\Main.ps1 -Verbose

.EXAMPLE
    # Live execution with app-only auth, stale devices only
    .\Main.ps1 -Execute -Scope StaleOnly -TenantId $tid -ClientId $cid -ClientSecret $sec

.EXAMPLE
    # Dry-run with HTML report and custom config
    .\Main.ps1 -ConfigPath "./Config/thresholds.json" -GenerateHtmlReport -Verbose
#>

[CmdletBinding()]
param(
    [switch]$Execute,

    [string]$ConfigPath = (Join-Path $PSScriptRoot "Config" "thresholds.json"),

    [string]$ExclusionPath = (Join-Path $PSScriptRoot "Config" "exclusions.csv"),

    [string]$OutputPath = (Join-Path $PSScriptRoot "Output"),

    [ValidateSet("All", "StaleOnly", "NonCompliantOnly")]
    [string]$Scope = "All",

    [string]$TenantId,

    [string]$ClientId,

    [string]$ClientSecret,

    [switch]$GenerateHtmlReport
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Add System.Web for HTML encoding in reports
Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue

$runTimestamp = Get-Date -Format "yyyyMMdd_HHmmss"

# ─────────────────────────────────────────────────────────────
# Import Modules
# ─────────────────────────────────────────────────────────────
$modulesPath = Join-Path $PSScriptRoot "Modules"

Write-Verbose "Loading modules from '$modulesPath'..."
Import-Module (Join-Path $modulesPath "Auth.psm1") -Force
Import-Module (Join-Path $modulesPath "DeviceDiscovery.psm1") -Force
Import-Module (Join-Path $modulesPath "Remediation.psm1") -Force
Import-Module (Join-Path $modulesPath "Reporting.psm1") -Force

# ─────────────────────────────────────────────────────────────
# Load Configuration
# ─────────────────────────────────────────────────────────────
Write-Verbose "Loading configuration from '$ConfigPath'..."
if (-not (Test-Path $ConfigPath)) {
    throw "Configuration file not found at '$ConfigPath'. Please create it or specify a valid path with -ConfigPath."
}

$config = Get-Content -Path $ConfigPath -Raw | ConvertFrom-Json
Write-Verbose "Configuration loaded: Warning=$($config.staleDays_Warning)d, Critical=$($config.staleDays_Critical)d, Abandoned=$($config.staleDays_Abandoned)d"
Write-Verbose "Actions enabled: SyncNudge=$($config.enableSyncNudge), Disable=$($config.enableDisable), Retire=$($config.enableRetire), Delete=$($config.enableDelete)"

# ─────────────────────────────────────────────────────────────
# Load Exclusion List
# ─────────────────────────────────────────────────────────────
Write-Verbose "Loading exclusion list from '$ExclusionPath'..."
$exclusionList = Get-ExclusionList -Path $ExclusionPath

# ─────────────────────────────────────────────────────────────
# Authenticate to Microsoft Graph
# ─────────────────────────────────────────────────────────────
Write-Host ""
if ($TenantId -and $ClientId -and $ClientSecret) {
    Write-Host "Authenticating with app-only (client credentials) flow..." -ForegroundColor Cyan
    $authContext = Connect-GraphAppOnly -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret
}
else {
    Write-Host "Authenticating with interactive (delegated) flow..." -ForegroundColor Cyan
    Write-Host "  (Provide -TenantId, -ClientId, -ClientSecret for unattended app-only auth)" -ForegroundColor Gray
    $connectParams = @{}
    if ($TenantId) { $connectParams.TenantId = $TenantId }
    $authContext = Connect-GraphInteractive @connectParams
}

Write-Host "Authentication successful. Auth type: $($authContext.AuthType)" -ForegroundColor Green

# ─────────────────────────────────────────────────────────────
# Mode Banner
# ─────────────────────────────────────────────────────────────
Write-Host ""
if ($Execute) {
    Write-Warning "═══════════════════════════════════════════════════════════"
    Write-Warning "  LIVE EXECUTION MODE — Changes WILL be applied to devices"
    Write-Warning "═══════════════════════════════════════════════════════════"
}
else {
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  DRY RUN MODE — No changes will be made (use -Execute)" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
}
Write-Host ""

# ─────────────────────────────────────────────────────────────
# Device Discovery & Classification
# ─────────────────────────────────────────────────────────────
Write-Host "Discovering and classifying devices (Scope: $Scope)..." -ForegroundColor Cyan

$classifiedDevices = Get-ClassifiedDevices `
    -AuthContext $authContext `
    -Config $config `
    -ExclusionList $exclusionList `
    -Scope $Scope

if (-not $classifiedDevices -or @($classifiedDevices).Count -eq 0) {
    Write-Host "No actionable devices found. Exiting." -ForegroundColor Yellow
    exit 0
}

Write-Host "Found $(@($classifiedDevices).Count) actionable device(s)." -ForegroundColor Green
Write-Host ""

# ─────────────────────────────────────────────────────────────
# Remediation
# ─────────────────────────────────────────────────────────────
Write-Host "Processing remediation actions..." -ForegroundColor Cyan

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
        -Config $config `
        -Execute:$Execute

    $actionResults.Add($result)

    # Update device action field for reporting
    $device.Action = $result.Action
}

Write-Host "Remediation processing complete." -ForegroundColor Green
Write-Host ""

# ─────────────────────────────────────────────────────────────
# Reporting
# ─────────────────────────────────────────────────────────────
Write-Host "Generating reports..." -ForegroundColor Cyan

$reportPaths = @{}

# CSV detail report
$csvPath = Export-DeviceReport `
    -Devices $classifiedDevices `
    -ActionResults $actionResults `
    -OutputPath $OutputPath `
    -RunTimestamp $runTimestamp
$reportPaths["CSV"] = $csvPath

# Approval report for abandoned devices
$approvalPath = Export-ApprovalReport `
    -Devices $classifiedDevices `
    -OutputPath $OutputPath `
    -RunTimestamp $runTimestamp
if ($approvalPath) {
    $reportPaths["Approval"] = $approvalPath
}

# HTML dashboard
if ($GenerateHtmlReport) {
    $htmlPath = Export-HtmlReport `
        -Devices $classifiedDevices `
        -ActionResults $actionResults `
        -OutputPath $OutputPath `
        -RunTimestamp $runTimestamp `
        -DryRun:(-not $Execute)
    $reportPaths["HTML"] = $htmlPath
}

# ─────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────
Write-RunSummary `
    -Devices $classifiedDevices `
    -ActionResults $actionResults `
    -ReportPaths $reportPaths `
    -DryRun:(-not $Execute)
