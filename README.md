# Intune Non-Compliant Device Lifecycle Automation

PowerShell-based automation that connects to Microsoft Graph API to detect, classify, remediate, and clean up non-compliant devices in Microsoft Intune.

## Features

- **Device Discovery** — Queries all Intune managed devices with automatic paging for large inventories (5,000–20,000+ devices)
- **Tier Classification** — Categorizes devices into actionable tiers based on sync age and compliance state
- **Automated Remediation** — Sync nudge, Entra ID disable, retire, and delete actions per tier
- **Safety First** — Dry-run by default, exclusion lists, approval workflows for destructive actions
- **Reporting** — CSV detail reports, approval CSVs, and self-contained HTML dashboards

## Device Tiers

| Tier | Criteria | Action |
|------|----------|--------|
| **Stale – Warning** | Last sync 30–60 days ago | Flag + notify user/manager |
| **Stale – Critical** | Last sync 60–90 days ago | Disable device in Entra ID |
| **Abandoned** | Last sync 90+ days ago OR no primary user | Queue for removal (retire/delete) |
| **Active Non-Compliant** | Synced within 30 days, not compliant | Trigger sync re-evaluation |
| **Healthy** | Compliant + recent sync | No action (excluded from report) |

## Prerequisites

### PowerShell Modules

```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
Install-Module Microsoft.Graph.DeviceManagement -Scope CurrentUser
Install-Module Microsoft.Graph.Identity.DirectoryManagement -Scope CurrentUser
```

### Azure AD App Registration (for unattended / app-only auth)

1. Go to **Azure Portal > App registrations > New registration**
2. Name: `Intune-Device-Lifecycle-Automation`
3. Under **API permissions**, add these **Application** permissions:
   - `DeviceManagementManagedDevices.ReadWrite.All`
   - `Device.ReadWrite.All`
   - `Directory.ReadWrite.All`
4. Grant admin consent
5. Under **Certificates & secrets**, create a client secret
6. Note the **Application (client) ID**, **Directory (tenant) ID**, and **Client secret value**

### Interactive Auth

For ad-hoc runs, no app registration is needed. The script will open a browser for sign-in. The signed-in user needs these roles:
- Intune Administrator (or Intune Service Administrator)
- Cloud Device Administrator (for Entra ID device operations)

## Usage

### Dry Run (default — no changes made)

```powershell
# Interactive auth, scan all devices
.\Main.ps1 -Verbose

# With HTML report
.\Main.ps1 -GenerateHtmlReport -Verbose

# Stale devices only
.\Main.ps1 -Scope StaleOnly -Verbose
```

### Live Execution

```powershell
# Interactive auth, execute actions
.\Main.ps1 -Execute -Verbose

# App-only auth, execute actions
.\Main.ps1 -Execute -TenantId "your-tenant-id" -ClientId "your-client-id" -ClientSecret "your-secret" -Verbose
```

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-Execute` | Switch | Off | Enable live execution. Without this, everything is dry-run |
| `-ConfigPath` | String | `./Config/thresholds.json` | Path to configuration file |
| `-ExclusionPath` | String | `./Config/exclusions.csv` | Path to exclusion list CSV |
| `-OutputPath` | String | `./Output` | Directory for generated reports |
| `-Scope` | String | `All` | Filter: `All`, `StaleOnly`, `NonCompliantOnly` |
| `-TenantId` | String | — | Azure AD tenant ID (for app-only auth) |
| `-ClientId` | String | — | App registration client ID (for app-only auth) |
| `-ClientSecret` | String | — | App registration client secret (for app-only auth) |
| `-GenerateHtmlReport` | Switch | Off | Generate HTML dashboard in addition to CSV |

## Configuration

### Thresholds (`Config/thresholds.json`)

```json
{
  "staleDays_Warning": 30,
  "staleDays_Critical": 60,
  "staleDays_Abandoned": 90,
  "enableSyncNudge": true,
  "enableDisable": true,
  "enableRetire": false,
  "enableDelete": false,
  "maxDevicesPerRun": 500,
  "batchSize": 20
}
```

- **staleDays_***: Day thresholds for each tier boundary
- **enable***: Toggle individual remediation actions on/off
- **maxDevicesPerRun**: Cap total devices processed (0 = unlimited)
- **batchSize**: Graph API page size for device queries

### Exclusion List (`Config/exclusions.csv`)

CSV with columns: `DeviceId`, `DeviceName`, `UserPrincipalName`, `Reason`

Any matching field excludes the device. Leave fields blank to skip that match criterion.

```csv
DeviceId,DeviceName,UserPrincipalName,Reason
,CONF-ROOM-01,,Conference room device
,KIOSK-LOBBY,,Shared kiosk device
,,vip.user@contoso.com,VIP executive device
```

## Project Structure

```
├── Main.ps1                      # Entry point with parameter handling
├── Modules/
│   ├── Auth.psm1                 # Graph auth (interactive + app-only)
│   ├── DeviceDiscovery.psm1      # Query, page, and classify devices
│   ├── Remediation.psm1          # Sync, disable, retire, delete functions
│   └── Reporting.psm1            # CSV/HTML report generation
├── Config/
│   ├── thresholds.json           # Configurable day thresholds per tier
│   └── exclusions.csv            # Devices/users to exclude
├── Output/                       # Reports generated here
└── README.md
```

## Safety & Governance

- **Dry-run by default**: No action is taken without the `-Execute` switch
- **Exclusion list**: VIP devices, shared kiosks, and conference rooms can be excluded
- **Approval workflow**: Abandoned devices generate an approval CSV for review before destructive actions
- **Rate limiting**: Automatic retry with exponential backoff on HTTP 429 and 5xx errors
- **Paging**: Handles large inventories (20,000+ devices) with `$top` and `@odata.nextLink` pagination
- **Destructive actions disabled by default**: `enableRetire` and `enableDelete` are `false` in the default config

## Reports

### CSV Report
Detailed per-device report with tier, action taken, status, and all device metadata.

### Approval Report
Separate CSV for abandoned devices requiring manual review. Includes a blank `Approved` column for reviewers to fill in before a second execution pass.

### HTML Dashboard
Self-contained HTML with inline CSS — no external dependencies. Includes:
- Summary cards with tier counts
- Action result badges (success/dry-run/failed/skipped)
- Sortable device detail table
- Suitable for emailing to leadership

## Graph API Endpoints Used

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/deviceManagement/managedDevices` | GET | Query all managed devices |
| `/deviceManagement/managedDevices/{id}/syncDevice` | POST | Trigger device sync |
| `/deviceManagement/managedDevices/{id}/rebootNow` | POST | Trigger device reboot |
| `/devices(deviceId='{id}')` | PATCH | Disable device in Entra ID |
| `/deviceManagement/managedDevices/{id}/retire` | POST | Retire device from Intune |
| `/deviceManagement/managedDevices/{id}` | DELETE | Delete device record |

## License

MIT
