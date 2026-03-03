<#
.SYNOPSIS
    Sets up Azure App Configuration and Key Vault for Intune Device Remediation.

.DESCRIPTION
    Run this script to populate Azure App Configuration with the required
    key-value pairs and store the client secret in Azure Key Vault as a
    Key Vault reference. Requires the Azure CLI (az) to be installed and
    authenticated (az login).

    IMPORTANT: Before running this script:
    1. Run 'az login' and authenticate with an account that has:
       - Contributor or App Configuration Data Owner on the App Configuration resource
       - Key Vault Administrator or Secret Officer on the Key Vault
    2. Set $ClientSecretValue below to your actual app registration client secret

.NOTES
    Resource Details:
    - App Configuration: onbe-it-apps-ac (https://onbe-it-apps-ac.azconfig.io)
    - Key Vault:         onbe-it-apps-kv (https://onbe-it-apps-kv.vault.azure.net/)
    - Resource Group:    onbe-it-apps-rg
    - Subscription:      593f8b50-5358-49b5-a615-12aec266efed
    - Tenant:            1177360f-f994-4f28-9ee0-f8c5bbd289cf
    - App Registration:  IT-PowerShell-Scripting (b634f5cc-9e81-443d-8123-4ac8b2ca8963)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$ClientSecretValue
)

$ErrorActionPreference = "Stop"

# ─────────────────────────────────────────────────────────────
# Variables — your environment
# ─────────────────────────────────────────────────────────────
$subscriptionId   = "593f8b50-5358-49b5-a615-12aec266efed"
$resourceGroup    = "onbe-it-apps-rg"
$appConfigName    = "onbe-it-apps-ac"
$keyVaultName     = "onbe-it-apps-kv"
$tenantId         = "1177360f-f994-4f28-9ee0-f8c5bbd289cf"
$clientId         = "b634f5cc-9e81-443d-8123-4ac8b2ca8963"
$kvSecretName     = "IntuneRemediation-GraphClientSecret"
$prefix           = "IntuneRemediation"

# ─────────────────────────────────────────────────────────────
# Step 0: Set subscription context
# ─────────────────────────────────────────────────────────────
Write-Host "`n[Step 0] Setting subscription context..." -ForegroundColor Cyan
az account set --subscription $subscriptionId
Write-Host "  Subscription set to $subscriptionId" -ForegroundColor Green

# ─────────────────────────────────────────────────────────────
# Step 1: Store client secret in Key Vault
# ─────────────────────────────────────────────────────────────
Write-Host "`n[Step 1] Storing client secret in Key Vault '$keyVaultName'..." -ForegroundColor Cyan
az keyvault secret set `
    --vault-name $keyVaultName `
    --name $kvSecretName `
    --value $ClientSecretValue `
    --output none

Write-Host "  Secret '$kvSecretName' stored successfully." -ForegroundColor Green

# ─────────────────────────────────────────────────────────────
# Step 2: Add App Configuration key-value pairs
# ─────────────────────────────────────────────────────────────
Write-Host "`n[Step 2] Populating App Configuration '$appConfigName'..." -ForegroundColor Cyan

# Auth settings (plain values)
$plainSettings = @{
    "${prefix}:TenantId"           = $tenantId
    "${prefix}:ClientId"           = $clientId
    "${prefix}:StaleDays_Warning"  = "30"
    "${prefix}:StaleDays_Critical" = "60"
    "${prefix}:StaleDays_Abandoned"= "90"
    "${prefix}:EnableSyncNudge"    = "true"
    "${prefix}:EnableDisable"      = "true"
    "${prefix}:EnableRetire"       = "false"
    "${prefix}:EnableDelete"       = "false"
    "${prefix}:MaxDevicesPerRun"   = "500"
    "${prefix}:BatchSize"          = "20"
}

foreach ($key in $plainSettings.Keys) {
    Write-Host "  Setting $key = $($plainSettings[$key])"
    az appconfig kv set `
        --name $appConfigName `
        --key $key `
        --value $plainSettings[$key] `
        --yes `
        --output none
}

Write-Host "  Plain key-value pairs set." -ForegroundColor Green

# ─────────────────────────────────────────────────────────────
# Step 3: Add Key Vault reference for the client secret
# ─────────────────────────────────────────────────────────────
Write-Host "`n[Step 3] Creating Key Vault reference for client secret..." -ForegroundColor Cyan

$kvSecretUri = "https://${keyVaultName}.vault.azure.net/secrets/${kvSecretName}"

az appconfig kv set-keyvault `
    --name $appConfigName `
    --key "${prefix}:ClientSecret" `
    --secret-identifier $kvSecretUri `
    --yes `
    --output none

Write-Host "  Key Vault reference '${prefix}:ClientSecret' -> '$kvSecretUri' created." -ForegroundColor Green

# ─────────────────────────────────────────────────────────────
# Step 4: Verify — list all keys under prefix
# ─────────────────────────────────────────────────────────────
Write-Host "`n[Step 4] Verifying App Configuration keys..." -ForegroundColor Cyan
az appconfig kv list --name $appConfigName --key "${prefix}:*" --output table

# ─────────────────────────────────────────────────────────────
# Done
# ─────────────────────────────────────────────────────────────
Write-Host "`n════════════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host "  Setup complete!" -ForegroundColor Green
Write-Host "════════════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host ""
Write-Host "To run the remediation script with App Configuration:" -ForegroundColor Yellow
Write-Host ""
Write-Host '  .\Main.ps1 -AppConfigEndpoint "https://onbe-it-apps-ac.azconfig.io" -Verbose' -ForegroundColor White
Write-Host ""
Write-Host "Or with a connection string:" -ForegroundColor Yellow
Write-Host ""
Write-Host '  $connStr = az appconfig credential list --name onbe-it-apps-ac --query "[?name==''Primary Read Only''].connectionString" -o tsv' -ForegroundColor White
Write-Host '  .\Main.ps1 -AppConfigConnectionString $connStr -Verbose' -ForegroundColor White
Write-Host ""
