<#
.SYNOPSIS
    Grants a principal read access to App Configuration and Key Vault secrets.

.DESCRIPTION
    Run this script to grant a user, service principal, or managed identity
    the roles needed to read from App Configuration and resolve Key Vault
    secret references at runtime.

    Assigns:
    - "App Configuration Data Reader" on the App Configuration resource
    - Key Vault access policy with 'get' secret permission (or RBAC equivalent)

.PARAMETER PrincipalObjectId
    The Object ID of the user, service principal, or managed identity that
    will run the remediation script.

.PARAMETER PrincipalType
    The type of principal: User, ServicePrincipal, or Group.

.EXAMPLE
    # Grant access to an Azure Automation managed identity
    .\Grant-AppConfigAccess.ps1 -PrincipalObjectId "abc-123-..." -PrincipalType ServicePrincipal

.EXAMPLE
    # Grant access to a user account for testing
    .\Grant-AppConfigAccess.ps1 -PrincipalObjectId "def-456-..." -PrincipalType User
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$PrincipalObjectId,

    [Parameter()]
    [ValidateSet("User", "ServicePrincipal", "Group")]
    [string]$PrincipalType = "ServicePrincipal"
)

$ErrorActionPreference = "Stop"

# ─────────────────────────────────────────────────────────────
# Variables — your environment
# ─────────────────────────────────────────────────────────────
$subscriptionId = "593f8b50-5358-49b5-a615-12aec266efed"
$resourceGroup  = "onbe-it-apps-rg"
$appConfigName  = "onbe-it-apps-ac"
$keyVaultName   = "onbe-it-apps-kv"

$appConfigScope = "/subscriptions/$subscriptionId/resourceGroups/$resourceGroup/providers/Microsoft.AppConfiguration/configurationStores/$appConfigName"

# ─────────────────────────────────────────────────────────────
# Step 0: Set subscription context
# ─────────────────────────────────────────────────────────────
Write-Host "`n[Step 0] Setting subscription context..." -ForegroundColor Cyan
az account set --subscription $subscriptionId

# ─────────────────────────────────────────────────────────────
# Step 1: Assign App Configuration Data Reader role
# ─────────────────────────────────────────────────────────────
Write-Host "`n[Step 1] Assigning 'App Configuration Data Reader' role..." -ForegroundColor Cyan

az role assignment create `
    --assignee-object-id $PrincipalObjectId `
    --assignee-principal-type $PrincipalType `
    --role "App Configuration Data Reader" `
    --scope $appConfigScope `
    --output none

Write-Host "  Role assigned on App Configuration." -ForegroundColor Green

# ─────────────────────────────────────────────────────────────
# Step 2: Grant Key Vault secret read access
# ─────────────────────────────────────────────────────────────
Write-Host "`n[Step 2] Granting Key Vault secret 'get' permission..." -ForegroundColor Cyan

# Check if the Key Vault uses RBAC or vault access policies
$kvProperties = az keyvault show --name $keyVaultName --query "properties.enableRbacAuthorization" -o tsv 2>$null

if ($kvProperties -eq "true") {
    # RBAC mode — assign Key Vault Secrets User role
    Write-Host "  Key Vault is using RBAC authorization." -ForegroundColor Gray
    $kvScope = "/subscriptions/$subscriptionId/resourceGroups/$resourceGroup/providers/Microsoft.KeyVault/vaults/$keyVaultName"

    az role assignment create `
        --assignee-object-id $PrincipalObjectId `
        --assignee-principal-type $PrincipalType `
        --role "Key Vault Secrets User" `
        --scope $kvScope `
        --output none
    Write-Host "  'Key Vault Secrets User' role assigned." -ForegroundColor Green
}
else {
    # Access policy mode
    Write-Host "  Key Vault is using access policies." -ForegroundColor Gray

    az keyvault set-policy `
        --name $keyVaultName `
        --object-id $PrincipalObjectId `
        --secret-permissions get `
        --output none
    Write-Host "  Access policy set (secret: get)." -ForegroundColor Green
}

# ─────────────────────────────────────────────────────────────
# Done
# ─────────────────────────────────────────────────────────────
Write-Host "`n════════════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host "  Access granted for principal $PrincipalObjectId" -ForegroundColor Green
Write-Host "════════════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host ""
Write-Host "The principal can now:" -ForegroundColor Yellow
Write-Host "  - Read settings from App Configuration (onbe-it-apps-ac)" -ForegroundColor White
Write-Host "  - Resolve Key Vault secret references (onbe-it-apps-kv)" -ForegroundColor White
Write-Host ""
