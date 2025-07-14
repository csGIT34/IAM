# Microsoft Graph and Azure RBAC Permissions Setup Script
# This script helps configure the necessary permissions for the Role Assignment Monitoring solution

<#
.SYNOPSIS
    Sets up Microsoft Graph and Azure RBAC permissions for the Role Assignment Monitoring runbook.

.DESCRIPTION
    This script configures the necessary permissions for the Azure Automation Account's managed identity:
    - Microsoft Graph API permissions for reading directory and role data
    - Azure RBAC permissions for reading role assignments
    - Storage Account permissions for logging

.PARAMETER SubscriptionId
    Azure subscription ID where the Automation Account is located

.PARAMETER ResourceGroupName
    Resource group name containing the Automation Account

.PARAMETER AutomationAccountName
    Name of the Azure Automation Account

.PARAMETER StorageAccountName
    Name of the Azure Storage Account for logging

.PARAMETER MonitoredSubscriptions
    Comma-separated list of subscription IDs to monitor (optional, defaults to current subscription)

.PARAMETER GrantStoragePermissions
    Whether to grant storage permissions automatically

.EXAMPLE
    .\Setup-Permissions.ps1 -SubscriptionId "12345678-1234-1234-1234-123456789012" -ResourceGroupName "rg-automation" -AutomationAccountName "aa-iam" -StorageAccountName "saiamlogging" -GrantStoragePermissions
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$SubscriptionId,
    
    [Parameter(Mandatory = $true)]
    [string]$ResourceGroupName,
    
    [Parameter(Mandatory = $true)]
    [string]$AutomationAccountName,
    
    [Parameter(Mandatory = $true)]
    [string]$StorageAccountName,
    
    [string]$MonitoredSubscriptions = "",
    [switch]$GrantStoragePermissions
)

Write-Host "=== Permissions Setup for Role Assignment Monitoring ===" -ForegroundColor Green
Write-Host "Subscription ID: $SubscriptionId" -ForegroundColor Cyan
Write-Host "Resource Group: $ResourceGroupName" -ForegroundColor Cyan
Write-Host "Automation Account: $AutomationAccountName" -ForegroundColor Cyan

try {
    # Connect to Azure
    Write-Host "Connecting to Azure..." -ForegroundColor Yellow
    $context = Connect-AzAccount
    if (-not $context) {
        throw "Failed to connect to Azure"
    }
    
    # Set subscription context
    Write-Host "Setting subscription context..." -ForegroundColor Yellow
    Set-AzContext -SubscriptionId $SubscriptionId
    
    # Get the managed identity
    Write-Host "Getting managed identity information..." -ForegroundColor Yellow
    $automationAccount = Get-AzAutomationAccount -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName
    $managedIdentityId = $automationAccount.Identity.PrincipalId
    
    if (-not $managedIdentityId) {
        throw "Managed Identity not found. Please ensure it's enabled for the Automation Account."
    }
    
    Write-Host "✓ Managed Identity ID: $managedIdentityId" -ForegroundColor Green
    
    # Connect to Microsoft Graph
    Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Yellow
    try {
        Connect-MgGraph -Scopes 'Application.ReadWrite.All', 'AppRoleAssignment.ReadWrite.All' -NoWelcome
        Write-Host "✓ Connected to Microsoft Graph" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
        Write-Host "Please run the following commands manually:" -ForegroundColor Yellow
        Write-Host "Connect-MgGraph -Scopes 'Application.ReadWrite.All', 'AppRoleAssignment.ReadWrite.All'" -ForegroundColor Cyan
        Write-Host "Then re-run this script." -ForegroundColor Cyan
        exit 1
    }
    
    # Get the managed identity service principal
    Write-Host "Getting managed identity service principal..." -ForegroundColor Yellow
    $managedIdentityPrincipal = Get-MgServicePrincipal -Filter "objectId eq '$managedIdentityId'"
    
    if (-not $managedIdentityPrincipal) {
        throw "Could not find managed identity service principal"
    }
    
    Write-Host "✓ Managed identity service principal found: $($managedIdentityPrincipal.DisplayName)" -ForegroundColor Green
    
    # Get Microsoft Graph service principal
    Write-Host "Getting Microsoft Graph service principal..." -ForegroundColor Yellow
    $graphApp = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"
    
    if (-not $graphApp) {
        throw "Could not find Microsoft Graph service principal"
    }
    
    Write-Host "✓ Microsoft Graph service principal found" -ForegroundColor Green
    
    # Grant Microsoft Graph permissions
    Write-Host "Granting Microsoft Graph permissions..." -ForegroundColor Yellow
    
    $requiredPermissions = @(
        'Directory.Read.All',
        'RoleManagement.Read.All',
        'PrivilegedAccess.Read.AzureAD'
    )
    
    foreach ($permission in $requiredPermissions) {
        Write-Host "Granting permission: $permission" -ForegroundColor Cyan
        
        try {
            # Find the app role
            $appRole = $graphApp.AppRoles | Where-Object { $_.Value -eq $permission }
            
            if (-not $appRole) {
                Write-Warning "Permission '$permission' not found in Microsoft Graph app roles"
                continue
            }
            
            # Check if permission is already granted
            $existingAssignment = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $managedIdentityPrincipal.Id | Where-Object { $_.AppRoleId -eq $appRole.Id }
            
            if ($existingAssignment) {
                Write-Host "✓ Permission '$permission' already granted" -ForegroundColor Green
            } else {
                # Grant the permission
                New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $managedIdentityPrincipal.Id -PrincipalId $managedIdentityPrincipal.Id -ResourceId $graphApp.Id -AppRoleId $appRole.Id
                Write-Host "✓ Permission '$permission' granted successfully" -ForegroundColor Green
            }
        } catch {
            Write-Warning "Failed to grant permission '$permission': $($_.Exception.Message)"
        }
    }
    
    # Grant Azure RBAC permissions
    Write-Host "Granting Azure RBAC permissions..." -ForegroundColor Yellow
    
    $subscriptionsToMonitor = @($SubscriptionId)
    if ($MonitoredSubscriptions) {
        $subscriptionsToMonitor = $MonitoredSubscriptions.Split(',').Trim()
    }
    
    foreach ($subId in $subscriptionsToMonitor) {
        Write-Host "Granting Reader role on subscription: $subId" -ForegroundColor Cyan
        
        try {
            # Set context for the subscription
            Set-AzContext -SubscriptionId $subId
            
            # Check if role assignment already exists
            $existingAssignment = Get-AzRoleAssignment -ObjectId $managedIdentityId -RoleDefinitionName "Reader" -Scope "/subscriptions/$subId"
            
            if ($existingAssignment) {
                Write-Host "✓ Reader role already assigned on subscription $subId" -ForegroundColor Green
            } else {
                # Assign Reader role
                New-AzRoleAssignment -ObjectId $managedIdentityId -RoleDefinitionName "Reader" -Scope "/subscriptions/$subId"
                Write-Host "✓ Reader role assigned on subscription $subId" -ForegroundColor Green
            }
        } catch {
            Write-Warning "Failed to grant Reader role on subscription $subId`: $($_.Exception.Message)"
        }
    }
    
    # Grant Storage Account permissions
    if ($GrantStoragePermissions) {
        Write-Host "Granting Storage Account permissions..." -ForegroundColor Yellow
        
        try {
            # Set context back to the original subscription
            Set-AzContext -SubscriptionId $SubscriptionId
            
            # Get the storage account
            $storageAccount = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -ErrorAction SilentlyContinue
            
            if (-not $storageAccount) {
                Write-Warning "Storage Account '$StorageAccountName' not found in resource group '$ResourceGroupName'"
            } else {
                # Check if role assignment already exists
                $existingAssignment = Get-AzRoleAssignment -ObjectId $managedIdentityId -RoleDefinitionName "Storage Table Data Contributor" -Scope $storageAccount.Id
                
                if ($existingAssignment) {
                    Write-Host "✓ Storage Table Data Contributor role already assigned" -ForegroundColor Green
                } else {
                    # Assign Storage Table Data Contributor role
                    New-AzRoleAssignment -ObjectId $managedIdentityId -RoleDefinitionName "Storage Table Data Contributor" -Scope $storageAccount.Id
                    Write-Host "✓ Storage Table Data Contributor role assigned" -ForegroundColor Green
                }
            }
        } catch {
            Write-Warning "Failed to grant Storage Account permissions: $($_.Exception.Message)"
        }
    }
    
    Write-Host "`n=== Permissions Setup Complete ===" -ForegroundColor Green
    Write-Host "Permissions granted:" -ForegroundColor Yellow
    Write-Host "Microsoft Graph API:" -ForegroundColor Cyan
    foreach ($permission in $requiredPermissions) {
        Write-Host "  - $permission" -ForegroundColor Cyan
    }
    Write-Host "Azure RBAC:" -ForegroundColor Cyan
    foreach ($subId in $subscriptionsToMonitor) {
        Write-Host "  - Reader role on subscription $subId" -ForegroundColor Cyan
    }
    if ($GrantStoragePermissions) {
        Write-Host "Storage Account:" -ForegroundColor Cyan
        Write-Host "  - Storage Table Data Contributor on $StorageAccountName" -ForegroundColor Cyan
    }
    
    Write-Host "`nNext steps:" -ForegroundColor Yellow
    Write-Host "1. Test the runbook manually to verify permissions are working" -ForegroundColor Cyan
    Write-Host "2. Monitor the execution logs for any permission-related errors" -ForegroundColor Cyan
    Write-Host "3. If needed, wait a few minutes for permissions to propagate" -ForegroundColor Cyan
    
    # Disconnect from Microsoft Graph
    Disconnect-MgGraph
    
} catch {
    Write-Error "Permissions setup failed: $($_.Exception.Message)"
    Write-Error "Stack Trace: $($_.ScriptStackTrace)"
    exit 1
}
