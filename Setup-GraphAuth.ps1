# Microsoft Graph Authentication Setup Script
# This script helps set up proper authentication for the Disable-InactiveUsers script

param(
    [Parameter(Mandatory = $true)]
    [string]$TenantId,
    [string]$AppName = "Disable-InactiveUsers-App",
    [switch]$CreateAppRegistration,
    [switch]$InteractiveAuth
)

Write-Host "=== Microsoft Graph Authentication Setup ===" -ForegroundColor Green

if ($CreateAppRegistration) {
    Write-Host "`nCreating Azure App Registration..." -ForegroundColor Yellow
    Write-Host "This requires Azure AD administrative permissions." -ForegroundColor Yellow
    
    # Connect to Microsoft Graph with admin permissions
    Connect-MgGraph -Scopes "Application.ReadWrite.All", "AppRoleAssignment.ReadWrite.All" -TenantId $TenantId
    
    # Required permissions for the app
    $requiredPermissions = @(
        @{ 
            ResourceAppId = "00000003-0000-0000-c000-000000000000"  # Microsoft Graph
            ResourceAccess = @(
                @{ Id = "741f803b-c850-494e-b5df-cde7c675a1ca"; Type = "Role" }, # User.ReadWrite.All
                @{ Id = "b0afded3-3588-46d8-8b3d-9842eff778da"; Type = "Role" }, # AuditLog.Read.All
                @{ Id = "b633e1c5-b582-4048-a93e-9f11b44c7e96"; Type = "Role" }, # Mail.Send
                @{ Id = "7ab1d382-f21e-4acd-a863-ba3e13f7da61"; Type = "Role" }  # Directory.Read.All
            )
        }
    )
    
    try {
        # Create the app registration
        $app = New-MgApplication -DisplayName $AppName -RequiredResourceAccess $requiredPermissions
        
        # Create a service principal for the app
        $sp = New-MgServicePrincipal -AppId $app.AppId
        
        # Create a client secret
        $passwordCredential = @{
            displayName = "Disable-InactiveUsers-Secret"
            endDateTime = (Get-Date).AddMonths(24)
        }
        $secret = Add-MgApplicationPassword -ApplicationId $app.Id -PasswordCredential $passwordCredential
        
        Write-Host "`nApp Registration Created Successfully!" -ForegroundColor Green
        Write-Host "Application ID: $($app.AppId)" -ForegroundColor Cyan
        Write-Host "Tenant ID: $TenantId" -ForegroundColor Cyan
        Write-Host "Client Secret: $($secret.SecretText)" -ForegroundColor Red
        Write-Host "`n⚠️  IMPORTANT: Save the Client Secret - it won't be shown again!" -ForegroundColor Red
        
        Write-Host "`nNext Steps:" -ForegroundColor Yellow
        Write-Host "1. Grant admin consent for the application permissions in Azure Portal" -ForegroundColor Yellow
        Write-Host "2. Update your script to use certificate-based authentication (recommended)" -ForegroundColor Yellow
        Write-Host "3. Store the credentials securely (Azure Key Vault recommended)" -ForegroundColor Yellow
        
        # Save configuration to file
        $config = @"
# Microsoft Graph App Registration Configuration
# Generated on $(Get-Date)

`$GraphAppConfig = @{
    TenantId = "$TenantId"
    ApplicationId = "$($app.AppId)"
    ClientSecret = "$($secret.SecretText)"  # Store securely in production!
}

# Example usage in script:
# `$secureSecret = ConvertTo-SecureString `$GraphAppConfig.ClientSecret -AsPlainText -Force
# `$credential = New-Object System.Management.Automation.PSCredential(`$GraphAppConfig.ApplicationId, `$secureSecret)
# Connect-MgGraph -TenantId `$GraphAppConfig.TenantId -ClientSecretCredential `$credential
"@
        
        $configFile = "GraphAppConfig_$(Get-Date -Format 'yyyyMMdd_HHmmss').ps1"
        $config | Out-File -FilePath $configFile -Encoding UTF8
        Write-Host "`nConfiguration saved to: $configFile" -ForegroundColor Green
        
        Disconnect-MgGraph
    }
    catch {
        Write-Error "Failed to create app registration: $($_.Exception.Message)"
        return
    }
}

if ($InteractiveAuth) {
    Write-Host "`nTesting Interactive Authentication..." -ForegroundColor Yellow
    
    try {
        # Test connection with required scopes
        $scopes = @(
            "User.ReadWrite.All",
            "AuditLog.Read.All", 
            "Mail.Send",
            "Directory.Read.All"
        )
        
        Connect-MgGraph -Scopes $scopes -TenantId $TenantId
        
        # Test basic functionality
        Write-Host "Testing Microsoft Graph connectivity..." -ForegroundColor Yellow
        $context = Get-MgContext
        Write-Host "Connected successfully!" -ForegroundColor Green
        Write-Host "Tenant: $($context.TenantId)" -ForegroundColor Cyan
        Write-Host "Account: $($context.Account)" -ForegroundColor Cyan
        Write-Host "Scopes: $($context.Scopes -join ', ')" -ForegroundColor Cyan
        
        # Test user enumeration
        Write-Host "`nTesting user enumeration..." -ForegroundColor Yellow
        $userCount = (Get-MgUser -Top 5).Count
        Write-Host "Successfully retrieved $userCount users" -ForegroundColor Green
        
        # Test audit log access
        Write-Host "`nTesting audit log access..." -ForegroundColor Yellow
        try {
            $signInLogs = Get-MgAuditLogSignIn -Top 1
            Write-Host "Successfully accessed audit logs" -ForegroundColor Green
        }
        catch {
            Write-Warning "Audit log access failed: $($_.Exception.Message)"
            Write-Host "This may require additional permissions or licensing" -ForegroundColor Yellow
        }
        
        Write-Host "`n✅ Interactive authentication test completed successfully!" -ForegroundColor Green
        
        Disconnect-MgGraph
    }
    catch {
        Write-Error "Authentication test failed: $($_.Exception.Message)"
        return
    }
}

if (-not $CreateAppRegistration -and -not $InteractiveAuth) {
    Write-Host @"
Microsoft Graph Authentication Setup Options:

1. Create App Registration (Recommended for Production):
   .\Setup-GraphAuth.ps1 -TenantId "your-tenant-id" -CreateAppRegistration

2. Test Interactive Authentication:
   .\Setup-GraphAuth.ps1 -TenantId "your-tenant-id" -InteractiveAuth

Required Permissions:
- User.ReadWrite.All (Application)
- AuditLog.Read.All (Application)
- Mail.Send (Application)
- Directory.Read.All (Application)

For production use, consider:
- Certificate-based authentication instead of client secrets
- Azure Key Vault for secure credential storage
- Managed Identity if running on Azure VMs
- Conditional Access policies for additional security

Get your Tenant ID from:
- Azure Portal > Azure Active Directory > Properties > Tenant ID
- PowerShell: (Get-MgContext).TenantId
"@ -ForegroundColor Cyan
}
