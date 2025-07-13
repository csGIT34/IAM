# Azure Automation - Disable Inactive Users

This repository contains an Azure Automation solution for automatically disabling inactive user accounts in both Active Directory and Entra ID (Azure AD). The solution has been specifically designed to run in Azure Automation using managed identity authentication.

## Features

- **Azure Automation Native**: Designed specifically for Azure Automation with managed identity authentication
- **Hybrid Worker Support**: Uses Hybrid Runbook Worker for Active Directory connectivity
- **Multi-Platform Support**: Handles Active Directory, Entra ID cloud users, and Entra ID guest users
- **Multi-Domain Active Directory**: Supports multiple AD domains with Azure Automation credentials
- **Secure Authentication**: Uses Azure Automation managed identity for Graph API access
- **Modern Microsoft Graph API**: Uses the latest Microsoft Graph PowerShell SDK
- **Accurate Inactivity Detection**: Uses LastLogonTimestamp for AD users and sign-in logs for Entra users
- **Cloud-Only Focus**: Processes only cloud-native Entra users (excludes hybrid/synced accounts)
- **Configurable Inactivity Period**: Default 90 days, fully customizable
- **Email Notifications**: Sends warnings via Microsoft Graph (no SMTP required)
- **Azure Storage Logging**: Logs all actions to Azure Storage Table
- **Flexible Exclusions**: Exclude users by AD groups, OUs, or user properties
- **Test Mode**: Safe testing without making actual changes

## Files Overview

### Core Files
1. **AzureAutomation-DisableInactiveUsers.ps1** - Main runbook for Azure Automation
2. **Setup-AzureAutomation.ps1** - Setup script for configuring Azure Automation
3. **Setup-HybridWorker.ps1** - Setup script for configuring Hybrid Runbook Worker
4. **AzureAutomation-Config.ps1** - Configuration template and examples

### Legacy Files (for reference)
- **Disable-InactiveUsers.ps1** - Original on-premises version
- **Config-DisableInactiveUsers.ps1** - Original configuration file
- **Setup-ScheduledTask.ps1** - Original Windows Task Scheduler setup
- **Install-Prerequisites.ps1** - Original module installation script
- **Setup-KeyVaultCredentials.ps1** - Original Key Vault setup script

## Quick Start

### Prerequisites

1. **Azure Resources**:
   - Azure Automation Account with system-assigned managed identity enabled
   - Hybrid Runbook Worker configured and domain-joined
   - Azure Storage Account for logging
   - Microsoft 365 tenant

2. **Permissions**:
   - Azure Subscription Contributor (for setup)
   - Microsoft 365 Global Administrator (for Graph API permissions)
   - Active Directory domain administrative rights

3. **PowerShell Modules** (installed automatically):
   - Az.Accounts, Az.Automation, Az.Storage, Az.Resources
   - Microsoft.Graph modules
   - ActiveDirectory module (on Hybrid Worker)

### Step 1: Set Up Hybrid Runbook Worker

Before configuring the runbook, you need to set up a Hybrid Runbook Worker for Active Directory connectivity:

```powershell
# Run on a domain-joined server
.\Setup-HybridWorker.ps1 -ResourceGroupName "rg-automation-iam" -AutomationAccountName "aa-disable-inactive-users" -HybridWorkerGroupName "ADWorkers"
```

### Step 2: Configure Your Environment

1. Copy and edit the `AzureAutomation-Config.ps1` file:

```powershell
# Edit the configuration values
$AzureAutomationConfig = @{
    SubscriptionId = "your-subscription-id"
    ResourceGroupName = "your-resource-group"
    AutomationAccountName = "your-automation-account"
    StorageAccountName = "your-storage-account"
    StorageAccountKey = "your-storage-key"
    SenderEmail = "admin@yourcompany.com"
    
    DomainCredentials = @{
        "contoso.com" = @{
            Username = "CONTOSO\svc-automation"
            Password = "your-secure-password"
        }
    }
    
    ExcludeGroups = "Domain Admins,Enterprise Admins,Service Accounts"
    HybridWorkerGroup = "ADWorkers"  # Name of your Hybrid Worker Group
    # ... other settings
}
```

### Step 3: Run the Setup Script

```powershell
# Run the setup script
.\Setup-AzureAutomation.ps1 @AzureAutomationConfig
```

This script will:
- Create Azure Automation variables
- Store domain credentials securely
- Install required PowerShell modules
- Create and publish the runbook
- Create a schedule (if requested)
- Configure the runbook to use your Hybrid Worker Group

### Step 4: Configure Managed Identity Permissions

After running the setup script, you'll need to manually configure Microsoft Graph API permissions for the managed identity. The script will provide the exact commands to run.

### Step 5: Test the Runbook

```powershell
# Test in test mode first (must specify Hybrid Worker Group)
Start-AzAutomationRunbook -AutomationAccountName "your-automation-account" -ResourceGroupName "your-resource-group" -Name "DisableInactiveUsers" -RunOn "ADWorkers" -Parameters @{TestMode=$true; DaysInactive=90}
```

### Step 6: Monitor and Validate

1. Check the runbook execution logs in Azure Automation
2. Review the Azure Storage Table for processed users
3. Verify email notifications are being sent
4. Test with a few accounts before full deployment

## Configuration

### Azure Automation Variables

The following variables are automatically created by the setup script:

| Variable Name | Description | Required |
|---------------|-------------|----------|
| StorageAccountName | Azure Storage Account name | Yes |
| StorageAccountKey | Azure Storage Account key | Yes |
| SenderEmail | Email address for notifications | Yes |
| TableName | Storage table name | No (default: InactiveUsers) |
| ExcludeGroups | Comma-separated AD groups to exclude | No |
| ExcludeOUs | Comma-separated OUs to exclude | No |
| ExcludeUserProperty | AD property to check for exclusion | No |
| ExcludeUserPropertyValue | Property value that excludes user | No |
| DomainControllers | Comma-separated domain controllers | No |
| HybridWorkerGroup | Hybrid Worker Group name | No |

### Azure Automation Credentials

Domain credentials are stored as Azure Automation credentials with the naming convention:
- `AD-CONTOSO` for contoso.com domain
- `AD-FABRIKAM` for fabrikam.com domain

### Managed Identity Permissions

The automation account's managed identity requires the following Microsoft Graph API permissions:
- `User.ReadWrite.All` - Read and write user accounts
- `Mail.Send` - Send email notifications
- `AuditLog.Read.All` - Read sign-in logs
- `Directory.Read.All` - Read directory information

## Usage

### Manual Execution

```powershell
# Run with default settings (90 days, test mode off) - MUST specify Hybrid Worker Group
Start-AzAutomationRunbook -AutomationAccountName "aa-iam" -ResourceGroupName "rg-automation" -Name "DisableInactiveUsers" -RunOn "ADWorkers"

# Run with custom parameters
Start-AzAutomationRunbook -AutomationAccountName "aa-iam" -ResourceGroupName "rg-automation" -Name "DisableInactiveUsers" -RunOn "ADWorkers" -Parameters @{
    DaysInactive = 120
    NotificationDays = @(21, 14, 7, 3)
    TestMode = $true
}
```

### Scheduled Execution

The setup script can automatically create a schedule for regular execution:

```powershell
# Create daily schedule at 2:00 AM on Hybrid Worker Group
.\Setup-AzureAutomation.ps1 @AzureAutomationConfig -CreateSchedule -ScheduleFrequency "Daily" -ScheduleTime "02:00" -HybridWorkerGroup "ADWorkers"
```

## Monitoring and Logging

### Azure Storage Table Logging

All processed users are logged to an Azure Storage Table with the following information:
- User details (UPN, display name, SAM account name)
- Account type (ActiveDirectory, EntraID)
- Last logon/sign-in date
- Action taken (Disabled, Notified, etc.)
- Processing timestamp

### Azure Automation Logs

Monitor runbook execution in:
- Azure Portal > Automation Account > Runbooks > DisableInactiveUsers > Recent jobs
- View output, errors, and execution details

### Email Notifications

Users receive email notifications at configurable intervals before account disabling:
- Default: 14, 7, and 3 days before
- Customizable via `NotificationDays` parameter

## Security Considerations

1. **Managed Identity**: Uses Azure Automation's managed identity for secure authentication
2. **Credential Storage**: Domain credentials stored securely in Azure Automation
3. **Least Privilege**: Grant only minimum required permissions
4. **Audit Trail**: All actions logged to Azure Storage Table
5. **Test Mode**: Always test changes before production deployment

## Troubleshooting

### Common Issues

1. **Module Import Errors**
   - Wait for modules to fully install in Azure Automation
   - Check module status in Automation Account > Modules

2. **Graph API Permission Errors**
   - Verify managed identity has required Graph API permissions
   - Check permission grants in Azure AD > Enterprise Applications

3. **Domain Connection Issues**
   - Verify domain credentials are correct
   - Check network connectivity to domain controllers
   - Ensure service account has required permissions

4. **Email Delivery Issues**
   - Verify sender email is a valid Microsoft 365 user
   - Check Graph API Mail.Send permission
   - Test with known good email addresses

### Debugging Steps

1. **Enable Test Mode**: Run with `TestMode=$true` to see what would be processed
2. **Check Logs**: Review Azure Automation runbook logs for detailed error messages
3. **Storage Table**: Check Azure Storage Table for processing details
4. **Manual Testing**: Test individual components (Graph connection, AD connection, etc.)

## Migration from On-Premises

If migrating from the original on-premises version:

1. **Export Current Configuration**: Document current settings and exclusions
2. **Update Exclusions**: Convert file-based exclusions to Azure Automation variables
3. **Test Thoroughly**: Run in test mode with existing data
4. **Schedule Cutover**: Plan transition to avoid duplicate processing

## Support and Contributing

For issues, questions, or contributions:
1. Check the troubleshooting section
2. Review Azure Automation and PowerShell documentation
3. Create issues in the repository for bugs or feature requests

## License

This project is provided as-is for educational and operational use. Please review and test thoroughly before production deployment.

## Changelog

### Version 2.0 (Azure Automation)
- Complete rewrite for Azure Automation compatibility
- Managed identity authentication
- Azure Automation native configuration
- Improved error handling and logging
- Enhanced security model

### Version 1.0 (On-Premises)
- Original on-premises version
- Local scheduled task execution
- Manual module installation
- File-based configuration
