# Azure Automation Configuration Template
# This file contains example configuration for setting up the Azure Automation environment

<#
.SYNOPSIS
    Configuration template for Azure Automation Disable Inactive Users runbook.

.DESCRIPTION
    This template provides examples of how to configure the Azure Automation setup script
    with your specific environment settings.

.NOTES
    Before using this template:
    1. Replace all placeholder values with your actual values
    2. Ensure you have the necessary permissions in Azure
    3. Test with a small subset first
#>

# Example configuration for Azure Automation setup
$AzureAutomationConfig = @{
    # Azure Subscription and Resources
    SubscriptionId = "12345678-1234-1234-1234-123456789012"  # Replace with your subscription ID
    ResourceGroupName = "rg-automation-iam"                   # Replace with your resource group
    AutomationAccountName = "aa-disable-inactive-users"      # Replace with your automation account name
    
    # Azure Storage for logging
    StorageAccountName = "saiamlogging"                       # Replace with your storage account name
    StorageAccountKey = "your-storage-account-key-here"       # Replace with your storage account key
    TableName = "InactiveUsers"                               # Default table name (can be changed)
    
    # Email configuration
    SenderEmail = "admin@yourcompany.com"                     # Replace with valid Microsoft 365 user
    
    # Domain credentials (add/remove domains as needed)
    DomainCredentials = @{
        "contoso.com" = @{
            Username = "CONTOSO\svc-automation"               # Replace with your domain service account
            Password = "your-secure-password-here"            # Replace with actual password
        }
        "fabrikam.com" = @{
            Username = "FABRIKAM\svc-automation"              # Replace with your domain service account
            Password = "your-secure-password-here"            # Replace with actual password
        }
        # Add more domains as needed
    }
    
    # Optional exclusion settings
    ExcludeGroups = "Domain Admins,Enterprise Admins,Service Accounts,Exempt from Disable"
    ExcludeOUs = "OU=Service Accounts,DC=contoso,DC=com;OU=System Accounts,DC=contoso,DC=com;OU=Service Accounts,DC=fabrikam,DC=com;OU=System Accounts,DC=fabrikam,DC=com"
    ExcludeUserProperty = "Department"                        # Optional: exclude users based on property
    ExcludeUserPropertyValue = "IT"                           # Optional: property value to exclude
    
    # Domain controllers (optional - if not specified, auto-discovery will be used)
    DomainControllers = "dc1.contoso.com,dc2.contoso.com,dc1.fabrikam.com,dc2.fabrikam.com"
    
    # Hybrid Worker Group for Active Directory connectivity (REQUIRED for AD operations)
    HybridWorkerGroup = "ADWorkers"                           # Replace with your Hybrid Worker Group name
    
    # Scheduling
    CreateSchedule = $true                                    # Set to $false to skip schedule creation
    ScheduleFrequency = "Daily"                               # Daily, Weekly, or Monthly
    ScheduleTime = "02:00"                                    # 24-hour format
}

# Example usage of the setup script
Write-Host "Example command to run the setup script:" -ForegroundColor Green
Write-Host ".\Setup-AzureAutomation.ps1 @AzureAutomationConfig" -ForegroundColor Yellow

# Individual parameter example
Write-Host "`nAlternative command with individual parameters:" -ForegroundColor Green
@"
.\Setup-AzureAutomation.ps1 `
    -SubscriptionId "$($AzureAutomationConfig.SubscriptionId)" `
    -ResourceGroupName "$($AzureAutomationConfig.ResourceGroupName)" `
    -AutomationAccountName "$($AzureAutomationConfig.AutomationAccountName)" `
    -StorageAccountName "$($AzureAutomationConfig.StorageAccountName)" `
    -StorageAccountKey "$($AzureAutomationConfig.StorageAccountKey)" `
    -SenderEmail "$($AzureAutomationConfig.SenderEmail)" `
    -DomainCredentials `$domainCredentials `
    -ExcludeGroups "$($AzureAutomationConfig.ExcludeGroups)" `
    -ExcludeOUs "$($AzureAutomationConfig.ExcludeOUs)" `
    -ExcludeUserProperty "$($AzureAutomationConfig.ExcludeUserProperty)" `
    -ExcludeUserPropertyValue "$($AzureAutomationConfig.ExcludeUserPropertyValue)" `
    -DomainControllers "$($AzureAutomationConfig.DomainControllers)" `
    -HybridWorkerGroup "$($AzureAutomationConfig.HybridWorkerGroup)" `
    -CreateSchedule `
    -ScheduleFrequency "$($AzureAutomationConfig.ScheduleFrequency)" `
    -ScheduleTime "$($AzureAutomationConfig.ScheduleTime)"
"@ | Write-Host -ForegroundColor Yellow

# Prerequisites checklist
Write-Host "`n=== PREREQUISITES CHECKLIST ===" -ForegroundColor Cyan
Write-Host "Before running the setup script, ensure you have:" -ForegroundColor Yellow
Write-Host "☐ Azure subscription with appropriate permissions" -ForegroundColor Yellow
Write-Host "☐ Azure Automation Account created" -ForegroundColor Yellow
Write-Host "☐ Azure Storage Account created" -ForegroundColor Yellow
Write-Host "☐ Microsoft 365 tenant with admin access" -ForegroundColor Yellow
Write-Host "☐ Domain service accounts with appropriate permissions" -ForegroundColor Yellow
Write-Host "☐ Hybrid Runbook Worker configured and domain-joined" -ForegroundColor Yellow
Write-Host "☐ PowerShell modules installed (Az.Accounts, Az.Automation, Az.Resources, Az.Storage)" -ForegroundColor Yellow

# Required permissions
Write-Host "`n=== REQUIRED PERMISSIONS ===" -ForegroundColor Cyan
Write-Host "Azure Subscription:" -ForegroundColor Yellow
Write-Host "- Contributor on the Resource Group containing the Automation Account" -ForegroundColor Yellow
Write-Host "- Storage Account Contributor on the logging storage account" -ForegroundColor Yellow
Write-Host "" -ForegroundColor Yellow
Write-Host "Microsoft 365:" -ForegroundColor Yellow
Write-Host "- Global Administrator (to grant Graph API permissions)" -ForegroundColor Yellow
Write-Host "- Or Application Administrator + Directory.ReadWrite.All" -ForegroundColor Yellow
Write-Host "" -ForegroundColor Yellow
Write-Host "Active Directory:" -ForegroundColor Yellow
Write-Host "- Domain service accounts need:" -ForegroundColor Yellow
Write-Host "  * Read permissions on user objects" -ForegroundColor Yellow
Write-Host "  * Write permissions to disable user accounts" -ForegroundColor Yellow
Write-Host "  * Read permissions on group memberships" -ForegroundColor Yellow
Write-Host "" -ForegroundColor Yellow
Write-Host "Hybrid Runbook Worker:" -ForegroundColor Yellow
Write-Host "- Server must be domain-joined" -ForegroundColor Yellow
Write-Host "- ActiveDirectory PowerShell module installed" -ForegroundColor Yellow
Write-Host "- Network connectivity to domain controllers" -ForegroundColor Yellow
Write-Host "- Network connectivity to Azure (port 443)" -ForegroundColor Yellow

# Testing recommendations
Write-Host "`n=== TESTING RECOMMENDATIONS ===" -ForegroundColor Cyan
Write-Host "1. Start with TestMode=`$true to see what would be processed" -ForegroundColor Yellow
Write-Host "2. Create a test OU with a few test users for initial validation" -ForegroundColor Yellow
Write-Host "3. Test with a higher DaysInactive value (e.g., 365) first" -ForegroundColor Yellow
Write-Host "4. Review Azure Storage Table logs after each test run" -ForegroundColor Yellow
Write-Host "5. Test email notifications with a test user account" -ForegroundColor Yellow
Write-Host "6. Gradually reduce DaysInactive to production value" -ForegroundColor Yellow

# Common issues and solutions
Write-Host "`n=== COMMON ISSUES AND SOLUTIONS ===" -ForegroundColor Cyan
Write-Host "Issue: 'Module not found' errors in runbook" -ForegroundColor Red
Write-Host "Solution: Wait for modules to fully install in Automation Account" -ForegroundColor Green
Write-Host "" -ForegroundColor Yellow
Write-Host "Issue: 'Insufficient privileges' for Graph API" -ForegroundColor Red
Write-Host "Solution: Grant API permissions to the managed identity" -ForegroundColor Green
Write-Host "" -ForegroundColor Yellow
Write-Host "Issue: 'Cannot connect to domain controller'" -ForegroundColor Red
Write-Host "Solution: Verify network connectivity and domain controller accessibility" -ForegroundColor Green
Write-Host "" -ForegroundColor Yellow
Write-Host "Issue: 'Access denied' when disabling users" -ForegroundColor Red
Write-Host "Solution: Verify domain service account has sufficient permissions" -ForegroundColor Green

# Security considerations
Write-Host "`n=== SECURITY CONSIDERATIONS ===" -ForegroundColor Cyan
Write-Host "1. Use dedicated service accounts with minimum required permissions" -ForegroundColor Yellow
Write-Host "2. Rotate domain service account passwords regularly" -ForegroundColor Yellow
Write-Host "3. Monitor Azure Automation logs for unauthorized access attempts" -ForegroundColor Yellow
Write-Host "4. Use Azure Key Vault for sensitive configuration if needed" -ForegroundColor Yellow
Write-Host "5. Enable audit logging in Active Directory" -ForegroundColor Yellow
Write-Host "6. Review exclusion lists regularly to prevent unauthorized exemptions" -ForegroundColor Yellow

# Monitoring and maintenance
Write-Host "`n=== MONITORING AND MAINTENANCE ===" -ForegroundColor Cyan
Write-Host "1. Set up alerts for runbook failures" -ForegroundColor Yellow
Write-Host "2. Monitor Azure Storage Table for processing metrics" -ForegroundColor Yellow
Write-Host "3. Review disabled accounts monthly" -ForegroundColor Yellow
Write-Host "4. Update exclusion lists as organizational structure changes" -ForegroundColor Yellow
Write-Host "5. Test email delivery periodically" -ForegroundColor Yellow
Write-Host "6. Review and update notification timing as needed" -ForegroundColor Yellow
Write-Host "7. Set up PowerBI dashboard for data visualization" -ForegroundColor Yellow

# PowerBI Dashboard Setup
Write-Host "`n=== POWERBI DASHBOARD SETUP ===" -ForegroundColor Cyan
Write-Host "After the automation is running, consider setting up a PowerBI dashboard:" -ForegroundColor Yellow
Write-Host "1. Follow the guide in PowerBI-Dashboard-Setup.md" -ForegroundColor Yellow
Write-Host "2. Use the pre-built template in PowerBI-Template-Guide.md" -ForegroundColor Yellow
Write-Host "3. Configure automated data refresh" -ForegroundColor Yellow
Write-Host "4. Set up alerts for key metrics" -ForegroundColor Yellow
Write-Host "5. Share dashboard with relevant stakeholders" -ForegroundColor Yellow
Write-Host "" -ForegroundColor Yellow
Write-Host "PowerBI Dashboard Benefits:" -ForegroundColor Green
Write-Host "- Visual trends and analytics" -ForegroundColor Green
Write-Host "- Real-time monitoring capabilities" -ForegroundColor Green
Write-Host "- Compliance reporting" -ForegroundColor Green
Write-Host "- Executive summary views" -ForegroundColor Green
Write-Host "- Automated alerts and notifications" -ForegroundColor Green
