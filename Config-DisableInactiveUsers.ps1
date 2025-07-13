# Configuration file for Disable-InactiveUsers.ps1
# Copy this file and customize for your environment

# Basic Settings
$Config = @{
    # Number of days of inactivity before account is disabled
    DaysInactive = 90
    
    # Days before disable date to send notifications
    NotificationDays = @(14, 7, 3)
    
    # Azure Storage Settings (REQUIRED)
    StorageAccountName = "yourstorageaccount"
    StorageAccountKey = "your-storage-account-key-here"
    TableName = "InactiveUsers"
    
    # Email Settings (REQUIRED)
    SenderEmail = "admin@yourcompany.com"  # Must be a valid Microsoft 365 user account
    
    # Active Directory Domains Configuration (REQUIRED)
    # Each domain needs: Name, KeyVaultName, and CredentialSecretName
    ADDomains = @(
        @{
            Name = "contoso.com"
            KeyVaultName = "kv-contoso-prod"
            CredentialSecretName = "ad-admin-contoso"
        },
        @{
            Name = "fabrikam.com"
            KeyVaultName = "kv-fabrikam-prod"
            CredentialSecretName = "ad-admin-fabrikam"
        }
        # Add more domains as needed
    )
    
    # Exclusion Settings (OPTIONAL)
    ExcludeGroups = @(
        "Domain Admins",
        "Enterprise Admins",
        "Service Accounts",
        "Exempt from Disable"
    )
    
    ExcludeOUs = @(
        "OU=Service Accounts,DC=contoso,DC=com",
        "OU=System Accounts,DC=contoso,DC=com",
        "OU=Service Accounts,DC=fabrikam,DC=com",
        "OU=System Accounts,DC=fabrikam,DC=com"
    )
    
    # Exclude users based on a specific property
    ExcludeUserProperty = "Department"
    ExcludeUserPropertyValue = "IT"
    
    # Test Mode (set to $true for testing, $false for production)
    TestMode = $true
}

# Example usage:
# .\Disable-InactiveUsers.ps1 @Config

# IMPORTANT: Key Vault Secret Format
# Store credentials in Azure Key Vault secrets using this format:
# Secret Value: "username|password"
# Example: "CONTOSO\svc-ad-admin|P@ssw0rd123"
