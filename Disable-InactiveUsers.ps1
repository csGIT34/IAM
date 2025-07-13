#Requires -Modules Microsoft.Graph, ActiveDirectory, Az.Storage, Az.Accounts, Az.KeyVault

<#
.SYNOPSIS
    Disables inactive user accounts in Active Directory and Entra ID after 90 days of inactivity.

.DESCRIPTION
    This script checks for user accounts that haven't logged in for 90 days and disables them.
    It sends email notifications 2 weeks, 1 week, and 3 days before disabling accounts via Microsoft Graph.
    User account details are logged to an Azure Storage Table.
    Supports exclusions based on AD groups, user properties, or OUs.

.PARAMETER DaysInactive
    Number of days of inactivity before account is disabled (default: 90)

.PARAMETER NotificationDays
    Array of days before disable date to send notifications (default: 14, 7, 3)

.PARAMETER ExcludeGroups
    Array of AD group names to exclude from processing

.PARAMETER ExcludeOUs
    Array of AD organizational units to exclude from processing

.PARAMETER ExcludeUserProperty
    AD user property to check for exclusion (e.g., "Department")

.PARAMETER ExcludeUserPropertyValue
    Value of the user property that excludes the user

.PARAMETER StorageAccountName
    Azure Storage Account name for logging

.PARAMETER StorageAccountKey
    Azure Storage Account access key

.PARAMETER TableName
    Azure Storage Table name (default: "InactiveUsers")

.PARAMETER SenderEmail
    Email address to send notifications from (must be a valid Microsoft 365 user)

.PARAMETER ADDomains
    Array of hashtables containing domain information (Name, KeyVaultName, CredentialSecretName)

.PARAMETER TestMode
    Run in test mode (no actual changes made)

.EXAMPLE
    .\Disable-InactiveUsers.ps1 -DaysInactive 90 -StorageAccountName "mystorageaccount" -StorageAccountKey "key123" -SenderEmail "admin@company.com" -ADDomains @(@{Name="contoso.com"; KeyVaultName="kv-contoso"; CredentialSecretName="ad-admin-contoso"}, @{Name="fabrikam.com"; KeyVaultName="kv-fabrikam"; CredentialSecretName="ad-admin-fabrikam"})
#>

param(
    [int]$DaysInactive = 90,
    [int[]]$NotificationDays = @(14, 7, 3),
    [string[]]$ExcludeGroups = @(),
    [string[]]$ExcludeOUs = @(),
    [string]$ExcludeUserProperty = "",
    [string]$ExcludeUserPropertyValue = "",
    [Parameter(Mandatory = $true)]
    [string]$StorageAccountName,
    [Parameter(Mandatory = $true)]
    [string]$StorageAccountKey,
    [string]$TableName = "InactiveUsers",
    [Parameter(Mandatory = $true)]
    [string]$SenderEmail,
    [Parameter(Mandatory = $true)]
    [array]$ADDomains,
    [switch]$TestMode
)

# Import required modules
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    Import-Module Microsoft.Graph.Users -ErrorAction Stop
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
    Import-Module Microsoft.Graph.Mail -ErrorAction Stop
    Import-Module Microsoft.Graph.Reports -ErrorAction Stop
    Import-Module Az.Storage -ErrorAction Stop
    Import-Module Az.Accounts -ErrorAction Stop
    Import-Module Az.KeyVault -ErrorAction Stop
}
catch {
    Write-Error "Required modules not installed. Please install: ActiveDirectory, Microsoft.Graph.Users, Microsoft.Graph.Authentication, Microsoft.Graph.Mail, Microsoft.Graph.Reports, Az.Storage, Az.Accounts, Az.KeyVault"
    exit 1
}

# Initialize logging
$LogFile = "DisableInactiveUsers_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    Write-Host $logEntry
    Add-Content -Path $LogFile -Value $logEntry
}

# Connect to Azure Storage
function Initialize-AzureStorage {
    try {
        $storageContext = New-AzStorageContext -StorageAccountName $StorageAccountName -StorageAccountKey $StorageAccountKey
        $table = Get-AzStorageTable -Name $TableName -Context $storageContext -ErrorAction SilentlyContinue
        
        if (-not $table) {
            Write-Log "Creating Azure Storage Table: $TableName"
            $table = New-AzStorageTable -Name $TableName -Context $storageContext
        }
        
        return $table.CloudTable
    }
    catch {
        Write-Log "Failed to initialize Azure Storage: $($_.Exception.Message)" -Level "ERROR"
        throw
    }
}

# Connect to Microsoft Graph
function Connect-MicrosoftGraph {
    try {
        Write-Log "Connecting to Microsoft Graph..."
        # Connect with required scopes
        $scopes = @(
            "User.ReadWrite.All",
            "AuditLog.Read.All", 
            "Mail.Send",
            "Directory.Read.All"
        )
        Connect-MgGraph -Scopes $scopes -ErrorAction Stop
        Write-Log "Successfully connected to Microsoft Graph"
    }
    catch {
        Write-Log "Failed to connect to Microsoft Graph: $($_.Exception.Message)" -Level "ERROR"
        throw
    }
}

# Get credentials from Azure Key Vault
function Get-KeyVaultCredential {
    param(
        [string]$KeyVaultName,
        [string]$SecretName
    )
    
    try {
        Write-Log "Retrieving credentials from Key Vault: $KeyVaultName, Secret: $SecretName"
        
        # Get the secret from Key Vault
        $secret = Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $SecretName -AsPlainText
        
        if (-not $secret) {
            throw "Secret '$SecretName' not found in Key Vault '$KeyVaultName'"
        }
        
        # Expected format: username|password
        $parts = $secret -split '\|'
        if ($parts.Length -ne 2) {
            throw "Invalid secret format. Expected: username|password"
        }
        
        $username = $parts[0]
        $password = $parts[1] | ConvertTo-SecureString -AsPlainText -Force
        
        $credential = New-Object System.Management.Automation.PSCredential($username, $password)
        
        Write-Log "Successfully retrieved credentials for user: $username"
        return $credential
    }
    catch {
        Write-Log "Failed to retrieve credentials from Key Vault: $($_.Exception.Message)" -Level "ERROR"
        throw
    }
}

# Connect to Active Directory domain with specific credentials
function Connect-ADDomain {
    param(
        [string]$DomainName,
        [System.Management.Automation.PSCredential]$Credential
    )
    
    try {
        Write-Log "Connecting to Active Directory domain: $DomainName"
        
        # Test the connection
        $testConnection = Get-ADDomain -Identity $DomainName -Credential $Credential -ErrorAction Stop
        
        Write-Log "Successfully connected to domain: $DomainName"
        return $true
    }
    catch {
        Write-Log "Failed to connect to domain $DomainName : $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

# Check if user should be excluded
function Test-UserExclusion {
    param(
        [Microsoft.ActiveDirectory.Management.ADUser]$User,
        [string[]]$ExcludeGroups,
        [string[]]$ExcludeOUs,
        [string]$ExcludeUserProperty,
        [string]$ExcludeUserPropertyValue
    )
    
    # Check OU exclusions
    if ($ExcludeOUs.Count -gt 0) {
        foreach ($ou in $ExcludeOUs) {
            if ($User.DistinguishedName -like "*$ou*") {
                Write-Log "User $($User.SamAccountName) excluded due to OU: $ou"
                return $true
            }
        }
    }
    
    # Check group exclusions
    if ($ExcludeGroups.Count -gt 0) {
        $userGroups = Get-ADPrincipalGroupMembership -Identity $User.SamAccountName | Select-Object -ExpandProperty Name
        foreach ($group in $ExcludeGroups) {
            if ($userGroups -contains $group) {
                Write-Log "User $($User.SamAccountName) excluded due to group membership: $group"
                return $true
            }
        }
    }
    
    # Check user property exclusions
    if ($ExcludeUserProperty -and $ExcludeUserPropertyValue) {
        $propertyValue = $User.$ExcludeUserProperty
        if ($propertyValue -eq $ExcludeUserPropertyValue) {
            Write-Log "User $($User.SamAccountName) excluded due to property $ExcludeUserProperty = $ExcludeUserPropertyValue"
            return $true
        }
    }
    
    return $false
}

# Log user to Azure Storage Table
function Add-UserToStorageTable {
    param(
        [object]$CloudTable,
        [object]$User,
        [string]$AccountType,
        [string]$Action,
        [datetime]$LastLogon
    )
    
    try {
        $partitionKey = $AccountType
        $rowKey = "$($User.UserPrincipalName)_$(Get-Date -Format 'yyyyMMddHHmmss')"
        
        $entity = @{
            PartitionKey = $partitionKey
            RowKey = $rowKey
            UserPrincipalName = $User.UserPrincipalName
            DisplayName = $User.DisplayName
            SamAccountName = if ($User.SamAccountName) { $User.SamAccountName } else { "N/A" }
            AccountType = $AccountType
            LastLogon = $LastLogon.ToString("yyyy-MM-dd HH:mm:ss")
            Action = $Action
            ProcessedDate = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            DaysInactive = [math]::Round((New-TimeSpan -Start $LastLogon -End (Get-Date)).TotalDays)
        }
        
        $result = Add-AzTableRow -Table $CloudTable -PartitionKey $partitionKey -RowKey $rowKey -Property $entity
        Write-Log "User $($User.UserPrincipalName) logged to Azure Storage Table"
    }
    catch {
        Write-Log "Failed to log user to Azure Storage Table: $($_.Exception.Message)" -Level "ERROR"
    }
}

# Send email notification using Microsoft Graph
function Send-EmailNotification {
    param(
        [string]$To,
        [string]$UserName,
        [int]$DaysUntilDisable,
        [string]$AccountType
    )
    
    try {
        $subject = "Account Inactivity Warning - $DaysUntilDisable days until disabled"
        $body = @"
Dear $UserName,

This is an automated notification regarding your $AccountType account inactivity.

Your account has been inactive for an extended period. If no login activity is detected, your account will be automatically disabled in $DaysUntilDisable days.

To prevent your account from being disabled, please log in to your account within the next $DaysUntilDisable days.

If you believe this is an error or have any questions, please contact your IT administrator.

Best regards,
IT Security Team
"@
        
        if (-not $TestMode) {
            # Create the email message
            $message = @{
                subject = $subject
                body = @{
                    contentType = "Text"
                    content = $body
                }
                toRecipients = @(
                    @{
                        emailAddress = @{
                            address = $To
                        }
                    }
                )
            }
            
            # Send the email using Microsoft Graph
            Send-MgUserMail -UserId $SenderEmail -Message $message
            Write-Log "Email notification sent to $To ($DaysUntilDisable days warning)"
        }
        else {
            Write-Log "TEST MODE: Would send email to $To ($DaysUntilDisable days warning)"
        }
    }
    catch {
        Write-Log "Failed to send email to $To : $($_.Exception.Message)" -Level "ERROR"
    }
}

# Process Active Directory users across multiple domains
function Process-ADUsers {
    param([object]$CloudTable)
    
    Write-Log "Processing Active Directory users across multiple domains..."
    
    $cutoffDate = (Get-Date).AddDays(-$DaysInactive)
    
    # Note: Using LastLogonTimestamp instead of LastLogonDate for better accuracy
    # LastLogonTimestamp is replicated across all domain controllers, while LastLogonDate
    # only reflects the last logon on the specific DC being queried
    
    foreach ($domainConfig in $ADDomains) {
        $domainName = $domainConfig.Name
        $keyVaultName = $domainConfig.KeyVaultName
        $credentialSecretName = $domainConfig.CredentialSecretName
        
        Write-Log "Processing domain: $domainName"
        
        try {
            # Get credentials for this domain from Key Vault
            $credential = Get-KeyVaultCredential -KeyVaultName $keyVaultName -SecretName $credentialSecretName
            
            # Test connection to domain
            if (-not (Connect-ADDomain -DomainName $domainName -Credential $credential)) {
                Write-Log "Skipping domain $domainName due to connection failure" -Level "WARNING"
                continue
            }
            
            # Get users from this domain
            $adUsers = Get-ADUser -Filter {Enabled -eq $true} -Properties LastLogonTimestamp, EmailAddress, Department, Title, Manager -Server $domainName -Credential $credential
            
            Write-Log "Found $($adUsers.Count) enabled users in domain: $domainName"
            
            foreach ($user in $adUsers) {
                # Skip if user should be excluded
                if (Test-UserExclusion -User $user -ExcludeGroups $ExcludeGroups -ExcludeOUs $ExcludeOUs -ExcludeUserProperty $ExcludeUserProperty -ExcludeUserPropertyValue $ExcludeUserPropertyValue) {
                    continue
                }
                
                # Use LastLogonTimestamp for more accurate inactivity detection
                $lastLogon = if ($user.LastLogonTimestamp) {
                    [DateTime]::FromFileTime($user.LastLogonTimestamp)
                } else {
                    (Get-Date).AddDays(-365) # Assume very old if no logon timestamp
                }
                
                if ($lastLogon -lt $cutoffDate) {
                    $daysInactive = [math]::Round((New-TimeSpan -Start $lastLogon -End (Get-Date)).TotalDays)
                    $daysUntilDisable = $DaysInactive - $daysInactive
                    
                    # Check if we should send notifications
                    if ($NotificationDays -contains $daysUntilDisable -and $user.EmailAddress) {
                        Send-EmailNotification -To $user.EmailAddress -UserName $user.DisplayName -DaysUntilDisable $daysUntilDisable -AccountType "Active Directory ($domainName)"
                    }
                    
                    # Disable account if past due date
                    if ($daysUntilDisable -le 0) {
                        try {
                            if (-not $TestMode) {
                                Disable-ADAccount -Identity $user.SamAccountName -Server $domainName -Credential $credential
                                Write-Log "Disabled AD account: $($user.SamAccountName) in domain $domainName (inactive for $daysInactive days)"
                                
                                # Create user object with domain info for logging
                                $userWithDomain = $user.PSObject.Copy()
                                $userWithDomain | Add-Member -MemberType NoteProperty -Name "Domain" -Value $domainName
                                Add-UserToStorageTable -CloudTable $CloudTable -User $userWithDomain -AccountType "ActiveDirectory-$domainName" -Action "Disabled" -LastLogon $lastLogon
                            }
                            else {
                                Write-Log "TEST MODE: Would disable AD account: $($user.SamAccountName) in domain $domainName (inactive for $daysInactive days)"
                                
                                # Create user object with domain info for logging
                                $userWithDomain = $user.PSObject.Copy()
                                $userWithDomain | Add-Member -MemberType NoteProperty -Name "Domain" -Value $domainName
                                Add-UserToStorageTable -CloudTable $CloudTable -User $userWithDomain -AccountType "ActiveDirectory-$domainName" -Action "TEST-WouldDisable" -LastLogon $lastLogon
                            }
                        }
                        catch {
                            Write-Log "Failed to disable AD account $($user.SamAccountName) in domain $domainName : $($_.Exception.Message)" -Level "ERROR"
                        }
                    }
                }
            }
            
            Write-Log "Completed processing domain: $domainName"
        }
        catch {
            Write-Log "Error processing domain $domainName : $($_.Exception.Message)" -Level "ERROR"
            continue
        }
    }
}

# Process Entra ID cloud users
function Process-EntraCloudUsers {
    param([object]$CloudTable)
    
    Write-Log "Processing Entra ID cloud users..."
    
    $cutoffDate = (Get-Date).AddDays(-$DaysInactive)
    
    try {
        # Get only cloud-only users (not hybrid/synced from AD)
        $entraUsers = Get-MgUser -All -Filter "userType eq 'Member' and accountEnabled eq true" -Property "Id,UserPrincipalName,DisplayName,Mail,UserType,AccountEnabled,CreatedDateTime,OnPremisesSyncEnabled,OnPremisesImmutableId"
        
        foreach ($user in $entraUsers) {
            # Skip hybrid/synced accounts - only process cloud-only accounts
            if ($user.OnPremisesSyncEnabled -eq $true -or $user.OnPremisesImmutableId) {
                Write-Log "Skipping hybrid/synced user: $($user.UserPrincipalName)"
                continue
            }
            
            # Get sign-in activity using Microsoft Graph
            try {
                $signInLogs = Get-MgAuditLogSignIn -Filter "userId eq '$($user.Id)'" -Top 1 -Sort "createdDateTime desc"
                
                $lastLogon = if ($signInLogs) { 
                    [datetime]$signInLogs[0].CreatedDateTime
                } else { 
                    (Get-Date).AddDays(-365) # Assume very old if no sign-in logs
                }
                
                if ($lastLogon -lt $cutoffDate) {
                    $daysInactive = [math]::Round((New-TimeSpan -Start $lastLogon -End (Get-Date)).TotalDays)
                    $daysUntilDisable = $DaysInactive - $daysInactive
                    
                    # Check if we should send notifications
                    if ($NotificationDays -contains $daysUntilDisable -and $user.Mail) {
                        Send-EmailNotification -To $user.Mail -UserName $user.DisplayName -DaysUntilDisable $daysUntilDisable -AccountType "Entra ID Cloud"
                    }
                    
                    # Disable account if past due date
                    if ($daysUntilDisable -le 0) {
                        try {
                            if (-not $TestMode) {
                                Update-MgUser -UserId $user.Id -AccountEnabled:$false
                                Write-Log "Disabled Entra cloud account: $($user.UserPrincipalName) (inactive for $daysInactive days)"
                                Add-UserToStorageTable -CloudTable $CloudTable -User $user -AccountType "EntraCloud" -Action "Disabled" -LastLogon $lastLogon
                            }
                            else {
                                Write-Log "TEST MODE: Would disable Entra cloud account: $($user.UserPrincipalName) (inactive for $daysInactive days)"
                                Add-UserToStorageTable -CloudTable $CloudTable -User $user -AccountType "EntraCloud" -Action "TEST-WouldDisable" -LastLogon $lastLogon
                            }
                        }
                        catch {
                            Write-Log "Failed to disable Entra cloud account $($user.UserPrincipalName): $($_.Exception.Message)" -Level "ERROR"
                        }
                    }
                }
            }
            catch {
                Write-Log "Error getting sign-in activity for $($user.UserPrincipalName): $($_.Exception.Message)" -Level "WARNING"
            }
        }
    }
    catch {
        Write-Log "Error processing Entra cloud users: $($_.Exception.Message)" -Level "ERROR"
    }
}

# Process Entra ID guest users
function Process-EntraGuestUsers {
    param([object]$CloudTable)
    
    Write-Log "Processing Entra ID guest users..."
    
    $cutoffDate = (Get-Date).AddDays(-$DaysInactive)
    
    try {
        # Get only cloud-only guest users (not hybrid/synced from AD)
        $guestUsers = Get-MgUser -All -Filter "userType eq 'Guest' and accountEnabled eq true" -Property "Id,UserPrincipalName,DisplayName,Mail,UserType,AccountEnabled,CreatedDateTime,OnPremisesSyncEnabled,OnPremisesImmutableId"
        
        foreach ($user in $guestUsers) {
            # Skip hybrid/synced accounts - only process cloud-only accounts
            if ($user.OnPremisesSyncEnabled -eq $true -or $user.OnPremisesImmutableId) {
                Write-Log "Skipping hybrid/synced guest user: $($user.UserPrincipalName)"
                continue
            }
            
            # Get sign-in activity using Microsoft Graph
            try {
                $signInLogs = Get-MgAuditLogSignIn -Filter "userId eq '$($user.Id)'" -Top 1 -Sort "createdDateTime desc"
                
                $lastLogon = if ($signInLogs) { 
                    [datetime]$signInLogs[0].CreatedDateTime
                } else { 
                    (Get-Date).AddDays(-365) # Assume very old if no sign-in logs
                }
                
                if ($lastLogon -lt $cutoffDate) {
                    $daysInactive = [math]::Round((New-TimeSpan -Start $lastLogon -End (Get-Date)).TotalDays)
                    $daysUntilDisable = $DaysInactive - $daysInactive
                    
                    # Check if we should send notifications
                    if ($NotificationDays -contains $daysUntilDisable -and $user.Mail) {
                        Send-EmailNotification -To $user.Mail -UserName $user.DisplayName -DaysUntilDisable $daysUntilDisable -AccountType "Entra ID Guest"
                    }
                    
                    # Disable account if past due date
                    if ($daysUntilDisable -le 0) {
                        try {
                            if (-not $TestMode) {
                                Update-MgUser -UserId $user.Id -AccountEnabled:$false
                                Write-Log "Disabled Entra guest account: $($user.UserPrincipalName) (inactive for $daysInactive days)"
                                Add-UserToStorageTable -CloudTable $CloudTable -User $user -AccountType "EntraGuest" -Action "Disabled" -LastLogon $lastLogon
                            }
                            else {
                                Write-Log "TEST MODE: Would disable Entra guest account: $($user.UserPrincipalName) (inactive for $daysInactive days)"
                                Add-UserToStorageTable -CloudTable $CloudTable -User $user -AccountType "EntraGuest" -Action "TEST-WouldDisable" -LastLogon $lastLogon
                            }
                        }
                        catch {
                            Write-Log "Failed to disable Entra guest account $($user.UserPrincipalName): $($_.Exception.Message)" -Level "ERROR"
                        }
                    }
                }
            }
            catch {
                Write-Log "Error getting sign-in activity for guest $($user.UserPrincipalName): $($_.Exception.Message)" -Level "WARNING"
            }
        }
    }
    catch {
        Write-Log "Error processing Entra guest users: $($_.Exception.Message)" -Level "ERROR"
    }
}

# Main execution
try {
    Write-Log "Starting Inactive User Disable Process"
    Write-Log "Parameters: DaysInactive=$DaysInactive, NotificationDays=$($NotificationDays -join ','), TestMode=$TestMode"
    
    # Validate domain configuration
    Write-Log "Validating domain configuration..."
    foreach ($domainConfig in $ADDomains) {
        if (-not $domainConfig.Name -or -not $domainConfig.KeyVaultName -or -not $domainConfig.CredentialSecretName) {
            throw "Invalid domain configuration. Each domain must have Name, KeyVaultName, and CredentialSecretName properties."
        }
        Write-Log "Domain configured: $($domainConfig.Name) -> KeyVault: $($domainConfig.KeyVaultName), Secret: $($domainConfig.CredentialSecretName)"
    }
    
    # Initialize Azure Storage
    $cloudTable = Initialize-AzureStorage
    
    # Connect to Microsoft Graph
    Connect-MicrosoftGraph
    
    # Process different types of users
    Process-ADUsers -CloudTable $cloudTable
    Process-EntraCloudUsers -CloudTable $cloudTable
    Process-EntraGuestUsers -CloudTable $cloudTable
    
    Write-Log "Inactive User Disable Process completed successfully"
}
catch {
    Write-Log "Fatal error in main execution: $($_.Exception.Message)" -Level "ERROR"
    exit 1
}
finally {
    # Disconnect from Microsoft Graph
    try {
        Disconnect-MgGraph -ErrorAction SilentlyContinue
        Write-Log "Disconnected from Microsoft Graph"
    }
    catch {
        # Ignore disconnect errors
    }
}
