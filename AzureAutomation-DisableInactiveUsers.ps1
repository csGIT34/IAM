#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Users, Microsoft.Graph.Mail, Microsoft.Graph.Reports, Az.Storage, Az.Accounts, Az.KeyVault, ActiveDirectory

<#
.SYNOPSIS
    Azure Automation Runbook to disable inactive user accounts in Active Directory and Entra ID.

.DESCRIPTION
    This runbook checks for user accounts that haven't logged in for a specified period and disables them.
    It sends email notifications before disabling accounts via Microsoft Graph.
    User account details are logged to an Azure Storage Table.
    Supports exclusions based on AD groups, user properties, or OUs.
    
    Designed to run in Azure Automation with managed identity authentication.

.PARAMETER DaysInactive
    Number of days of inactivity before account is disabled (default: 90)

.PARAMETER NotificationDays
    Array of days before disable date to send notifications (default: 14, 7, 3)

.PARAMETER TestMode
    Run in test mode (no actual changes made)

.NOTES
    This runbook requires the following Azure Automation variables:
    - StorageAccountName
    - StorageAccountKey
    - SenderEmail
    - ExcludeGroups (optional)
    - ExcludeOUs (optional)
    - ExcludeUserProperty (optional)
    - ExcludeUserPropertyValue (optional)
    - TableName (optional, defaults to "InactiveUsers")
    
    Domain credentials should be stored in Azure Automation credentials with names:
    - AD-<DomainName> (e.g., AD-CONTOSO, AD-FABRIKAM)
    
    The managed identity must have appropriate permissions for:
    - Microsoft Graph API (User.ReadWrite.All, Mail.Send, AuditLog.Read.All, Directory.Read.All)
    - Azure Storage (Storage Table Data Contributor)
    - Azure Key Vault (Key Vault Secrets User) - if using Key Vault for domain credentials

.EXAMPLE
    Start-AzAutomationRunbook -AutomationAccountName "MyAutomationAccount" -ResourceGroupName "MyResourceGroup" -Name "DisableInactiveUsers" -Parameters @{DaysInactive=90; TestMode=$true}
#>

param(
    [int]$DaysInactive = 90,
    [int[]]$NotificationDays = @(14, 7, 3),
    [switch]$TestMode
)

# Initialize logging for Azure Automation
function Write-AutomationLog {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    Write-Output $logEntry
    if ($Level -eq "ERROR") {
        Write-Error $logEntry
    } elseif ($Level -eq "WARNING") {
        Write-Warning $logEntry
    }
}

# Get Azure Automation variables
function Get-AutomationVariable {
    param([string]$Name, [string]$DefaultValue = "")
    try {
        $value = Get-AutomationVariable -Name $Name -ErrorAction SilentlyContinue
        if ([string]::IsNullOrEmpty($value)) {
            if ([string]::IsNullOrEmpty($DefaultValue)) {
                throw "Required automation variable '$Name' not found"
            }
            return $DefaultValue
        }
        return $value
    }
    catch {
        if ([string]::IsNullOrEmpty($DefaultValue)) {
            Write-AutomationLog "Failed to get automation variable '$Name': $($_.Exception.Message)" -Level "ERROR"
            throw
        }
        return $DefaultValue
    }
}

# Get configuration from Azure Automation variables
try {
    Write-AutomationLog "Loading configuration from Azure Automation variables..."
    
    $StorageAccountName = Get-AutomationVariable -Name "StorageAccountName"
    $StorageAccountKey = Get-AutomationVariable -Name "StorageAccountKey"
    $SenderEmail = Get-AutomationVariable -Name "SenderEmail"
    $TableName = Get-AutomationVariable -Name "TableName" -DefaultValue "InactiveUsers"
    
    # Optional exclusion settings
    $ExcludeGroupsString = Get-AutomationVariable -Name "ExcludeGroups" -DefaultValue ""
    $ExcludeOUsString = Get-AutomationVariable -Name "ExcludeOUs" -DefaultValue ""
    $ExcludeUserProperty = Get-AutomationVariable -Name "ExcludeUserProperty" -DefaultValue ""
    $ExcludeUserPropertyValue = Get-AutomationVariable -Name "ExcludeUserPropertyValue" -DefaultValue ""
    
    # Parse comma-separated strings into arrays
    $ExcludeGroups = if ($ExcludeGroupsString) { $ExcludeGroupsString -split ',' | ForEach-Object { $_.Trim() } } else { @() }
    $ExcludeOUs = if ($ExcludeOUsString) { $ExcludeOUsString -split ',' | ForEach-Object { $_.Trim() } } else { @() }
    
    Write-AutomationLog "Configuration loaded successfully"
}
catch {
    Write-AutomationLog "Failed to load configuration: $($_.Exception.Message)" -Level "ERROR"
    throw
}

# Connect to Azure using managed identity
try {
    Write-AutomationLog "Connecting to Azure using managed identity..."
    $null = Connect-AzAccount -Identity -ErrorAction Stop
    Write-AutomationLog "Successfully connected to Azure"
}
catch {
    Write-AutomationLog "Failed to connect to Azure: $($_.Exception.Message)" -Level "ERROR"
    throw
}

# Connect to Azure Storage
function Initialize-AzureStorage {
    try {
        Write-AutomationLog "Initializing Azure Storage connection..."
        $storageContext = New-AzStorageContext -StorageAccountName $StorageAccountName -StorageAccountKey $StorageAccountKey
        $table = Get-AzStorageTable -Name $TableName -Context $storageContext -ErrorAction SilentlyContinue
        
        if (-not $table) {
            Write-AutomationLog "Creating Azure Storage Table: $TableName"
            $table = New-AzStorageTable -Name $TableName -Context $storageContext
        }
        
        Write-AutomationLog "Azure Storage initialized successfully"
        return $table.CloudTable
    }
    catch {
        Write-AutomationLog "Failed to initialize Azure Storage: $($_.Exception.Message)" -Level "ERROR"
        throw
    }
}

# Connect to Microsoft Graph using managed identity
function Connect-MicrosoftGraph {
    try {
        Write-AutomationLog "Connecting to Microsoft Graph using managed identity..."
        
        # Connect with managed identity
        $null = Connect-MgGraph -Identity -ErrorAction Stop
        
        Write-AutomationLog "Successfully connected to Microsoft Graph"
    }
    catch {
        Write-AutomationLog "Failed to connect to Microsoft Graph: $($_.Exception.Message)" -Level "ERROR"
        throw
    }
}

# Get domain credentials from Azure Automation
function Get-DomainCredential {
    param([string]$DomainName)
    
    try {
        $credentialName = "AD-$($DomainName.ToUpper())"
        Write-AutomationLog "Retrieving domain credentials for: $credentialName"
        
        $credential = Get-AutomationPSCredential -Name $credentialName -ErrorAction Stop
        
        if (-not $credential) {
            throw "Credential '$credentialName' not found in Azure Automation"
        }
        
        Write-AutomationLog "Successfully retrieved credentials for domain: $DomainName"
        return $credential
    }
    catch {
        Write-AutomationLog "Failed to retrieve domain credentials: $($_.Exception.Message)" -Level "ERROR"
        throw
    }
}

# Get available domain controllers from Azure Automation variables
function Get-DomainControllers {
    try {
        $domainControllersString = Get-AutomationVariable -Name "DomainControllers" -DefaultValue ""
        if ([string]::IsNullOrEmpty($domainControllersString)) {
            Write-AutomationLog "No domain controllers specified in variables, using automatic discovery"
            return @()
        }
        
        $domainControllers = $domainControllersString -split ',' | ForEach-Object { $_.Trim() }
        Write-AutomationLog "Found domain controllers: $($domainControllers -join ', ')"
        return $domainControllers
    }
    catch {
        Write-AutomationLog "Failed to get domain controllers: $($_.Exception.Message)" -Level "WARNING"
        return @()
    }
}

# Connect to Active Directory domain
function Connect-ADDomain {
    param(
        [string]$DomainName,
        [System.Management.Automation.PSCredential]$Credential,
        [string]$Server = ""
    )
    
    try {
        Write-AutomationLog "Connecting to Active Directory domain: $DomainName"
        
        $connectParams = @{
            Identity = $DomainName
            Credential = $Credential
            ErrorAction = "Stop"
        }
        
        if ($Server) {
            $connectParams.Server = $Server
        }
        
        $null = Get-ADDomain @connectParams
        
        Write-AutomationLog "Successfully connected to domain: $DomainName"
        return $true
    }
    catch {
        Write-AutomationLog "Failed to connect to domain $DomainName : $($_.Exception.Message)" -Level "ERROR"
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
        [string]$ExcludeUserPropertyValue,
        [System.Management.Automation.PSCredential]$Credential
    )
    
    # Check OU exclusions
    if ($ExcludeOUs.Count -gt 0) {
        foreach ($ou in $ExcludeOUs) {
            if ($User.DistinguishedName -like "*$ou*") {
                Write-AutomationLog "User $($User.SamAccountName) excluded due to OU: $ou"
                return $true
            }
        }
    }
    
    # Check group exclusions
    if ($ExcludeGroups.Count -gt 0) {
        try {
            $userGroups = Get-ADPrincipalGroupMembership -Identity $User.SamAccountName -Credential $Credential | Select-Object -ExpandProperty Name
            foreach ($group in $ExcludeGroups) {
                if ($userGroups -contains $group) {
                    Write-AutomationLog "User $($User.SamAccountName) excluded due to group membership: $group"
                    return $true
                }
            }
        }
        catch {
            Write-AutomationLog "Failed to check group membership for user $($User.SamAccountName): $($_.Exception.Message)" -Level "WARNING"
        }
    }
    
    # Check user property exclusions
    if ($ExcludeUserProperty -and $ExcludeUserPropertyValue) {
        $propertyValue = $User.$ExcludeUserProperty
        if ($propertyValue -eq $ExcludeUserPropertyValue) {
            Write-AutomationLog "User $($User.SamAccountName) excluded due to property $ExcludeUserProperty = $ExcludeUserPropertyValue"
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
        
        $null = Add-AzTableRow -Table $CloudTable -PartitionKey $partitionKey -RowKey $rowKey -Property $entity
        Write-AutomationLog "User $($User.UserPrincipalName) logged to Azure Storage Table"
    }
    catch {
        Write-AutomationLog "Failed to log user to Azure Storage Table: $($_.Exception.Message)" -Level "ERROR"
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
            $params = @{
                Message = @{
                    Subject = $subject
                    Body = @{
                        ContentType = "Text"
                        Content = $body
                    }
                    ToRecipients = @(
                        @{
                            EmailAddress = @{
                                Address = $To
                            }
                        }
                    )
                }
                SaveToSentItems = $false
            }
            
            Send-MgUserMail -UserId $SenderEmail -BodyParameter $params
            Write-AutomationLog "Email notification sent to $To"
        } else {
            Write-AutomationLog "TEST MODE: Would send email to $To with subject: $subject"
        }
    }
    catch {
        Write-AutomationLog "Failed to send email notification to $To : $($_.Exception.Message)" -Level "ERROR"
    }
}

# Main execution
try {
    Write-AutomationLog "Starting Disable Inactive Users runbook..."
    Write-AutomationLog "Parameters: DaysInactive=$DaysInactive, NotificationDays=$($NotificationDays -join ','), TestMode=$TestMode"
    
    # Initialize Azure Storage
    $cloudTable = Initialize-AzureStorage
    
    # Connect to Microsoft Graph
    Connect-MicrosoftGraph
    
    # Get domain controllers from configuration
    $domainControllers = Get-DomainControllers
    
    # Process domains automatically discovered or from configuration
    $domains = @()
    if ($domainControllers.Count -gt 0) {
        foreach ($dc in $domainControllers) {
            $domainName = $dc.Split('.')[1..($dc.Split('.').Length-1)] -join '.'
            if ($domainName -and $domainName -notin $domains) {
                $domains += $domainName
            }
        }
    } else {
        # Try to discover domains from automation credentials
        $allCredentials = Get-AutomationPSCredential | Where-Object { $_.Name -like "AD-*" }
        foreach ($cred in $allCredentials) {
            $domainName = $cred.Name.Substring(3).ToLower()
            $domains += $domainName
        }
    }
    
    Write-AutomationLog "Processing domains: $($domains -join ', ')"
    
    # Calculate threshold dates
    $inactiveThreshold = (Get-Date).AddDays(-$DaysInactive)
    Write-AutomationLog "Inactive threshold date: $inactiveThreshold"
    
    $totalProcessed = 0
    $totalDisabled = 0
    $totalNotified = 0
    
    # Process each domain
    foreach ($domain in $domains) {
        Write-AutomationLog "Processing domain: $domain"
        
        try {
            # Get domain credentials
            $domainCredential = Get-DomainCredential -DomainName $domain
            
            # Find appropriate domain controller
            $server = ""
            if ($domainControllers.Count -gt 0) {
                $server = $domainControllers | Where-Object { $_ -like "*$domain*" } | Select-Object -First 1
            }
            
            # Connect to domain
            if (-not (Connect-ADDomain -DomainName $domain -Credential $domainCredential -Server $server)) {
                Write-AutomationLog "Skipping domain $domain due to connection failure" -Level "WARNING"
                continue
            }
            
            # Get inactive users from AD
            $adParams = @{
                Filter = { Enabled -eq $true -and LastLogonTimestamp -lt $inactiveThreshold }
                Properties = @("LastLogonTimestamp", "DisplayName", "EmailAddress", "Department", "MemberOf")
                Credential = $domainCredential
            }
            
            if ($server) {
                $adParams.Server = $server
            }
            
            $inactiveUsers = Get-ADUser @adParams
            
            Write-AutomationLog "Found $($inactiveUsers.Count) inactive users in domain $domain"
            
            foreach ($user in $inactiveUsers) {
                $totalProcessed++
                
                # Check exclusions
                if (Test-UserExclusion -User $user -ExcludeGroups $ExcludeGroups -ExcludeOUs $ExcludeOUs -ExcludeUserProperty $ExcludeUserProperty -ExcludeUserPropertyValue $ExcludeUserPropertyValue -Credential $domainCredential) {
                    continue
                }
                
                # Calculate days since last logon
                $lastLogon = if ($user.LastLogonTimestamp) { [DateTime]::FromFileTime($user.LastLogonTimestamp) } else { (Get-Date).AddDays(-365) }
                $daysSinceLogon = [math]::Round((New-TimeSpan -Start $lastLogon -End (Get-Date)).TotalDays)
                
                # Check if user should be disabled
                if ($daysSinceLogon -ge $DaysInactive) {
                    Write-AutomationLog "Disabling user: $($user.SamAccountName) (inactive for $daysSinceLogon days)"
                    
                    if (-not $TestMode) {
                        try {
                            $disableParams = @{
                                Identity = $user.SamAccountName
                                Credential = $domainCredential
                                ErrorAction = "Stop"
                            }
                            
                            if ($server) {
                                $disableParams.Server = $server
                            }
                            
                            Disable-ADAccount @disableParams
                            $totalDisabled++
                            
                            # Log to storage table
                            Add-UserToStorageTable -CloudTable $cloudTable -User $user -AccountType "ActiveDirectory" -Action "Disabled" -LastLogon $lastLogon
                        }
                        catch {
                            Write-AutomationLog "Failed to disable user $($user.SamAccountName): $($_.Exception.Message)" -Level "ERROR"
                        }
                    } else {
                        Write-AutomationLog "TEST MODE: Would disable user $($user.SamAccountName)"
                        Add-UserToStorageTable -CloudTable $cloudTable -User $user -AccountType "ActiveDirectory" -Action "TEST-Disabled" -LastLogon $lastLogon
                    }
                    
                    # Send email notification if user has email
                    if ($user.EmailAddress) {
                        Send-EmailNotification -To $user.EmailAddress -UserName $user.DisplayName -DaysUntilDisable 0 -AccountType "Active Directory"
                    }
                }
                else {
                    # Check for notification thresholds
                    $daysUntilDisable = $DaysInactive - $daysSinceLogon
                    
                    if ($daysUntilDisable -in $NotificationDays) {
                        Write-AutomationLog "Sending notification to user: $($user.SamAccountName) ($daysUntilDisable days until disable)"
                        
                        if ($user.EmailAddress) {
                            Send-EmailNotification -To $user.EmailAddress -UserName $user.DisplayName -DaysUntilDisable $daysUntilDisable -AccountType "Active Directory"
                            $totalNotified++
                            
                            # Log to storage table
                            Add-UserToStorageTable -CloudTable $cloudTable -User $user -AccountType "ActiveDirectory" -Action "Notified-$daysUntilDisable" -LastLogon $lastLogon
                        }
                    }
                }
            }
        }
        catch {
            Write-AutomationLog "Error processing domain $domain : $($_.Exception.Message)" -Level "ERROR"
        }
    }
    
    # Process Entra ID users
    Write-AutomationLog "Processing Entra ID users..."
    
    try {
        # Get cloud-only users (not synced from AD)
        $entraUsers = Get-MgUser -Filter "accountEnabled eq true and userType eq 'Member'" -Property "id,userPrincipalName,displayName,mail,onPremisesSyncEnabled,signInActivity,createdDateTime" -All
        
        # Filter to cloud-only users
        $cloudUsers = $entraUsers | Where-Object { $_.onPremisesSyncEnabled -ne $true }
        
        Write-AutomationLog "Found $($cloudUsers.Count) cloud-only Entra ID users"
        
        foreach ($user in $cloudUsers) {
            $totalProcessed++
            
            # Get last sign-in date
            $lastSignIn = if ($user.signInActivity -and $user.signInActivity.lastSignInDateTime) {
                [DateTime]::Parse($user.signInActivity.lastSignInDateTime)
            } else {
                # Use creation date if no sign-in activity
                [DateTime]::Parse($user.createdDateTime)
            }
            
            $daysSinceSignIn = [math]::Round((New-TimeSpan -Start $lastSignIn -End (Get-Date)).TotalDays)
            
            # Check if user should be disabled
            if ($daysSinceSignIn -ge $DaysInactive) {
                Write-AutomationLog "Disabling Entra ID user: $($user.userPrincipalName) (inactive for $daysSinceSignIn days)"
                
                if (-not $TestMode) {
                    try {
                        Update-MgUser -UserId $user.id -AccountEnabled:$false
                        $totalDisabled++
                        
                        # Log to storage table
                        Add-UserToStorageTable -CloudTable $cloudTable -User $user -AccountType "EntraID" -Action "Disabled" -LastLogon $lastSignIn
                    }
                    catch {
                        Write-AutomationLog "Failed to disable Entra ID user $($user.userPrincipalName): $($_.Exception.Message)" -Level "ERROR"
                    }
                } else {
                    Write-AutomationLog "TEST MODE: Would disable Entra ID user $($user.userPrincipalName)"
                    Add-UserToStorageTable -CloudTable $cloudTable -User $user -AccountType "EntraID" -Action "TEST-Disabled" -LastLogon $lastSignIn
                }
                
                # Send email notification
                if ($user.mail) {
                    Send-EmailNotification -To $user.mail -UserName $user.displayName -DaysUntilDisable 0 -AccountType "Entra ID"
                }
            }
            else {
                # Check for notification thresholds
                $daysUntilDisable = $DaysInactive - $daysSinceSignIn
                
                if ($daysUntilDisable -in $NotificationDays) {
                    Write-AutomationLog "Sending notification to Entra ID user: $($user.userPrincipalName) ($daysUntilDisable days until disable)"
                    
                    if ($user.mail) {
                        Send-EmailNotification -To $user.mail -UserName $user.displayName -DaysUntilDisable $daysUntilDisable -AccountType "Entra ID"
                        $totalNotified++
                        
                        # Log to storage table
                        Add-UserToStorageTable -CloudTable $cloudTable -User $user -AccountType "EntraID" -Action "Notified-$daysUntilDisable" -LastLogon $lastSignIn
                    }
                }
            }
        }
    }
    catch {
        Write-AutomationLog "Error processing Entra ID users: $($_.Exception.Message)" -Level "ERROR"
    }
    
    # Summary
    Write-AutomationLog "Runbook execution completed successfully"
    Write-AutomationLog "Total users processed: $totalProcessed"
    Write-AutomationLog "Total users disabled: $totalDisabled"
    Write-AutomationLog "Total notifications sent: $totalNotified"
    
    if ($TestMode) {
        Write-AutomationLog "TEST MODE was enabled - no actual changes were made"
    }
    
    Write-Output "Execution Summary:"
    Write-Output "- Total users processed: $totalProcessed"
    Write-Output "- Total users disabled: $totalDisabled"
    Write-Output "- Total notifications sent: $totalNotified"
    Write-Output "- Test mode: $TestMode"
}
catch {
    Write-AutomationLog "Fatal error in runbook execution: $($_.Exception.Message)" -Level "ERROR"
    throw
}
finally {
    # Cleanup connections
    try {
        Disconnect-MgGraph -ErrorAction SilentlyContinue
        Write-AutomationLog "Disconnected from Microsoft Graph"
    }
    catch {
        Write-AutomationLog "Error disconnecting from Microsoft Graph: $($_.Exception.Message)" -Level "WARNING"
    }
}
