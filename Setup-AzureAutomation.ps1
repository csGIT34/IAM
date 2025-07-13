# Azure Automation Setup Script
# This script helps configure Azure Automation Account for the Disable Inactive Users runbook

<#
.SYNOPSIS
    Sets up Azure Automation Account for the Disable Inactive Users runbook.

.DESCRIPTION
    This script configures the Azure Automation Account with the necessary:
    - Variables for configuration
    - Credentials for domain access
    - Managed identity permissions
    - PowerShell modules
    - Schedules for automatic execution

.PARAMETER SubscriptionId
    Azure subscription ID where the Automation Account is located

.PARAMETER ResourceGroupName
    Resource group name containing the Automation Account

.PARAMETER AutomationAccountName
    Name of the Azure Automation Account

.PARAMETER StorageAccountName
    Name of the Azure Storage Account for logging

.PARAMETER StorageAccountKey
    Access key for the Azure Storage Account

.PARAMETER SenderEmail
    Email address to send notifications from (must be a valid Microsoft 365 user)

.PARAMETER DomainCredentials
    Hashtable of domain credentials in format: @{DomainName = @{Username = ""; Password = ""}}

.PARAMETER ExcludeGroups
    Comma-separated list of AD groups to exclude from processing

.PARAMETER ExcludeOUs
    Comma-separated list of AD OUs to exclude from processing

.PARAMETER ExcludeUserProperty
    AD user property to check for exclusion (e.g., "Department")

.PARAMETER ExcludeUserPropertyValue
    Value of the user property that excludes the user

.PARAMETER DomainControllers
    Comma-separated list of domain controllers to use

.PARAMETER CreateSchedule
    Whether to create a schedule for automatic execution

.PARAMETER ScheduleFrequency
    Schedule frequency (Daily, Weekly, Monthly)

.PARAMETER ScheduleTime
    Time to run the schedule (24-hour format, e.g., "02:00")

.EXAMPLE
    $domainCreds = @{
        "contoso.com" = @{Username = "CONTOSO\svc-automation"; Password = "P@ssw0rd123"}
        "fabrikam.com" = @{Username = "FABRIKAM\svc-automation"; Password = "P@ssw0rd456"}
    }
    
    .\Setup-AzureAutomation.ps1 -SubscriptionId "12345678-1234-1234-1234-123456789012" -ResourceGroupName "rg-automation" -AutomationAccountName "aa-iam" -StorageAccountName "saiamlogging" -StorageAccountKey "key123" -SenderEmail "admin@contoso.com" -DomainCredentials $domainCreds -CreateSchedule -ScheduleFrequency "Daily" -ScheduleTime "02:00"
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
    
    [Parameter(Mandatory = $true)]
    [string]$StorageAccountKey,
    
    [Parameter(Mandatory = $true)]
    [string]$SenderEmail,
    
    [Parameter(Mandatory = $true)]
    [hashtable]$DomainCredentials,
    
    [string]$ExcludeGroups = "",
    [string]$ExcludeOUs = "",
    [string]$ExcludeUserProperty = "",
    [string]$ExcludeUserPropertyValue = "",
    [string]$DomainControllers = "",
    [string]$TableName = "InactiveUsers",
    [string]$HybridWorkerGroup = "",
    
    [switch]$CreateSchedule,
    [string]$ScheduleFrequency = "Daily",
    [string]$ScheduleTime = "02:00"
)

# Import required modules
try {
    Import-Module Az.Accounts -ErrorAction Stop
    Import-Module Az.Automation -ErrorAction Stop
    Import-Module Az.Resources -ErrorAction Stop
    Import-Module Az.Storage -ErrorAction Stop
}
catch {
    Write-Error "Required modules not installed. Please install: Az.Accounts, Az.Automation, Az.Resources, Az.Storage"
    exit 1
}

# Connect to Azure
Write-Host "Connecting to Azure..." -ForegroundColor Green
try {
    Connect-AzAccount -SubscriptionId $SubscriptionId -ErrorAction Stop
    Write-Host "Successfully connected to Azure subscription: $SubscriptionId" -ForegroundColor Green
}
catch {
    Write-Error "Failed to connect to Azure: $($_.Exception.Message)"
    exit 1
}

# Verify Automation Account exists
Write-Host "Verifying Automation Account..." -ForegroundColor Green
try {
    $automationAccount = Get-AzAutomationAccount -ResourceGroupName $ResourceGroupName -Name $AutomationAccountName -ErrorAction Stop
    Write-Host "Found Automation Account: $($automationAccount.AutomationAccountName)" -ForegroundColor Green
}
catch {
    Write-Error "Automation Account '$AutomationAccountName' not found in resource group '$ResourceGroupName'"
    exit 1
}

# Function to set automation variable
function Set-AutomationVariable {
    param(
        [string]$Name,
        [string]$Value,
        [string]$Description
    )
    
    try {
        $existingVar = Get-AzAutomationVariable -AutomationAccountName $AutomationAccountName -ResourceGroupName $ResourceGroupName -Name $Name -ErrorAction SilentlyContinue
        
        if ($existingVar) {
            Set-AzAutomationVariable -AutomationAccountName $AutomationAccountName -ResourceGroupName $ResourceGroupName -Name $Name -Value $Value -Encrypted $false
            Write-Host "Updated automation variable: $Name" -ForegroundColor Yellow
        }
        else {
            New-AzAutomationVariable -AutomationAccountName $AutomationAccountName -ResourceGroupName $ResourceGroupName -Name $Name -Value $Value -Description $Description -Encrypted $false
            Write-Host "Created automation variable: $Name" -ForegroundColor Green
        }
    }
    catch {
        Write-Error "Failed to set automation variable '$Name': $($_.Exception.Message)"
    }
}

# Function to set automation credential
function Set-AutomationCredential {
    param(
        [string]$Name,
        [string]$Username,
        [securestring]$Password,
        [string]$Description
    )
    
    try {
        $credential = New-Object System.Management.Automation.PSCredential($Username, $Password)
        
        $existingCred = Get-AzAutomationCredential -AutomationAccountName $AutomationAccountName -ResourceGroupName $ResourceGroupName -Name $Name -ErrorAction SilentlyContinue
        
        if ($existingCred) {
            Set-AzAutomationCredential -AutomationAccountName $AutomationAccountName -ResourceGroupName $ResourceGroupName -Name $Name -Value $credential
            Write-Host "Updated automation credential: $Name" -ForegroundColor Yellow
        }
        else {
            New-AzAutomationCredential -AutomationAccountName $AutomationAccountName -ResourceGroupName $ResourceGroupName -Name $Name -Value $credential -Description $Description
            Write-Host "Created automation credential: $Name" -ForegroundColor Green
        }
    }
    catch {
        Write-Error "Failed to set automation credential '$Name': $($_.Exception.Message)"
    }
}

# Set automation variables
Write-Host "`nConfiguring automation variables..." -ForegroundColor Green

Set-AutomationVariable -Name "StorageAccountName" -Value $StorageAccountName -Description "Azure Storage Account name for logging"
Set-AutomationVariable -Name "StorageAccountKey" -Value $StorageAccountKey -Description "Azure Storage Account access key"
Set-AutomationVariable -Name "SenderEmail" -Value $SenderEmail -Description "Email address to send notifications from"
Set-AutomationVariable -Name "TableName" -Value $TableName -Description "Azure Storage Table name for logging"

if ($ExcludeGroups) {
    Set-AutomationVariable -Name "ExcludeGroups" -Value $ExcludeGroups -Description "Comma-separated list of AD groups to exclude"
}

if ($ExcludeOUs) {
    Set-AutomationVariable -Name "ExcludeOUs" -Value $ExcludeOUs -Description "Comma-separated list of AD OUs to exclude"
}

if ($ExcludeUserProperty) {
    Set-AutomationVariable -Name "ExcludeUserProperty" -Value $ExcludeUserProperty -Description "AD user property to check for exclusion"
}

if ($ExcludeUserPropertyValue) {
    Set-AutomationVariable -Name "ExcludeUserPropertyValue" -Value $ExcludeUserPropertyValue -Description "Value that excludes the user"
}

if ($DomainControllers) {
    Set-AutomationVariable -Name "DomainControllers" -Value $DomainControllers -Description "Comma-separated list of domain controllers"
}

if ($HybridWorkerGroup) {
    Set-AutomationVariable -Name "HybridWorkerGroup" -Value $HybridWorkerGroup -Description "Hybrid Worker Group name for AD connectivity"
}

# Set domain credentials
Write-Host "`nConfiguring domain credentials..." -ForegroundColor Green

foreach ($domain in $DomainCredentials.Keys) {
    $credName = "AD-$($domain.ToUpper())"
    $username = $DomainCredentials[$domain].Username
    $password = ConvertTo-SecureString $DomainCredentials[$domain].Password -AsPlainText -Force
    
    Set-AutomationCredential -Name $credName -Username $username -Password $password -Description "Domain credentials for $domain"
}

# Install required PowerShell modules
Write-Host "`nInstalling required PowerShell modules..." -ForegroundColor Green

$requiredModules = @(
    "Microsoft.Graph.Authentication",
    "Microsoft.Graph.Users",
    "Microsoft.Graph.Mail", 
    "Microsoft.Graph.Reports",
    "Az.Accounts",
    "Az.Storage",
    "Az.KeyVault",
    "ActiveDirectory",
    "AzTable"
)

foreach ($module in $requiredModules) {
    try {
        Write-Host "Installing module: $module" -ForegroundColor Yellow
        
        $existingModule = Get-AzAutomationModule -AutomationAccountName $AutomationAccountName -ResourceGroupName $ResourceGroupName -Name $module -ErrorAction SilentlyContinue
        
        if ($existingModule) {
            Write-Host "Module $module already exists" -ForegroundColor Yellow
        }
        else {
            New-AzAutomationModule -AutomationAccountName $AutomationAccountName -ResourceGroupName $ResourceGroupName -Name $module -ModuleUri "https://www.powershellgallery.com/packages/$module"
            Write-Host "Module $module installation initiated" -ForegroundColor Green
        }
    }
    catch {
        Write-Warning "Failed to install module $module : $($_.Exception.Message)"
    }
}

# Create the runbook
Write-Host "`nCreating runbook..." -ForegroundColor Green

$runbookName = "DisableInactiveUsers"
$runbookPath = Join-Path $PSScriptRoot "AzureAutomation-DisableInactiveUsers.ps1"

if (-not (Test-Path $runbookPath)) {
    Write-Error "Runbook file not found: $runbookPath"
    exit 1
}

try {
    # Import the runbook
    $existingRunbook = Get-AzAutomationRunbook -AutomationAccountName $AutomationAccountName -ResourceGroupName $ResourceGroupName -Name $runbookName -ErrorAction SilentlyContinue
    
    if ($existingRunbook) {
        Write-Host "Updating existing runbook: $runbookName" -ForegroundColor Yellow
        Set-AzAutomationRunbookDefinition -AutomationAccountName $AutomationAccountName -ResourceGroupName $ResourceGroupName -Name $runbookName -Path $runbookPath -Overwrite
    }
    else {
        Write-Host "Creating new runbook: $runbookName" -ForegroundColor Green
        Import-AzAutomationRunbook -AutomationAccountName $AutomationAccountName -ResourceGroupName $ResourceGroupName -Name $runbookName -Type PowerShell -Path $runbookPath
    }
    
    # Publish the runbook
    Publish-AzAutomationRunbook -AutomationAccountName $AutomationAccountName -ResourceGroupName $ResourceGroupName -Name $runbookName
    Write-Host "Runbook published successfully" -ForegroundColor Green
}
catch {
    Write-Error "Failed to create/update runbook: $($_.Exception.Message)"
}

# Create schedule if requested
if ($CreateSchedule) {
    Write-Host "`nCreating schedule..." -ForegroundColor Green
    
    $scheduleName = "DisableInactiveUsers-$ScheduleFrequency"
    
    try {
        $startTime = (Get-Date).Date.AddDays(1).AddHours([int]$ScheduleTime.Split(':')[0]).AddMinutes([int]$ScheduleTime.Split(':')[1])
        
        $existingSchedule = Get-AzAutomationSchedule -AutomationAccountName $AutomationAccountName -ResourceGroupName $ResourceGroupName -Name $scheduleName -ErrorAction SilentlyContinue
        
        if ($existingSchedule) {
            Write-Host "Schedule already exists: $scheduleName" -ForegroundColor Yellow
        }
        else {
            switch ($ScheduleFrequency) {
                "Daily" {
                    $null = New-AzAutomationSchedule -AutomationAccountName $AutomationAccountName -ResourceGroupName $ResourceGroupName -Name $scheduleName -StartTime $startTime -DayInterval 1
                }
                "Weekly" {
                    $null = New-AzAutomationSchedule -AutomationAccountName $AutomationAccountName -ResourceGroupName $ResourceGroupName -Name $scheduleName -StartTime $startTime -WeekInterval 1
                }
                "Monthly" {
                    $null = New-AzAutomationSchedule -AutomationAccountName $AutomationAccountName -ResourceGroupName $ResourceGroupName -Name $scheduleName -StartTime $startTime -MonthInterval 1
                }
            }
            
            Write-Host "Created schedule: $scheduleName" -ForegroundColor Green
            
            # Link schedule to runbook
            if ($HybridWorkerGroup) {
                Register-AzAutomationScheduledRunbook -AutomationAccountName $AutomationAccountName -ResourceGroupName $ResourceGroupName -RunbookName $runbookName -ScheduleName $scheduleName -RunOn $HybridWorkerGroup
                Write-Host "Linked schedule to runbook with Hybrid Worker Group: $HybridWorkerGroup" -ForegroundColor Green
            } else {
                Register-AzAutomationScheduledRunbook -AutomationAccountName $AutomationAccountName -ResourceGroupName $ResourceGroupName -RunbookName $runbookName -ScheduleName $scheduleName
                Write-Host "Linked schedule to runbook" -ForegroundColor Green
                Write-Warning "No Hybrid Worker Group specified - runbook will run in Azure sandbox without AD connectivity"
            }
        }
    }
    catch {
        Write-Error "Failed to create schedule: $($_.Exception.Message)"
    }
}

# Configure managed identity permissions
Write-Host "`nConfiguring managed identity permissions..." -ForegroundColor Green

$managedIdentityObjectId = $automationAccount.Identity.PrincipalId

if ($managedIdentityObjectId) {
    Write-Host "Automation Account Managed Identity Object ID: $managedIdentityObjectId" -ForegroundColor Green
    
    Write-Host "`nRequired permissions to configure manually:" -ForegroundColor Yellow
    Write-Host "1. Microsoft Graph API permissions:" -ForegroundColor Yellow
    Write-Host "   - User.ReadWrite.All" -ForegroundColor Yellow
    Write-Host "   - Mail.Send" -ForegroundColor Yellow
    Write-Host "   - AuditLog.Read.All" -ForegroundColor Yellow
    Write-Host "   - Directory.Read.All" -ForegroundColor Yellow
    Write-Host "`n2. Azure Storage permissions:" -ForegroundColor Yellow
    Write-Host "   - Storage Table Data Contributor on the storage account" -ForegroundColor Yellow
    Write-Host "`n3. Azure Key Vault permissions (if using Key Vault):" -ForegroundColor Yellow
    Write-Host "   - Key Vault Secrets User" -ForegroundColor Yellow
    
    Write-Host "`nUse the following commands to configure Graph API permissions:" -ForegroundColor Cyan
    Write-Host "# Connect to Microsoft Graph PowerShell" -ForegroundColor Gray
    Write-Host "Connect-MgGraph -Scopes 'Application.ReadWrite.All', 'AppRoleAssignment.ReadWrite.All'" -ForegroundColor Gray
    Write-Host "" -ForegroundColor Gray
    Write-Host "# Get the managed identity service principal" -ForegroundColor Gray
    Write-Host "`$managedIdentity = Get-MgServicePrincipal -Filter `"objectId eq '$managedIdentityObjectId'`"" -ForegroundColor Gray
    Write-Host "" -ForegroundColor Gray
    Write-Host "# Get Microsoft Graph service principal" -ForegroundColor Gray
    Write-Host "`$graphApp = Get-MgServicePrincipal -Filter `"appId eq '00000003-0000-0000-c000-000000000000'`"" -ForegroundColor Gray
    Write-Host "" -ForegroundColor Gray
    Write-Host "# Assign required permissions" -ForegroundColor Gray
    Write-Host "`$permissions = @('User.ReadWrite.All', 'Mail.Send', 'AuditLog.Read.All', 'Directory.Read.All')" -ForegroundColor Gray
    Write-Host "foreach (`$permission in `$permissions) {" -ForegroundColor Gray
    Write-Host "    `$appRole = `$graphApp.AppRoles | Where-Object { `$_.Value -eq `$permission }" -ForegroundColor Gray
    Write-Host "    New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId `$managedIdentity.Id -PrincipalId `$managedIdentity.Id -ResourceId `$graphApp.Id -AppRoleId `$appRole.Id" -ForegroundColor Gray
    Write-Host "}" -ForegroundColor Gray
}
else {
    Write-Warning "Managed identity not found. Please enable system-assigned managed identity on the Automation Account."
}

Write-Host "`n=== SETUP COMPLETED ===" -ForegroundColor Green
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "1. Set up Hybrid Runbook Worker for Active Directory connectivity" -ForegroundColor Yellow
Write-Host "2. Wait for PowerShell modules to finish installing (check Automation Account > Modules)" -ForegroundColor Yellow
Write-Host "3. Configure managed identity permissions as shown above" -ForegroundColor Yellow
Write-Host "4. Test the runbook with TestMode=`$true on the Hybrid Worker" -ForegroundColor Yellow
Write-Host "5. Review the logs in Azure Storage Table" -ForegroundColor Yellow
Write-Host "6. Set TestMode=`$false in production" -ForegroundColor Yellow

# Hybrid Worker setup instructions
Write-Host "`n=== HYBRID WORKER SETUP ===" -ForegroundColor Green
Write-Host "To set up a Hybrid Runbook Worker for Active Directory connectivity:" -ForegroundColor Yellow
Write-Host "1. Install Azure Connected Machine agent on a domain-joined server" -ForegroundColor Yellow
Write-Host "2. Install the Hybrid Runbook Worker extension" -ForegroundColor Yellow
Write-Host "3. Ensure the server has:" -ForegroundColor Yellow
Write-Host "   - PowerShell 5.1 or later" -ForegroundColor Yellow
Write-Host "   - ActiveDirectory PowerShell module" -ForegroundColor Yellow
Write-Host "   - Network connectivity to domain controllers" -ForegroundColor Yellow
Write-Host "   - Network connectivity to Azure (port 443)" -ForegroundColor Yellow
Write-Host "4. Create a Hybrid Worker Group and add the worker" -ForegroundColor Yellow
Write-Host "5. Update the HybridWorkerGroup variable in Automation Account" -ForegroundColor Yellow

# Test runbook execution
Write-Host "`nTo test the runbook, run:" -ForegroundColor Cyan
if ($HybridWorkerGroup) {
    Write-Host "Start-AzAutomationRunbook -AutomationAccountName '$AutomationAccountName' -ResourceGroupName '$ResourceGroupName' -Name '$runbookName' -RunOn '$HybridWorkerGroup' -Parameters @{TestMode=`$true; DaysInactive=90}" -ForegroundColor Gray
} else {
    Write-Host "Start-AzAutomationRunbook -AutomationAccountName '$AutomationAccountName' -ResourceGroupName '$ResourceGroupName' -Name '$runbookName' -Parameters @{TestMode=`$true; DaysInactive=90}" -ForegroundColor Gray
    Write-Host "WARNING: No Hybrid Worker Group specified - add -RunOn parameter for AD connectivity" -ForegroundColor Red
}
