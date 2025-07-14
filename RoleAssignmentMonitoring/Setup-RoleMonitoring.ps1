# Azure Automation Setup Script for Role Assignment Monitoring
# This script helps configure Azure Automation Account for the Role Assignment Monitoring runbook

<#
.SYNOPSIS
    Sets up Azure Automation Account for the Role Assignment Monitoring runbook.

.DESCRIPTION
    This script configures the Azure Automation Account with the necessary:
    - Variables for configuration
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

.PARAMETER AlertEmail
    Email address to send alerts to

.PARAMETER MonitoredSubscriptions
    Comma-separated list of subscription IDs to monitor (optional)

.PARAMETER ExcludedRoles
    Comma-separated list of roles to exclude from monitoring

.PARAMETER CreateSchedule
    Whether to create a schedule for automatic execution

.PARAMETER ScheduleFrequency
    Schedule frequency (Daily, Weekly, Monthly)

.PARAMETER ScheduleTime
    Time to run the schedule (24-hour format, e.g., "02:00")

.EXAMPLE
    .\Setup-RoleMonitoring.ps1 -SubscriptionId "12345678-1234-1234-1234-123456789012" -ResourceGroupName "rg-automation" -AutomationAccountName "aa-iam" -StorageAccountName "saiamlogging" -StorageAccountKey "key123" -AlertEmail "admin@contoso.com" -CreateSchedule -ScheduleFrequency "Daily" -ScheduleTime "02:00"
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
    [string]$AlertEmail,
    
    [string]$MonitoredSubscriptions = "",
    [string]$ExcludedRoles = "Reader,Security Reader",
    [string]$TableName = "RoleAssignments",
    
    [switch]$CreateSchedule,
    [ValidateSet("Daily", "Weekly", "Monthly")]
    [string]$ScheduleFrequency = "Daily",
    [string]$ScheduleTime = "02:00"
)

Write-Host "=== Azure Automation Setup for Role Assignment Monitoring ===" -ForegroundColor Green
Write-Host "Subscription ID: $SubscriptionId" -ForegroundColor Cyan
Write-Host "Resource Group: $ResourceGroupName" -ForegroundColor Cyan
Write-Host "Automation Account: $AutomationAccountName" -ForegroundColor Cyan
Write-Host "Storage Account: $StorageAccountName" -ForegroundColor Cyan

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
    
    # Verify automation account exists
    Write-Host "Verifying Automation Account exists..." -ForegroundColor Yellow
    $automationAccount = Get-AzAutomationAccount -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName
    if (-not $automationAccount) {
        throw "Automation Account '$AutomationAccountName' not found in resource group '$ResourceGroupName'"
    }
    
    Write-Host "✓ Automation Account verified" -ForegroundColor Green
    
    # Create Azure Automation Variables
    Write-Host "Creating Azure Automation variables..." -ForegroundColor Yellow
    
    $variables = @{
        "StorageAccountName" = $StorageAccountName
        "StorageAccountKey" = $StorageAccountKey
        "AlertEmail" = $AlertEmail
        "TableName" = $TableName
    }
    
    # Add optional variables if provided
    if ($MonitoredSubscriptions) {
        $variables["MonitoredSubscriptions"] = $MonitoredSubscriptions
    }
    
    if ($ExcludedRoles) {
        $variables["ExcludedRoles"] = $ExcludedRoles
    }
    
    foreach ($variable in $variables.GetEnumerator()) {
        try {
            Write-Host "Creating variable: $($variable.Key)" -ForegroundColor Cyan
            New-AzAutomationVariable -AutomationAccountName $AutomationAccountName -ResourceGroupName $ResourceGroupName -Name $variable.Key -Value $variable.Value -Encrypted $false
            Write-Host "✓ Variable '$($variable.Key)' created successfully" -ForegroundColor Green
        } catch {
            if ($_.Exception.Message -like "*already exists*") {
                Write-Host "Variable '$($variable.Key)' already exists, updating..." -ForegroundColor Yellow
                Set-AzAutomationVariable -AutomationAccountName $AutomationAccountName -ResourceGroupName $ResourceGroupName -Name $variable.Key -Value $variable.Value
                Write-Host "✓ Variable '$($variable.Key)' updated successfully" -ForegroundColor Green
            } else {
                Write-Warning "Failed to create variable '$($variable.Key)': $($_.Exception.Message)"
            }
        }
    }
    
    # Install required PowerShell modules
    Write-Host "Installing required PowerShell modules..." -ForegroundColor Yellow
    
    $requiredModules = @(
        "Microsoft.Graph.Authentication",
        "Microsoft.Graph.Users",
        "Microsoft.Graph.DirectoryObjects", 
        "Microsoft.Graph.Identity.DirectoryManagement",
        "Az.Accounts",
        "Az.Resources",
        "Az.Storage",
        "AzTable"
    )
    
    foreach ($module in $requiredModules) {
        Write-Host "Installing module: $module" -ForegroundColor Cyan
        try {
            Import-AzAutomationModule -AutomationAccountName $AutomationAccountName -ResourceGroupName $ResourceGroupName -Name $module -ModuleVersion "Latest"
            Write-Host "✓ Module '$module' installation initiated" -ForegroundColor Green
        } catch {
            Write-Warning "Failed to install module '$module': $($_.Exception.Message)"
        }
    }
    
    # Wait for module installation
    Write-Host "Waiting for modules to install (this may take several minutes)..." -ForegroundColor Yellow
    $moduleInstallationComplete = $false
    $maxWaitTime = 30 # minutes
    $waitTime = 0
    
    while (-not $moduleInstallationComplete -and $waitTime -lt $maxWaitTime) {
        Start-Sleep -Seconds 60
        $waitTime++
        
        $installingModules = @()
        foreach ($module in $requiredModules) {
            $moduleStatus = Get-AzAutomationModule -AutomationAccountName $AutomationAccountName -ResourceGroupName $ResourceGroupName -Name $module -ErrorAction SilentlyContinue
            if ($moduleStatus -and $moduleStatus.ImportState -eq "Installing") {
                $installingModules += $module
            }
        }
        
        if ($installingModules.Count -eq 0) {
            $moduleInstallationComplete = $true
            Write-Host "✓ All modules installed successfully" -ForegroundColor Green
        } else {
            Write-Host "Still installing modules: $($installingModules -join ', ') (waited $waitTime minutes)" -ForegroundColor Yellow
        }
    }
    
    if (-not $moduleInstallationComplete) {
        Write-Warning "Module installation is taking longer than expected. You may need to wait before running the runbook."
    }
    
    # Import the runbook
    Write-Host "Importing runbook..." -ForegroundColor Yellow
    $runbookPath = Join-Path $PSScriptRoot "AzureAutomation-RoleMonitoring.ps1"
    
    if (Test-Path $runbookPath) {
        try {
            Import-AzAutomationRunbook -AutomationAccountName $AutomationAccountName -ResourceGroupName $ResourceGroupName -Name "RoleAssignmentMonitoring" -Type "PowerShell" -Path $runbookPath
            Write-Host "✓ Runbook imported successfully" -ForegroundColor Green
            
            # Publish the runbook
            Write-Host "Publishing runbook..." -ForegroundColor Yellow
            Publish-AzAutomationRunbook -AutomationAccountName $AutomationAccountName -ResourceGroupName $ResourceGroupName -Name "RoleAssignmentMonitoring"
            Write-Host "✓ Runbook published successfully" -ForegroundColor Green
        } catch {
            Write-Warning "Failed to import/publish runbook: $($_.Exception.Message)"
        }
    } else {
        Write-Warning "Runbook file not found at: $runbookPath"
    }
    
    # Create schedule if requested
    if ($CreateSchedule) {
        Write-Host "Creating schedule..." -ForegroundColor Yellow
        
        $scheduleName = "RoleAssignmentMonitoring-Schedule"
        $timeComponents = $ScheduleTime.Split(':')
        $startTime = (Get-Date).Date.AddHours([int]$timeComponents[0]).AddMinutes([int]$timeComponents[1]).AddDays(1)
        
        try {
            # Create the schedule
            New-AzAutomationSchedule -AutomationAccountName $AutomationAccountName -ResourceGroupName $ResourceGroupName -Name $scheduleName -StartTime $startTime -DayInterval 1
            Write-Host "✓ Schedule created: $scheduleName" -ForegroundColor Green
            
            # Link runbook to schedule
            Register-AzAutomationScheduledRunbook -AutomationAccountName $AutomationAccountName -ResourceGroupName $ResourceGroupName -RunbookName "RoleAssignmentMonitoring" -ScheduleName $scheduleName
            Write-Host "✓ Runbook linked to schedule" -ForegroundColor Green
        } catch {
            Write-Warning "Failed to create schedule: $($_.Exception.Message)"
        }
    }
    
    # Get managed identity information
    Write-Host "Getting managed identity information..." -ForegroundColor Yellow
    $managedIdentity = Get-AzAutomationAccount -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName
    $managedIdentityId = $managedIdentity.Identity.PrincipalId
    
    if ($managedIdentityId) {
        Write-Host "✓ Managed Identity ID: $managedIdentityId" -ForegroundColor Green
    } else {
        Write-Warning "Managed Identity not found. Please ensure it's enabled for the Automation Account."
    }
    
    Write-Host "`n=== Setup Complete ===" -ForegroundColor Green
    Write-Host "Next steps:" -ForegroundColor Yellow
    Write-Host "1. Grant the managed identity the following permissions:" -ForegroundColor Cyan
    Write-Host "   - Microsoft Graph API: Directory.Read.All, RoleManagement.Read.All" -ForegroundColor Cyan
    Write-Host "   - Azure RBAC: Reader role at subscription level" -ForegroundColor Cyan
    Write-Host "   - Storage Account: Storage Table Data Contributor" -ForegroundColor Cyan
    Write-Host "2. Test the runbook manually before enabling the schedule" -ForegroundColor Cyan
    Write-Host "3. Monitor the execution logs for any issues" -ForegroundColor Cyan
    
    if ($managedIdentityId) {
        Write-Host "`nTo grant Microsoft Graph permissions, run these commands:" -ForegroundColor Yellow
        Write-Host "Connect-MgGraph -Scopes 'Application.ReadWrite.All', 'AppRoleAssignment.ReadWrite.All'" -ForegroundColor Cyan
        Write-Host "`$managedIdentity = Get-MgServicePrincipal -Filter `"objectId eq '$managedIdentityId'`"" -ForegroundColor Cyan
        Write-Host "`$graphApp = Get-MgServicePrincipal -Filter `"appId eq '00000003-0000-0000-c000-000000000000'`"" -ForegroundColor Cyan
        Write-Host "`$permissions = @('Directory.Read.All', 'RoleManagement.Read.All')" -ForegroundColor Cyan
        Write-Host "foreach (`$permission in `$permissions) {" -ForegroundColor Cyan
        Write-Host "    `$appRole = `$graphApp.AppRoles | Where-Object { `$_.Value -eq `$permission }" -ForegroundColor Cyan
        Write-Host "    New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId `$managedIdentity.Id -PrincipalId `$managedIdentity.Id -ResourceId `$graphApp.Id -AppRoleId `$appRole.Id" -ForegroundColor Cyan
        Write-Host "}" -ForegroundColor Cyan
    }
    
} catch {
    Write-Error "Setup failed: $($_.Exception.Message)"
    Write-Error "Stack Trace: $($_.ScriptStackTrace)"
    exit 1
}
