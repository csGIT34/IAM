# Script to create a scheduled task for the Disable-InactiveUsers script
# Run this script as Administrator to set up the scheduled task

param(
    [string]$ScriptPath = "C:\Users\Public\Documents\Disable-InactiveUsers.ps1",
    [string]$ConfigPath = "C:\Users\Public\Documents\Config-DisableInactiveUsers.ps1",
    [string]$TaskName = "Disable-InactiveUsers",
    [string]$TaskDescription = "Automatically disable inactive user accounts",
    [string]$RunTime = "02:00",  # 2:00 AM
    [string]$RunDay = "Daily"    # Daily, Weekly, Monthly
)

# Check if running as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script must be run as Administrator"
    exit 1
}

try {
    # Create the scheduled task action
    $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ExecutionPolicy Bypass -File `"$ScriptPath`" -ConfigFile `"$ConfigPath`""
    
    # Create the scheduled task trigger
    switch ($RunDay) {
        "Daily" { 
            $trigger = New-ScheduledTaskTrigger -Daily -At $RunTime
        }
        "Weekly" { 
            $trigger = New-ScheduledTaskTrigger -Weekly -At $RunTime -DaysOfWeek Monday
        }
        "Monthly" { 
            $trigger = New-ScheduledTaskTrigger -Weekly -At $RunTime -WeeksInterval 4
        }
        default { 
            $trigger = New-ScheduledTaskTrigger -Daily -At $RunTime
        }
    }
    
    # Create the scheduled task principal (run as SYSTEM)
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    
    # Create the scheduled task settings
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
    
    # Register the scheduled task
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description $TaskDescription
    
    Write-Host "Scheduled task '$TaskName' created successfully!" -ForegroundColor Green
    Write-Host "Task will run $RunDay at $RunTime" -ForegroundColor Green
    Write-Host "Script: $ScriptPath" -ForegroundColor Green
    Write-Host "Config: $ConfigPath" -ForegroundColor Green
    
    # Show the task
    Get-ScheduledTask -TaskName $TaskName | Select-Object TaskName, State, LastRunTime, NextRunTime
}
catch {
    Write-Error "Failed to create scheduled task: $($_.Exception.Message)"
    exit 1
}

# Instructions for manual configuration
Write-Host "`n=== IMPORTANT SETUP INSTRUCTIONS ===" -ForegroundColor Yellow
Write-Host "1. Edit the configuration file: $ConfigPath" -ForegroundColor Yellow
Write-Host "2. Update the following required settings:" -ForegroundColor Yellow
Write-Host "   - StorageAccountName: Your Azure Storage Account name" -ForegroundColor Yellow
Write-Host "   - StorageAccountKey: Your Azure Storage Account access key" -ForegroundColor Yellow
Write-Host "   - SenderEmail: Valid Microsoft 365 user email address" -ForegroundColor Yellow
Write-Host "3. Customize exclusion settings as needed" -ForegroundColor Yellow
Write-Host "4. Test the script first by setting TestMode = `$true" -ForegroundColor Yellow
Write-Host "5. Once tested, set TestMode = `$false for production" -ForegroundColor Yellow
