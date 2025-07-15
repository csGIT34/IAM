#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Installs prerequisites for MFA Registration Reporting solution
.DESCRIPTION
    This script installs and configures all necessary components for the MFA Registration Reporting solution,
    including PowerShell modules, permissions setup, and initial configuration.
.PARAMETER InstallModules
    Install required PowerShell modules
.PARAMETER ConfigurePermissions
    Configure necessary permissions for reporting
.PARAMETER CreateScheduledTask
    Create a scheduled task for automated reporting
.PARAMETER SetupConfiguration
    Create initial configuration files
.PARAMETER TestConnection
    Test connection to Microsoft Graph
.PARAMETER InstallPath
    Installation path for the solution
.PARAMETER TenantId
    Tenant ID for initial configuration
.EXAMPLE
    .\Install-Prerequisites.ps1
.EXAMPLE
    .\Install-Prerequisites.ps1 -CreateScheduledTask -TenantId "your-tenant-id"
.EXAMPLE
    .\Install-Prerequisites.ps1 -InstallPath "C:\MFAReporting" -SetupConfiguration
.NOTES
    Author: GitHub Copilot
    Version: 1.0
    Requires: PowerShell 5.1 or later, Administrator privileges
    Purpose: Install and configure MFA Registration Reporting prerequisites
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [switch]$InstallModules = $true,
    
    [Parameter(Mandatory = $false)]
    [switch]$ConfigurePermissions = $true,
    
    [Parameter(Mandatory = $false)]
    [switch]$CreateScheduledTask,
    
    [Parameter(Mandatory = $false)]
    [switch]$SetupConfiguration = $true,
    
    [Parameter(Mandatory = $false)]
    [switch]$TestConnection,
    
    [Parameter(Mandatory = $false)]
    [string]$InstallPath = "C:\MFAReporting",
    
    [Parameter(Mandatory = $false)]
    [string]$TenantId
)

# Initialize logging
$LogPath = ".\logs\Install-Prerequisites_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$null = New-Item -Path (Split-Path $LogPath -Parent) -ItemType Directory -Force -ErrorAction SilentlyContinue

function Write-Log {
    param([string]$Message, [string]$Level = 'Info')
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logEntry = "[$timestamp] [$Level] $Message"
    Add-Content -Path $LogPath -Value $logEntry
    
    switch ($Level) {
        'Error' { Write-Error $Message }
        'Warning' { Write-Warning $Message }
        'Info' { Write-Host $Message -ForegroundColor Green }
        'Debug' { Write-Debug $Message }
    }
}

function Test-Prerequisites {
    try {
        Write-Log "Checking prerequisites..."
        
        # Check PowerShell version
        $psVersion = $PSVersionTable.PSVersion
        Write-Log "PowerShell version: $($psVersion)"
        
        if ($psVersion.Major -lt 5) {
            throw "PowerShell 5.1 or later is required. Current version: $psVersion"
        }
        
        # Check if running as administrator
        $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        $isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        
        if (-not $isAdmin) {
            throw "This script must be run as Administrator"
        }
        
        # Check internet connectivity
        $internetConnection = Test-NetConnection -ComputerName "graph.microsoft.com" -Port 443 -InformationLevel Quiet -ErrorAction SilentlyContinue
        if (-not $internetConnection) {
            Write-Log "Warning: Unable to connect to Microsoft Graph. Check internet connectivity." -Level Warning
        }
        
        # Check execution policy
        $executionPolicy = Get-ExecutionPolicy
        Write-Log "Current execution policy: $executionPolicy"
        
        if ($executionPolicy -eq 'Restricted') {
            Write-Log "Setting execution policy to RemoteSigned for current user..."
            Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
        }
        
        Write-Log "Prerequisites check completed successfully"
        
    } catch {
        Write-Log "Prerequisites check failed: $($_.Exception.Message)" -Level Error
        throw
    }
}

function Install-RequiredModules {
    if (-not $InstallModules) {
        Write-Log "Skipping module installation as requested"
        return
    }
    
    try {
        Write-Log "Installing required PowerShell modules..."
        
        # Required modules for MFA reporting
        $requiredModules = @(
            @{
                Name = 'Microsoft.Graph.Authentication'
                MinVersion = '2.0.0'
                Description = 'Microsoft Graph Authentication module'
            },
            @{
                Name = 'Microsoft.Graph.Reports'
                MinVersion = '2.0.0'
                Description = 'Microsoft Graph Reports module'
            },
            @{
                Name = 'Microsoft.Graph.Users'
                MinVersion = '2.0.0'
                Description = 'Microsoft Graph Users module'
            },
            @{
                Name = 'Microsoft.Graph.Identity.SignIns'
                MinVersion = '2.0.0'
                Description = 'Microsoft Graph Identity SignIns module'
            },
            @{
                Name = 'ImportExcel'
                MinVersion = '7.0.0'
                Description = 'Excel import/export module'
            }
        )
        
        foreach ($module in $requiredModules) {
            Write-Log "Processing module: $($module.Name)"
            
            $existingModule = Get-Module -ListAvailable -Name $module.Name | Sort-Object Version -Descending | Select-Object -First 1
            
            if ($existingModule) {
                Write-Log "Module $($module.Name) version $($existingModule.Version) is already installed"
                
                # Check if update is needed
                try {
                    $latestVersion = Find-Module -Name $module.Name -ErrorAction SilentlyContinue
                    if ($latestVersion -and $latestVersion.Version -gt $existingModule.Version) {
                        Write-Log "Updating module $($module.Name) from $($existingModule.Version) to $($latestVersion.Version)"
                        Update-Module -Name $module.Name -Force
                    }
                } catch {
                    Write-Log "Failed to check for updates for $($module.Name): $($_.Exception.Message)" -Level Warning
                }
            } else {
                Write-Log "Installing module: $($module.Name)"
                try {
                    Install-Module -Name $module.Name -Scope AllUsers -Force -AllowClobber
                    Write-Log "Successfully installed module: $($module.Name)"
                } catch {
                    Write-Log "Failed to install module $($module.Name): $($_.Exception.Message)" -Level Warning
                    
                    # Try installing for current user if AllUsers fails
                    try {
                        Install-Module -Name $module.Name -Scope CurrentUser -Force -AllowClobber
                        Write-Log "Successfully installed module $($module.Name) for current user"
                    } catch {
                        Write-Log "Failed to install module $($module.Name) for current user: $($_.Exception.Message)" -Level Error
                    }
                }
            }
        }
        
        Write-Log "Module installation completed"
        
    } catch {
        Write-Log "Module installation failed: $($_.Exception.Message)" -Level Error
        throw
    }
}

function Set-GraphPermissions {
    if (-not $ConfigurePermissions) {
        Write-Log "Skipping permissions configuration as requested"
        return
    }
    
    try {
        Write-Log "Configuring Microsoft Graph permissions..."
        
        $requiredPermissions = @(
            'Reports.Read.All',
            'User.Read.All',
            'UserAuthenticationMethod.Read.All',
            'Directory.Read.All',
            'AuditLog.Read.All'
        )
        
        Write-Log "Required permissions for MFA reporting:"
        foreach ($permission in $requiredPermissions) {
            Write-Log "  - $permission"
        }
        
        Write-Log "Application registration steps:"
        Write-Log "1. Navigate to Azure Portal > App Registrations"
        Write-Log "2. Create new application registration or use existing"
        Write-Log "3. Go to API Permissions and add the following Microsoft Graph permissions:"
        foreach ($permission in $requiredPermissions) {
            Write-Log "   - $permission (Application permission)"
        }
        Write-Log "4. Grant admin consent for the permissions"
        Write-Log "5. Create a client secret or certificate for authentication"
        
        Write-Log "Permissions configuration guidance provided"
        
    } catch {
        Write-Log "Permissions configuration failed: $($_.Exception.Message)" -Level Error
        throw
    }
}

function Initialize-DirectoryStructure {
    try {
        Write-Log "Creating directory structure at $InstallPath..."
        
        $directories = @(
            $InstallPath,
            "$InstallPath\scripts",
            "$InstallPath\config",
            "$InstallPath\logs",
            "$InstallPath\reports",
            "$InstallPath\archive",
            "$InstallPath\temp",
            "$InstallPath\templates"
        )
        
        foreach ($dir in $directories) {
            if (-not (Test-Path $dir)) {
                $null = New-Item -Path $dir -ItemType Directory -Force
                Write-Log "Created directory: $dir"
            } else {
                Write-Log "Directory already exists: $dir"
            }
        }
        
        # Copy scripts to installation directory
        $scriptFiles = @(
            "Get-MFARegistrationStatus.ps1",
            "Start-BulkMFAReporting.ps1",
            "Install-Prerequisites.ps1"
        )
        
        foreach ($script in $scriptFiles) {
            if (Test-Path $script) {
                $destPath = Join-Path "$InstallPath\scripts" $script
                Copy-Item -Path $script -Destination $destPath -Force
                Write-Log "Copied script: $script"
            }
        }
        
        Write-Log "Directory structure initialized successfully"
        
    } catch {
        Write-Log "Directory structure initialization failed: $($_.Exception.Message)" -Level Error
        throw
    }
}

function New-ConfigurationFiles {
    if (-not $SetupConfiguration) {
        Write-Log "Skipping configuration file creation as requested"
        return
    }
    
    try {
        Write-Log "Creating configuration files..."
        
        # Main configuration file
        $configPath = Join-Path $InstallPath "config\reporting-config.json"
        $config = @{
            version = "1.0"
            tenants = @(
                @{
                    id = $TenantId -or "your-tenant-id"
                    name = "Primary Tenant"
                    description = "Primary organizational tenant"
                    enabled = $true
                }
            )
            reportSettings = @{
                includeDisabledUsers = $false
                includeAuthMethods = $true
                generateRecommendations = $true
                filterByLicenseStatus = "All"
                complianceThreshold = 90
                outputFormats = @("HTML", "CSV", "JSON")
                archiveAfterDays = 30
            }
            scheduling = @{
                enabled = $false
                frequency = "Daily"
                time = "09:00"
                daysOfWeek = @("Monday", "Tuesday", "Wednesday", "Thursday", "Friday")
            }
            emailConfiguration = @{
                enabled = $false
                smtpServer = "smtp.office365.com"
                smtpPort = 587
                useSSL = $true
                sender = "reports@yourdomain.com"
                recipients = @("admin@yourdomain.com", "security@yourdomain.com")
                subject = "MFA Registration Status Report"
                attachReports = $true
            }
            security = @{
                enableAuditLogging = $true
                auditLogPath = "$InstallPath\logs\audit.log"
                encryptReports = $false
                dataRetentionDays = 365
            }
        }
        
        $config | ConvertTo-Json -Depth 10 | Out-File -FilePath $configPath -Encoding UTF8
        Write-Log "Created configuration file: $configPath"
        
        # PowerShell profile configuration
        $profileConfigPath = Join-Path $InstallPath "config\powershell-profile.ps1"
        $profileConfig = @'
# MFA Registration Reporting PowerShell Profile Configuration

# Set module paths
$MFAReportingPath = "INSTALLPATH"
$env:PSModulePath = "$MFAReportingPath\modules;$env:PSModulePath"

# Import required modules
Import-Module Microsoft.Graph.Authentication -Force
Import-Module Microsoft.Graph.Reports -Force
Import-Module Microsoft.Graph.Users -Force

# Set default parameters
$PSDefaultParameterValues = @{
    'Get-MFARegistrationStatus:OutputFormat' = 'HTML'
    'Get-MFARegistrationStatus:IncludeAuthMethods' = $true
    'Get-MFARegistrationStatus:GenerateRecommendations' = $true
    'Start-BulkMFAReporting:OutputDirectory' = "$MFAReportingPath\reports"
    'Start-BulkMFAReporting:GenerateConsolidatedReport' = $true
}

# Helper functions
function Connect-MFAReporting {
    param([string]$TenantId)
    
    $scopes = @(
        'Reports.Read.All',
        'User.Read.All',
        'UserAuthenticationMethod.Read.All'
    )
    
    if ($TenantId) {
        Connect-MgGraph -TenantId $TenantId -Scopes $scopes
    } else {
        Connect-MgGraph -Scopes $scopes
    }
}

function Get-MFAReportingStatus {
    Get-MgContext | Select-Object TenantId, Account, Scopes, AuthType
}

Write-Host "MFA Registration Reporting environment loaded" -ForegroundColor Green
Write-Host "Available commands:" -ForegroundColor Yellow
Write-Host "  - Connect-MFAReporting" -ForegroundColor Cyan
Write-Host "  - Get-MFARegistrationStatus" -ForegroundColor Cyan
Write-Host "  - Start-BulkMFAReporting" -ForegroundColor Cyan
Write-Host "  - Get-MFAReportingStatus" -ForegroundColor Cyan
'@
        
        $profileConfig = $profileConfig.Replace("INSTALLPATH", $InstallPath)
        $profileConfig | Out-File -FilePath $profileConfigPath -Encoding UTF8
        Write-Log "Created PowerShell profile configuration: $profileConfigPath"
        
        # Create sample tenant configuration
        $sampleConfigPath = Join-Path $InstallPath "config\sample-tenants.json"
        $sampleConfig = @{
            tenants = @(
                @{
                    id = "tenant-1-id"
                    name = "Production Tenant"
                    description = "Main production environment"
                    enabled = $true
                    priority = 1
                },
                @{
                    id = "tenant-2-id"
                    name = "Development Tenant"
                    description = "Development environment"
                    enabled = $true
                    priority = 2
                }
            )
        }
        
        $sampleConfig | ConvertTo-Json -Depth 10 | Out-File -FilePath $sampleConfigPath -Encoding UTF8
        Write-Log "Created sample tenant configuration: $sampleConfigPath"
        
        Write-Log "Configuration files created successfully"
        
    } catch {
        Write-Log "Configuration file creation failed: $($_.Exception.Message)" -Level Error
        throw
    }
}

function New-ScheduledTask {
    if (-not $CreateScheduledTask) {
        Write-Log "Skipping scheduled task creation as requested"
        return
    }
    
    try {
        Write-Log "Creating scheduled task for MFA reporting..."
        
        $taskName = "MFA-Registration-Reporting"
        $taskDescription = "Automated MFA Registration Status Reporting"
        $scriptPath = Join-Path $InstallPath "scripts\Start-BulkMFAReporting.ps1"
        
        # Check if task already exists
        $existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        if ($existingTask) {
            Write-Log "Scheduled task '$taskName' already exists. Removing existing task..."
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
        }
        
        # Create task action
        $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ExecutionPolicy Bypass -File `"$scriptPath`" -ConfigPath `"$InstallPath\config\reporting-config.json`" -OutputDirectory `"$InstallPath\reports`" -GenerateConsolidatedReport"
        
        # Create task trigger (daily at 9 AM)
        $trigger = New-ScheduledTaskTrigger -Daily -At "09:00"
        
        # Create task settings
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
        
        # Create task principal (run as SYSTEM)
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount
        
        # Register the task
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Description $taskDescription
        
        Write-Log "Scheduled task '$taskName' created successfully"
        Write-Log "Task will run daily at 9:00 AM"
        
        # Display task information
        $task = Get-ScheduledTask -TaskName $taskName
        Write-Log "Task status: $($task.State)"
        Write-Log "Next run time: $($task.NextRunTime)"
        
    } catch {
        Write-Log "Scheduled task creation failed: $($_.Exception.Message)" -Level Error
        throw
    }
}

function Test-GraphConnection {
    if (-not $TestConnection) {
        Write-Log "Skipping connection test as requested"
        return
    }
    
    try {
        Write-Log "Testing Microsoft Graph connection..."
        
        $requiredScopes = @(
            'Reports.Read.All',
            'User.Read.All',
            'UserAuthenticationMethod.Read.All'
        )
        
        # Test connection
        $connectParams = @{
            Scopes = $requiredScopes
            NoWelcome = $true
        }
        
        if ($TenantId) {
            $connectParams.TenantId = $TenantId
        }
        
        Connect-MgGraph @connectParams
        
        # Get context information
        $context = Get-MgContext
        Write-Log "Successfully connected to Microsoft Graph"
        Write-Log "Tenant ID: $($context.TenantId)"
        Write-Log "Account: $($context.Account)"
        Write-Log "Scopes: $($context.Scopes -join ', ')"
        
        # Test API access
        Write-Log "Testing API access..."
        $testReport = Get-MgReportAuthenticationMethodUserRegistrationDetail -Top 1 -ErrorAction SilentlyContinue
        
        if ($testReport) {
            Write-Log "API access test successful"
        } else {
            Write-Log "API access test failed - check permissions" -Level Warning
        }
        
        # Disconnect
        Disconnect-MgGraph
        Write-Log "Disconnected from Microsoft Graph"
        
    } catch {
        Write-Log "Graph connection test failed: $($_.Exception.Message)" -Level Error
        
        # Provide troubleshooting guidance
        Write-Log "Troubleshooting steps:" -Level Warning
        Write-Log "1. Ensure you have the required permissions" -Level Warning
        Write-Log "2. Check if your account has admin consent for the application" -Level Warning
        Write-Log "3. Verify network connectivity to graph.microsoft.com" -Level Warning
        Write-Log "4. Try running Connect-MgGraph manually to check for specific errors" -Level Warning
    }
}

function Show-CompletionSummary {
    try {
        Write-Log "Installation completed successfully!"
        Write-Log ""
        Write-Log "=== Installation Summary ===" -Level Warning
        Write-Log "Installation Path: $InstallPath"
        Write-Log "Configuration Path: $InstallPath\config"
        Write-Log "Reports Path: $InstallPath\reports"
        Write-Log "Logs Path: $InstallPath\logs"
        Write-Log ""
        Write-Log "=== Next Steps ===" -Level Warning
        Write-Log "1. Update configuration file: $InstallPath\config\reporting-config.json"
        Write-Log "2. Configure tenant IDs and email settings"
        Write-Log "3. Test the installation:"
        Write-Log "   cd $InstallPath\scripts"
        Write-Log "   .\Get-MFARegistrationStatus.ps1 -OutputFormat Console"
        Write-Log ""
        Write-Log "=== Available Scripts ===" -Level Warning
        Write-Log "- Get-MFARegistrationStatus.ps1: Single tenant MFA report"
        Write-Log "- Start-BulkMFAReporting.ps1: Multi-tenant bulk reporting"
        Write-Log ""
        Write-Log "=== Documentation ===" -Level Warning
        Write-Log "For detailed usage instructions, see the README.md file"
        Write-Log "For troubleshooting, check the logs directory"
        
    } catch {
        Write-Log "Failed to show completion summary: $($_.Exception.Message)" -Level Error
    }
}

# Main execution
try {
    Write-Log "Starting MFA Registration Reporting prerequisites installation..."
    
    # Run prerequisites check
    Test-Prerequisites
    
    # Install required modules
    Install-RequiredModules
    
    # Configure permissions (guidance)
    Set-GraphPermissions
    
    # Initialize directory structure
    Initialize-DirectoryStructure
    
    # Create configuration files
    New-ConfigurationFiles
    
    # Create scheduled task if requested
    New-ScheduledTask
    
    # Test connection if requested
    Test-GraphConnection
    
    # Show completion summary
    Show-CompletionSummary
    
    Write-Log "MFA Registration Reporting prerequisites installation completed successfully"
    
} catch {
    Write-Log "Prerequisites installation failed: $($_.Exception.Message)" -Level Error
    Write-Log "Stack trace: $($_.Exception.StackTrace)" -Level Error
    throw
}
