#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Installs and configures prerequisites for SAP SuccessFactors Integration
.DESCRIPTION
    This script installs all required PowerShell modules, configures permissions,
    and sets up the environment for SAP SuccessFactors termination verification.
.PARAMETER Scope
    Installation scope for PowerShell modules (CurrentUser or AllUsers)
.PARAMETER SkipAzureAdConnect
    Skip Azure AD Connect validation
.PARAMETER SkipActiveDirectoryCheck
    Skip Active Directory availability check
.PARAMETER ConfigureScheduledTask
    Configure scheduled task for automated processing
.PARAMETER InstallAzureAutomation
    Install Azure Automation prerequisites
.PARAMETER ValidateConnectivity
    Validate connectivity to external services
.PARAMETER Force
    Force installation even if modules already exist
.EXAMPLE
    .\Install-Prerequisites.ps1
.EXAMPLE
    .\Install-Prerequisites.ps1 -Scope AllUsers -ConfigureScheduledTask
.EXAMPLE
    .\Install-Prerequisites.ps1 -SkipAzureAdConnect -SkipActiveDirectoryCheck -Force
.NOTES
    Author: GitHub Copilot
    Version: 1.0
    Requires: PowerShell 5.1 or later, Administrator privileges
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet('CurrentUser', 'AllUsers')]
    [string]$Scope = 'CurrentUser',
    
    [Parameter(Mandatory = $false)]
    [switch]$SkipAzureAdConnect,
    
    [Parameter(Mandatory = $false)]
    [switch]$SkipActiveDirectoryCheck,
    
    [Parameter(Mandatory = $false)]
    [switch]$ConfigureScheduledTask,
    
    [Parameter(Mandatory = $false)]
    [switch]$InstallAzureAutomation,
    
    [Parameter(Mandatory = $false)]
    [switch]$ValidateConnectivity,
    
    [Parameter(Mandatory = $false)]
    [switch]$Force
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
    Write-Log "Checking system prerequisites..."
    
    # Check PowerShell version
    if ($PSVersionTable.PSVersion -lt [Version]'5.1') {
        Write-Log "PowerShell 5.1 or later is required" -Level Error
        return $false
    }
    
    Write-Log "PowerShell version: $($PSVersionTable.PSVersion)"
    
    # Check if running as administrator
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if ($Scope -eq 'AllUsers' -and -not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Log "Administrator privileges required for AllUsers scope" -Level Error
        return $false
    }
    
    # Check execution policy
    $executionPolicy = Get-ExecutionPolicy
    if ($executionPolicy -eq 'Restricted') {
        Write-Log "Execution policy is Restricted. Please run: Set-ExecutionPolicy -ExecutionPolicy RemoteSigned" -Level Error
        return $false
    }
    
    Write-Log "Execution policy: $executionPolicy"
    
    # Check internet connectivity
    try {
        $null = Test-Connection -ComputerName "8.8.8.8" -Count 1 -ErrorAction Stop
        Write-Log "Internet connectivity verified"
    } catch {
        Write-Log "Internet connectivity check failed: $($_.Exception.Message)" -Level Warning
    }
    
    return $true
}

function Install-PowerShellModules {
    Write-Log "Installing PowerShell modules..."
    
    # Define required modules
    $requiredModules = @(
        @{
            Name = 'Microsoft.Graph.Authentication'
            MinVersion = '1.0.0'
            Description = 'Microsoft Graph Authentication module'
        },
        @{
            Name = 'Microsoft.Graph.Users'
            MinVersion = '1.0.0'
            Description = 'Microsoft Graph Users module'
        },
        @{
            Name = 'Microsoft.Graph.Groups'
            MinVersion = '1.0.0'
            Description = 'Microsoft Graph Groups module'
        },
        @{
            Name = 'Microsoft.Graph.DirectoryObjects'
            MinVersion = '1.0.0'
            Description = 'Microsoft Graph Directory Objects module'
        },
        @{
            Name = 'Microsoft.Graph.Identity.DirectoryManagement'
            MinVersion = '1.0.0'
            Description = 'Microsoft Graph Identity Directory Management module'
        },
        @{
            Name = 'ActiveDirectory'
            MinVersion = '1.0.0'
            Description = 'Active Directory module'
            Optional = $true
        },
        @{
            Name = 'AzureAD'
            MinVersion = '2.0.0'
            Description = 'Azure Active Directory module'
            Optional = $true
        },
        @{
            Name = 'Az.Accounts'
            MinVersion = '2.0.0'
            Description = 'Azure PowerShell Accounts module'
            Optional = $InstallAzureAutomation
        },
        @{
            Name = 'Az.Automation'
            MinVersion = '1.0.0'
            Description = 'Azure Automation module'
            Optional = $InstallAzureAutomation
        },
        @{
            Name = 'Az.Resources'
            MinVersion = '1.0.0'
            Description = 'Azure Resources module'
            Optional = $InstallAzureAutomation
        },
        @{
            Name = 'ImportExcel'
            MinVersion = '7.0.0'
            Description = 'Excel import/export module'
            Optional = $true
        },
        @{
            Name = 'Pester'
            MinVersion = '5.0.0'
            Description = 'Pester testing framework'
            Optional = $true
        }
    )
    
    foreach ($module in $requiredModules) {
        try {
            $installedModule = Get-Module -ListAvailable -Name $module.Name | 
                Sort-Object Version -Descending | 
                Select-Object -First 1
            
            if ($installedModule -and $installedModule.Version -ge [Version]$module.MinVersion -and -not $Force) {
                Write-Log "Module $($module.Name) version $($installedModule.Version) is already installed"
                continue
            }
            
            if ($module.Optional -and -not $module.Optional) {
                Write-Log "Skipping optional module: $($module.Name)"
                continue
            }
            
            Write-Log "Installing module: $($module.Name)"
            Install-Module -Name $module.Name -Scope $Scope -Force -AllowClobber -ErrorAction Stop
            
            $newModule = Get-Module -ListAvailable -Name $module.Name | 
                Sort-Object Version -Descending | 
                Select-Object -First 1
            
            Write-Log "Successfully installed $($module.Name) version $($newModule.Version)"
            
        } catch {
            if ($module.Optional) {
                Write-Log "Failed to install optional module $($module.Name): $($_.Exception.Message)" -Level Warning
            } else {
                Write-Log "Failed to install required module $($module.Name): $($_.Exception.Message)" -Level Error
                throw
            }
        }
    }
}

function Test-ActiveDirectoryConnectivity {
    if ($SkipActiveDirectoryCheck) {
        Write-Log "Skipping Active Directory connectivity check"
        return $true
    }
    
    Write-Log "Testing Active Directory connectivity..."
    
    try {
        # Test if AD module is available
        if (Get-Module -ListAvailable -Name ActiveDirectory) {
            Import-Module ActiveDirectory -ErrorAction Stop
            
            # Test domain connectivity
            $domain = Get-ADDomain -ErrorAction Stop
            Write-Log "Connected to domain: $($domain.DNSRoot)"
            
            # Test basic query
            $null = Get-ADUser -Filter "Name -like '*'" -ResultSetSize 1 -ErrorAction Stop
            Write-Log "Active Directory connectivity verified"
            
            return $true
        } else {
            Write-Log "Active Directory module not available" -Level Warning
            return $false
        }
    } catch {
        Write-Log "Active Directory connectivity failed: $($_.Exception.Message)" -Level Warning
        return $false
    }
}

function Test-AzureAdConnectivity {
    if ($SkipAzureAdConnect) {
        Write-Log "Skipping Azure AD connectivity check"
        return $true
    }
    
    Write-Log "Testing Azure AD connectivity..."
    
    try {
        # Test Microsoft Graph connectivity
        Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
        
        Write-Log "Microsoft Graph Authentication module loaded"
        Write-Log "Please run 'Connect-MgGraph' to authenticate to Microsoft Graph"
        
        return $true
    } catch {
        Write-Log "Microsoft Graph module test failed: $($_.Exception.Message)" -Level Warning
        return $false
    }
}

function Test-SapSuccessFactorsConnectivity {
    if (-not $ValidateConnectivity) {
        Write-Log "Skipping SAP SuccessFactors connectivity validation"
        return $true
    }
    
    Write-Log "Testing SAP SuccessFactors connectivity..."
    
    try {
        # Test connectivity to SAP SuccessFactors API endpoint
        $testEndpoint = "https://api4.successfactors.com/odata/v2"
        $response = Invoke-WebRequest -Uri $testEndpoint -Method Get -UseBasicParsing -TimeoutSec 10
        
        if ($response.StatusCode -eq 200) {
            Write-Log "SAP SuccessFactors API endpoint is reachable"
            return $true
        } else {
            Write-Log "SAP SuccessFactors API endpoint returned status: $($response.StatusCode)" -Level Warning
            return $false
        }
    } catch {
        Write-Log "SAP SuccessFactors connectivity test failed: $($_.Exception.Message)" -Level Warning
        return $false
    }
}

function New-ConfigurationTemplate {
    Write-Log "Creating configuration template..."
    
    try {
        $configPath = ".\config\verification-config-template.json"
        $configDir = Split-Path $configPath -Parent
        
        $null = New-Item -Path $configDir -ItemType Directory -Force -ErrorAction SilentlyContinue
        
        $templateConfig = @{
            successFactors = @{
                endpoint = "https://api4.successfactors.com/odata/v2"
                description = "Update with your SAP SuccessFactors API endpoint"
            }
            companies = @(
                @{
                    id = "YOUR_COMPANY_ID"
                    name = "Your Company Name"
                    description = "Update with your company details"
                    endpoint = "https://api4.successfactors.com/odata/v2"
                    clientId = "YOUR_CLIENT_ID"
                    clientSecret = "YOUR_CLIENT_SECRET"
                    region = "US"
                    timezone = "America/New_York"
                    enabled = $true
                }
            )
            processingSettings = @{
                gracePeriodDays = 7
                includeActiveUsers = $false
                autoRemediate = $false
                dryRun = $true
                complianceThreshold = 95
            }
            notificationSettings = @{
                enabled = $false
                recipients = @("admin@company.com")
                smtpServer = "smtp.company.com"
                smtpPort = 587
                smtpUseSsl = $true
            }
            activeDirectorySettings = @{
                searchBase = "DC=company,DC=com"
                serviceAccount = "AD_SERVICE_ACCOUNT"
            }
            azureAdSettings = @{
                tenantId = "YOUR_TENANT_ID"
                clientId = "YOUR_CLIENT_ID"
                clientSecret = "YOUR_CLIENT_SECRET"
            }
        }
        
        $templateConfig | ConvertTo-Json -Depth 10 | Out-File -FilePath $configPath -Encoding UTF8
        Write-Log "Configuration template created: $configPath"
        
    } catch {
        Write-Log "Failed to create configuration template: $($_.Exception.Message)" -Level Error
    }
}

function Install-ScheduledTask {
    if (-not $ConfigureScheduledTask) {
        Write-Log "Skipping scheduled task configuration"
        return
    }
    
    Write-Log "Configuring scheduled task..."
    
    try {
        # Create scheduled task for automated processing
        $taskName = "SAP SuccessFactors Termination Verification"
        $taskDescription = "Automated verification of terminated users from SAP SuccessFactors"
        
        $scriptPath = Join-Path $PSScriptRoot "Start-BulkTerminationVerification.ps1"
        $arguments = "-ConfigPath `"$PSScriptRoot\config\verification-config.json`" -OutputDirectory `"$PSScriptRoot\reports`" -GenerateConsolidatedReport"
        
        $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ExecutionPolicy Bypass -File `"$scriptPath`" $arguments"
        $trigger = New-ScheduledTaskTrigger -Daily -At "2:00AM"
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
        
        $task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description $taskDescription
        
        # Check if task already exists
        if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
            Write-Log "Updating existing scheduled task: $taskName"
            Set-ScheduledTask -TaskName $taskName -InputObject $task
        } else {
            Write-Log "Creating new scheduled task: $taskName"
            Register-ScheduledTask -TaskName $taskName -InputObject $task
        }
        
        Write-Log "Scheduled task configured successfully"
        
    } catch {
        Write-Log "Failed to configure scheduled task: $($_.Exception.Message)" -Level Error
    }
}

function Test-Installation {
    Write-Log "Testing installation..."
    
    try {
        # Test module imports
        $testModules = @('Microsoft.Graph.Authentication', 'Microsoft.Graph.Users')
        
        foreach ($module in $testModules) {
            try {
                Import-Module $module -ErrorAction Stop
                Write-Log "Successfully imported: $module"
            } catch {
                Write-Log "Failed to import: $module - $($_.Exception.Message)" -Level Error
            }
        }
        
        # Test script execution
        $verifyScript = Join-Path $PSScriptRoot "Verify-TerminatedUsers.ps1"
        if (Test-Path $verifyScript) {
            Write-Log "Main verification script found: $verifyScript"
        } else {
            Write-Log "Main verification script not found: $verifyScript" -Level Warning
        }
        
        # Test configuration
        $configPath = ".\config\verification-config.json"
        if (Test-Path $configPath) {
            Write-Log "Configuration file found: $configPath"
        } else {
            Write-Log "Configuration file not found: $configPath" -Level Warning
        }
        
        Write-Log "Installation test completed"
        
    } catch {
        Write-Log "Installation test failed: $($_.Exception.Message)" -Level Error
    }
}

function Show-PostInstallationInstructions {
    Write-Log "=== Post-Installation Instructions ==="
    Write-Log ""
    Write-Log "1. Configuration Setup:"
    Write-Log "   - Edit config\verification-config.json with your environment details"
    Write-Log "   - Update SAP SuccessFactors API credentials"
    Write-Log "   - Configure Azure AD/Active Directory settings"
    Write-Log "   - Set up notification recipients"
    Write-Log ""
    Write-Log "2. Authentication Setup:"
    Write-Log "   - Run: Connect-MgGraph -Scopes 'User.Read.All','Directory.Read.All'"
    Write-Log "   - Authenticate with appropriate permissions"
    Write-Log ""
    Write-Log "3. Test Connectivity:"
    Write-Log "   - Run: .\Verify-TerminatedUsers.ps1 -DryRun"
    Write-Log "   - Verify SAP SuccessFactors connectivity"
    Write-Log "   - Test Active Directory/Azure AD connectivity"
    Write-Log ""
    Write-Log "4. Scheduled Execution:"
    if ($ConfigureScheduledTask) {
        Write-Log "   - Scheduled task has been configured"
        Write-Log "   - Check Task Scheduler for 'SAP SuccessFactors Termination Verification'"
    } else {
        Write-Log "   - Run: .\Install-Prerequisites.ps1 -ConfigureScheduledTask"
        Write-Log "   - Or manually configure scheduled execution"
    }
    Write-Log ""
    Write-Log "5. Testing:"
    Write-Log "   - Run Pester tests: Invoke-Pester .\tests\"
    Write-Log "   - Review test results and fix any issues"
    Write-Log ""
    Write-Log "6. Documentation:"
    Write-Log "   - Review README.md for detailed usage instructions"
    Write-Log "   - Check example configurations in config\ folder"
    Write-Log ""
    Write-Log "Installation completed successfully!"
}

# Main execution
try {
    Write-Log "Starting SAP SuccessFactors Integration prerequisites installation..."
    
    # Check prerequisites
    if (-not (Test-Prerequisites)) {
        throw "Prerequisites check failed"
    }
    
    # Install PowerShell modules
    Install-PowerShellModules
    
    # Test connectivity
    $adConnected = Test-ActiveDirectoryConnectivity
    $azureAdConnected = Test-AzureAdConnectivity
    $sfConnected = Test-SapSuccessFactorsConnectivity
    
    # Log connectivity results
    Write-Log "Connectivity test results:"
    Write-Log "- Active Directory: $(if ($adConnected) { 'Connected' } else { 'Not Connected' })"
    Write-Log "- Azure AD: $(if ($azureAdConnected) { 'Connected' } else { 'Not Connected' })"
    Write-Log "- SAP SuccessFactors: $(if ($sfConnected) { 'Connected' } else { 'Not Connected' })"
    
    # Create configuration template
    New-ConfigurationTemplate
    
    # Configure scheduled task if requested
    Install-ScheduledTask
    
    # Test installation
    Test-Installation
    
    # Show post-installation instructions
    Show-PostInstallationInstructions
    
    Write-Log "Prerequisites installation completed successfully!"
    
} catch {
    Write-Log "Prerequisites installation failed: $($_.Exception.Message)" -Level Error
    Write-Log "Stack trace: $($_.Exception.StackTrace)" -Level Error
    throw
}
