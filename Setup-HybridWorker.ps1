# Hybrid Runbook Worker Setup Script
# This script helps set up a Hybrid Runbook Worker for Active Directory connectivity

<#
.SYNOPSIS
    Sets up a Hybrid Runbook Worker for Azure Automation with Active Directory connectivity.

.DESCRIPTION
    This script configures a Windows server as a Hybrid Runbook Worker for Azure Automation,
    specifically for the Disable Inactive Users runbook. It installs required components,
    configures the worker, and validates the setup.

.PARAMETER ResourceGroupName
    Resource group name containing the Automation Account

.PARAMETER AutomationAccountName
    Name of the Azure Automation Account

.PARAMETER HybridWorkerGroupName
    Name of the Hybrid Worker Group to create or join

.PARAMETER WorkerName
    Name for this specific worker (defaults to computer name)

.PARAMETER ValidateOnly
    Only validate the current setup without making changes

.EXAMPLE
    .\Setup-HybridWorker.ps1 -ResourceGroupName "rg-automation" -AutomationAccountName "aa-iam" -HybridWorkerGroupName "ADWorkers"

.EXAMPLE
    .\Setup-HybridWorker.ps1 -ResourceGroupName "rg-automation" -AutomationAccountName "aa-iam" -HybridWorkerGroupName "ADWorkers" -ValidateOnly
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$ResourceGroupName,
    
    [Parameter(Mandatory = $true)]
    [string]$AutomationAccountName,
    
    [Parameter(Mandatory = $true)]
    [string]$HybridWorkerGroupName,
    
    [string]$WorkerName = $env:COMPUTERNAME,
    
    [switch]$ValidateOnly
)

# Check if running as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script must be run as Administrator"
    exit 1
}

Write-Host "=== Azure Automation Hybrid Worker Setup ===" -ForegroundColor Green
Write-Host "Resource Group: $ResourceGroupName" -ForegroundColor Yellow
Write-Host "Automation Account: $AutomationAccountName" -ForegroundColor Yellow
Write-Host "Hybrid Worker Group: $HybridWorkerGroupName" -ForegroundColor Yellow
Write-Host "Worker Name: $WorkerName" -ForegroundColor Yellow
Write-Host "Validate Only: $ValidateOnly" -ForegroundColor Yellow

# Function to check prerequisites
function Test-Prerequisites {
    Write-Host "`nChecking prerequisites..." -ForegroundColor Green
    
    $issues = @()
    
    # Check if domain joined
    $computerSystem = Get-WmiObject -Class Win32_ComputerSystem
    if ($computerSystem.PartOfDomain) {
        Write-Host "✓ Server is domain-joined: $($computerSystem.Domain)" -ForegroundColor Green
    } else {
        $issues += "Server is not domain-joined"
        Write-Host "✗ Server is not domain-joined" -ForegroundColor Red
    }
    
    # Check PowerShell version
    $psVersion = $PSVersionTable.PSVersion
    if ($psVersion.Major -ge 5) {
        Write-Host "✓ PowerShell version: $($psVersion.ToString())" -ForegroundColor Green
    } else {
        $issues += "PowerShell version must be 5.1 or later"
        Write-Host "✗ PowerShell version: $($psVersion.ToString()) - Need 5.1 or later" -ForegroundColor Red
    }
    
    # Check if ActiveDirectory module is available
    if (Get-Module -ListAvailable -Name ActiveDirectory) {
        Write-Host "✓ ActiveDirectory PowerShell module is available" -ForegroundColor Green
    } else {
        $issues += "ActiveDirectory PowerShell module is not installed"
        Write-Host "✗ ActiveDirectory PowerShell module is not installed" -ForegroundColor Red
    }
    
    # Check Azure PowerShell modules
    $requiredModules = @("Az.Accounts", "Az.Automation", "Az.ConnectedMachine")
    foreach ($module in $requiredModules) {
        if (Get-Module -ListAvailable -Name $module) {
            Write-Host "✓ $module module is available" -ForegroundColor Green
        } else {
            $issues += "$module module is not installed"
            Write-Host "✗ $module module is not installed" -ForegroundColor Red
        }
    }
    
    # Check network connectivity to Azure
    try {
        $testConnection = Test-NetConnection -ComputerName "management.azure.com" -Port 443 -InformationLevel Quiet
        if ($testConnection) {
            Write-Host "✓ Network connectivity to Azure" -ForegroundColor Green
        } else {
            $issues += "No network connectivity to Azure"
            Write-Host "✗ No network connectivity to Azure" -ForegroundColor Red
        }
    } catch {
        $issues += "Unable to test network connectivity to Azure"
        Write-Host "✗ Unable to test network connectivity to Azure" -ForegroundColor Red
    }
    
    # Check if Azure Connected Machine Agent is installed
    $arcAgent = Get-Service -Name "himds" -ErrorAction SilentlyContinue
    if ($arcAgent) {
        Write-Host "✓ Azure Connected Machine Agent is installed" -ForegroundColor Green
    } else {
        $issues += "Azure Connected Machine Agent is not installed"
        Write-Host "✗ Azure Connected Machine Agent is not installed" -ForegroundColor Red
    }
    
    return $issues
}

# Function to install required modules
function Install-RequiredModules {
    Write-Host "`nInstalling required PowerShell modules..." -ForegroundColor Green
    
    $requiredModules = @("Az.Accounts", "Az.Automation", "Az.ConnectedMachine")
    
    foreach ($module in $requiredModules) {
        try {
            if (-not (Get-Module -ListAvailable -Name $module)) {
                Write-Host "Installing $module..." -ForegroundColor Yellow
                Install-Module -Name $module -Force -AllowClobber -Scope AllUsers
                Write-Host "✓ $module installed successfully" -ForegroundColor Green
            } else {
                Write-Host "✓ $module is already installed" -ForegroundColor Green
            }
        } catch {
            Write-Error "Failed to install $module : $($_.Exception.Message)"
        }
    }
}

# Function to install ActiveDirectory module
function Install-ActiveDirectoryModule {
    Write-Host "`nInstalling ActiveDirectory PowerShell module..." -ForegroundColor Green
    
    try {
        if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
            Write-Host "Installing Remote Server Administration Tools (RSAT)..." -ForegroundColor Yellow
            
            # Check Windows version
            $osVersion = [System.Environment]::OSVersion.Version
            if ($osVersion.Major -eq 10) {
                # Windows 10/Server 2016+
                Enable-WindowsOptionalFeature -Online -FeatureName RSATClient-Roles-AD-Powershell -All
            } else {
                # Older Windows versions
                Write-Host "Please install RSAT manually for this Windows version" -ForegroundColor Yellow
                Write-Host "Download from: https://www.microsoft.com/en-us/download/details.aspx?id=45520" -ForegroundColor Yellow
            }
            
            Write-Host "✓ ActiveDirectory module installation initiated" -ForegroundColor Green
        } else {
            Write-Host "✓ ActiveDirectory module is already installed" -ForegroundColor Green
        }
    } catch {
        Write-Error "Failed to install ActiveDirectory module: $($_.Exception.Message)"
    }
}

# Function to configure Azure Connected Machine Agent
function Install-AzureConnectedMachineAgent {
    Write-Host "`nInstalling Azure Connected Machine Agent..." -ForegroundColor Green
    
    try {
        # Check if already installed
        $arcAgent = Get-Service -Name "himds" -ErrorAction SilentlyContinue
        if ($arcAgent) {
            Write-Host "✓ Azure Connected Machine Agent is already installed" -ForegroundColor Green
            return
        }
        
        # Download and install the agent
        $downloadUrl = "https://aka.ms/AzureConnectedMachineAgent"
        $installerPath = "$env:TEMP\AzureConnectedMachineAgent.msi"
        
        Write-Host "Downloading Azure Connected Machine Agent..." -ForegroundColor Yellow
        Invoke-WebRequest -Uri $downloadUrl -OutFile $installerPath
        
        Write-Host "Installing Azure Connected Machine Agent..." -ForegroundColor Yellow
        Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$installerPath`" /quiet" -Wait
        
        Write-Host "✓ Azure Connected Machine Agent installed successfully" -ForegroundColor Green
    } catch {
        Write-Error "Failed to install Azure Connected Machine Agent: $($_.Exception.Message)"
    }
}

# Function to connect to Azure Arc
function Connect-AzureArc {
    param(
        [string]$SubscriptionId,
        [string]$ResourceGroupName,
        [string]$Location = "East US"
    )
    
    Write-Host "`nConnecting server to Azure Arc..." -ForegroundColor Green
    
    try {
        # Check if already connected
        $arcStatus = azcmagent show --output json 2>$null | ConvertFrom-Json
        if ($arcStatus -and $arcStatus.status -eq "Connected") {
            Write-Host "✓ Server is already connected to Azure Arc" -ForegroundColor Green
            return
        }
        
        Write-Host "Connecting to Azure Arc..." -ForegroundColor Yellow
        $connectCommand = "azcmagent connect --subscription-id `"$SubscriptionId`" --resource-group `"$ResourceGroupName`" --location `"$Location`""
        
        Write-Host "Run this command to connect to Azure Arc:" -ForegroundColor Yellow
        Write-Host $connectCommand -ForegroundColor Gray
        Write-Host "Note: You'll need to authenticate with Azure during this process" -ForegroundColor Yellow
        
    } catch {
        Write-Error "Failed to connect to Azure Arc: $($_.Exception.Message)"
    }
}

# Function to install Hybrid Worker extension
function Install-HybridWorkerExtension {
    Write-Host "`nInstalling Hybrid Runbook Worker extension..." -ForegroundColor Green
    
    try {
        # Check if extension is already installed
        $extensions = azcmagent extension list --output json 2>$null | ConvertFrom-Json
        $hybridWorkerExtension = $extensions | Where-Object { $_.name -eq "HybridWorker" }
        
        if ($hybridWorkerExtension) {
            Write-Host "✓ Hybrid Runbook Worker extension is already installed" -ForegroundColor Green
            return
        }
        
        Write-Host "Installing Hybrid Runbook Worker extension..." -ForegroundColor Yellow
        $installCommand = "azcmagent extension install --name HybridWorker --publisher Microsoft.Azure.Automation.HybridWorker --type HybridWorker"
        
        Write-Host "Run this command to install the extension:" -ForegroundColor Yellow
        Write-Host $installCommand -ForegroundColor Gray
        
    } catch {
        Write-Error "Failed to install Hybrid Worker extension: $($_.Exception.Message)"
    }
}

# Function to create or join Hybrid Worker Group
function Setup-HybridWorkerGroup {
    Write-Host "`nSetting up Hybrid Worker Group..." -ForegroundColor Green
    
    try {
        # Connect to Azure
        Connect-AzAccount
        
        # Check if Hybrid Worker Group exists
        $workerGroup = Get-AzAutomationHybridWorkerGroup -AutomationAccountName $AutomationAccountName -ResourceGroupName $ResourceGroupName -Name $HybridWorkerGroupName -ErrorAction SilentlyContinue
        
        if (-not $workerGroup) {
            Write-Host "Creating Hybrid Worker Group: $HybridWorkerGroupName" -ForegroundColor Yellow
            New-AzAutomationHybridWorkerGroup -AutomationAccountName $AutomationAccountName -ResourceGroupName $ResourceGroupName -Name $HybridWorkerGroupName
            Write-Host "✓ Hybrid Worker Group created successfully" -ForegroundColor Green
        } else {
            Write-Host "✓ Hybrid Worker Group already exists" -ForegroundColor Green
        }
        
        # Add worker to group (this is typically done automatically by the extension)
        Write-Host "Note: The worker will be automatically added to the group by the Hybrid Worker extension" -ForegroundColor Yellow
        
    } catch {
        Write-Error "Failed to setup Hybrid Worker Group: $($_.Exception.Message)"
    }
}

# Function to validate the setup
function Test-HybridWorkerSetup {
    Write-Host "`nValidating Hybrid Worker setup..." -ForegroundColor Green
    
    $validationResults = @()
    
    # Check if services are running
    $services = @("himds", "HybridWorker")
    foreach ($service in $services) {
        $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -eq "Running") {
            Write-Host "✓ $service service is running" -ForegroundColor Green
        } else {
            $validationResults += "$service service is not running"
            Write-Host "✗ $service service is not running" -ForegroundColor Red
        }
    }
    
    # Test Active Directory connectivity
    try {
        $domain = Get-ADDomain -ErrorAction Stop
        Write-Host "✓ Active Directory connectivity: $($domain.DNSRoot)" -ForegroundColor Green
    } catch {
        $validationResults += "Cannot connect to Active Directory"
        Write-Host "✗ Cannot connect to Active Directory: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    # Test Azure connectivity
    try {
        $arcStatus = azcmagent show --output json 2>$null | ConvertFrom-Json
        if ($arcStatus -and $arcStatus.status -eq "Connected") {
            Write-Host "✓ Azure Arc connectivity: Connected" -ForegroundColor Green
        } else {
            $validationResults += "Not connected to Azure Arc"
            Write-Host "✗ Not connected to Azure Arc" -ForegroundColor Red
        }
    } catch {
        $validationResults += "Cannot check Azure Arc status"
        Write-Host "✗ Cannot check Azure Arc status" -ForegroundColor Red
    }
    
    return $validationResults
}

# Main execution
try {
    # Check prerequisites
    $prerequisiteIssues = Test-Prerequisites
    
    if ($prerequisiteIssues.Count -gt 0 -and -not $ValidateOnly) {
        Write-Host "`nPrerequisite issues found:" -ForegroundColor Red
        foreach ($issue in $prerequisiteIssues) {
            Write-Host "- $issue" -ForegroundColor Red
        }
        
        $continue = Read-Host "`nDo you want to continue with automatic installation? (y/N)"
        if ($continue -ne "y" -and $continue -ne "Y") {
            Write-Host "Setup cancelled by user" -ForegroundColor Yellow
            exit 0
        }
    }
    
    if ($ValidateOnly) {
        Write-Host "`nValidation complete." -ForegroundColor Green
        if ($prerequisiteIssues.Count -eq 0) {
            Write-Host "All prerequisites are met!" -ForegroundColor Green
        }
        exit 0
    }
    
    # Install required components
    Install-RequiredModules
    Install-ActiveDirectoryModule
    Install-AzureConnectedMachineAgent
    
    # Setup Azure Arc and Hybrid Worker
    Write-Host "`nManual steps required:" -ForegroundColor Yellow
    Write-Host "1. Connect this server to Azure Arc" -ForegroundColor Yellow
    Write-Host "2. Install the Hybrid Worker extension" -ForegroundColor Yellow
    Write-Host "3. Create/join the Hybrid Worker Group" -ForegroundColor Yellow
    
    $subscriptionId = Read-Host "Enter your Azure Subscription ID"
    $location = Read-Host "Enter Azure region (e.g., East US)"
    
    Connect-AzureArc -SubscriptionId $subscriptionId -ResourceGroupName $ResourceGroupName -Location $location
    Install-HybridWorkerExtension
    Setup-HybridWorkerGroup
    
    # Final validation
    Write-Host "`nPerforming final validation..." -ForegroundColor Green
    $validationIssues = Test-HybridWorkerSetup
    
    if ($validationIssues.Count -eq 0) {
        Write-Host "`n✓ Hybrid Worker setup completed successfully!" -ForegroundColor Green
        Write-Host "The server is now ready to run Azure Automation runbooks with Active Directory connectivity." -ForegroundColor Green
    } else {
        Write-Host "`nSetup completed with issues:" -ForegroundColor Yellow
        foreach ($issue in $validationIssues) {
            Write-Host "- $issue" -ForegroundColor Yellow
        }
    }
    
    Write-Host "`nNext steps:" -ForegroundColor Cyan
    Write-Host "1. Update the HybridWorkerGroup variable in your Automation Account" -ForegroundColor Yellow
    Write-Host "2. Test the runbook: Start-AzAutomationRunbook -RunOn '$HybridWorkerGroupName'" -ForegroundColor Yellow
    Write-Host "3. Monitor the runbook execution for any issues" -ForegroundColor Yellow
    
} catch {
    Write-Error "Setup failed: $($_.Exception.Message)"
    exit 1
}
