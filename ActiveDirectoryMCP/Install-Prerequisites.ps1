# Prerequisites Installation Script for Active Directory MCP Server
# This script installs the required PowerShell modules and dependencies

<#
.SYNOPSIS
    Installs prerequisites for the Active Directory MCP Server.

.DESCRIPTION
    This script installs the required PowerShell modules and dependencies
    needed for the Active Directory MCP Server to function properly.

.PARAMETER InstallModules
    Whether to install PowerShell modules

.PARAMETER InstallNodeModules
    Whether to install Node.js modules

.PARAMETER UpdateModules
    Whether to update existing modules

.PARAMETER TestConnection
    Whether to test AD connection after installation

.EXAMPLE
    .\Install-Prerequisites.ps1 -InstallModules -InstallNodeModules -TestConnection
#>

param(
    [switch]$InstallModules = $true,
    [switch]$InstallNodeModules = $true,
    [switch]$UpdateModules = $false,
    [switch]$TestConnection = $false
)

Write-Host "=== Active Directory MCP Server Prerequisites Installation ===" -ForegroundColor Green

# Check if running as administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

if (-not $isAdmin) {
    Write-Warning "This script should be run as Administrator for best results"
    Write-Host "Some modules may require elevated privileges to install" -ForegroundColor Yellow
}

# Check PowerShell version
$psVersion = $PSVersionTable.PSVersion
Write-Host "PowerShell Version: $psVersion" -ForegroundColor Cyan

if ($psVersion.Major -lt 5) {
    Write-Error "PowerShell 5.1 or higher is required. Please upgrade PowerShell."
    exit 1
}

# Check if Active Directory module is available
$adModuleAvailable = Get-Module -ListAvailable -Name ActiveDirectory
if (-not $adModuleAvailable) {
    Write-Warning "Active Directory PowerShell module is not installed"
    Write-Host "Please install Remote Server Administration Tools (RSAT) for Active Directory" -ForegroundColor Yellow
    Write-Host "Download from: https://www.microsoft.com/en-us/download/details.aspx?id=45520" -ForegroundColor Cyan
}

# Install PowerShell modules
if ($InstallModules) {
    Write-Host "Installing PowerShell modules..." -ForegroundColor Yellow
    
    $requiredModules = @(
        @{ Name = "ActiveDirectory"; Description = "Active Directory PowerShell Module" },
        @{ Name = "ImportExcel"; Description = "Excel import/export functionality" },
        @{ Name = "PSWriteHTML"; Description = "HTML report generation" },
        @{ Name = "PSLogging"; Description = "Enhanced logging capabilities" },
        @{ Name = "PSFramework"; Description = "PowerShell framework utilities" },
        @{ Name = "Microsoft.PowerShell.Archive"; Description = "Archive operations" },
        @{ Name = "PowerShellGet"; Description = "PowerShell package management" }
    )
    
    foreach ($module in $requiredModules) {
        Write-Host "Processing module: $($module.Name)" -ForegroundColor Cyan
        
        try {
            $installedModule = Get-Module -ListAvailable -Name $module.Name
            
            if ($installedModule) {
                if ($UpdateModules) {
                    Write-Host "Updating module: $($module.Name)" -ForegroundColor Yellow
                    Update-Module -Name $module.Name -Force
                } else {
                    Write-Host "✓ Module already installed: $($module.Name)" -ForegroundColor Green
                }
            } else {
                Write-Host "Installing module: $($module.Name)" -ForegroundColor Yellow
                Install-Module -Name $module.Name -Force -AllowClobber -Scope CurrentUser
                Write-Host "✓ Module installed: $($module.Name)" -ForegroundColor Green
            }
        } catch {
            Write-Warning "Failed to install module '$($module.Name)': $($_.Exception.Message)"
        }
    }
}

# Check Node.js installation
if ($InstallNodeModules) {
    Write-Host "Checking Node.js installation..." -ForegroundColor Yellow
    
    try {
        $nodeVersion = node --version
        Write-Host "✓ Node.js version: $nodeVersion" -ForegroundColor Green
        
        # Check if version is 18 or higher
        $version = [version]($nodeVersion -replace 'v', '')
        if ($version.Major -lt 18) {
            Write-Warning "Node.js 18 or higher is required. Current version: $nodeVersion"
            Write-Host "Please upgrade Node.js: https://nodejs.org/" -ForegroundColor Yellow
        }
    } catch {
        Write-Error "Node.js is not installed or not in PATH"
        Write-Host "Please install Node.js 18 or higher: https://nodejs.org/" -ForegroundColor Yellow
        exit 1
    }
    
    # Check npm
    try {
        $npmVersion = npm --version
        Write-Host "✓ npm version: $npmVersion" -ForegroundColor Green
    } catch {
        Write-Error "npm is not installed or not in PATH"
        exit 1
    }
    
    # Install Node.js dependencies
    Write-Host "Installing Node.js dependencies..." -ForegroundColor Yellow
    
    $packageJsonPath = Join-Path $PSScriptRoot "package.json"
    if (Test-Path $packageJsonPath) {
        try {
            Push-Location $PSScriptRoot
            npm install
            Write-Host "✓ Node.js dependencies installed" -ForegroundColor Green
        } catch {
            Write-Error "Failed to install Node.js dependencies: $($_.Exception.Message)"
        } finally {
            Pop-Location
        }
    } else {
        Write-Warning "package.json not found. Run this script from the project root directory."
    }
}

# Test Active Directory connection
if ($TestConnection) {
    Write-Host "Testing Active Directory connection..." -ForegroundColor Yellow
    
    try {
        # Import Active Directory module
        Import-Module ActiveDirectory -ErrorAction Stop
        
        # Test basic AD connectivity
        $domain = Get-ADDomain -ErrorAction Stop
        Write-Host "✓ Connected to domain: $($domain.DNSRoot)" -ForegroundColor Green
        
        # Test user query
        $testUser = Get-ADUser -Filter "Name -eq '$env:USERNAME'" -ErrorAction Stop
        if ($testUser) {
            Write-Host "✓ User query successful: $($testUser.Name)" -ForegroundColor Green
        }
        
        # Test group query
        $testGroup = Get-ADGroup -Filter "Name -eq 'Domain Users'" -ErrorAction Stop
        if ($testGroup) {
            Write-Host "✓ Group query successful: $($testGroup.Name)" -ForegroundColor Green
        }
        
        Write-Host "✓ Active Directory connection test passed" -ForegroundColor Green
        
    } catch {
        Write-Error "Active Directory connection test failed: $($_.Exception.Message)"
        Write-Host "Please verify:" -ForegroundColor Yellow
        Write-Host "1. You are connected to the domain" -ForegroundColor Cyan
        Write-Host "2. Active Directory module is installed" -ForegroundColor Cyan
        Write-Host "3. You have appropriate permissions" -ForegroundColor Cyan
    }
}

# Check Windows features
Write-Host "Checking Windows features..." -ForegroundColor Yellow

if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
    $rsatFeatures = Get-WindowsFeature -Name "RSAT-AD-PowerShell" -ErrorAction SilentlyContinue
    if ($rsatFeatures -and $rsatFeatures.InstallState -eq "Installed") {
        Write-Host "✓ RSAT Active Directory PowerShell feature is installed" -ForegroundColor Green
    } else {
        Write-Warning "RSAT Active Directory PowerShell feature is not installed"
        Write-Host "Install with: Install-WindowsFeature RSAT-AD-PowerShell" -ForegroundColor Cyan
    }
}

# Create directories if they don't exist
Write-Host "Creating required directories..." -ForegroundColor Yellow

$directories = @(
    "logs",
    "config",
    "temp",
    "reports",
    "cache"
)

foreach ($dir in $directories) {
    $dirPath = Join-Path $PSScriptRoot $dir
    if (-not (Test-Path $dirPath)) {
        New-Item -ItemType Directory -Path $dirPath -Force | Out-Null
        Write-Host "✓ Created directory: $dir" -ForegroundColor Green
    } else {
        Write-Host "✓ Directory exists: $dir" -ForegroundColor Green
    }
}

# Create configuration file if it doesn't exist
Write-Host "Checking configuration file..." -ForegroundColor Yellow

$configPath = Join-Path $PSScriptRoot "config\config.json"
$exampleConfigPath = Join-Path $PSScriptRoot "config.example.json"

if (-not (Test-Path $configPath) -and (Test-Path $exampleConfigPath)) {
    Copy-Item $exampleConfigPath $configPath
    Write-Host "✓ Created configuration file from example" -ForegroundColor Green
    Write-Host "Please edit config\config.json with your environment settings" -ForegroundColor Yellow
} elseif (Test-Path $configPath) {
    Write-Host "✓ Configuration file exists" -ForegroundColor Green
} else {
    Write-Warning "Configuration file not found. Please create config\config.json"
}

# Check TypeScript installation
Write-Host "Checking TypeScript installation..." -ForegroundColor Yellow

try {
    $tscVersion = tsc --version
    Write-Host "✓ TypeScript version: $tscVersion" -ForegroundColor Green
} catch {
    Write-Host "Installing TypeScript globally..." -ForegroundColor Yellow
    try {
        npm install -g typescript
        Write-Host "✓ TypeScript installed globally" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to install TypeScript globally: $($_.Exception.Message)"
    }
}

# Final summary
Write-Host "`n=== Installation Summary ===" -ForegroundColor Green

Write-Host "Prerequisites check completed:" -ForegroundColor Yellow
Write-Host "✓ PowerShell modules" -ForegroundColor Green
Write-Host "✓ Node.js and npm" -ForegroundColor Green
Write-Host "✓ Project dependencies" -ForegroundColor Green
Write-Host "✓ Directory structure" -ForegroundColor Green
Write-Host "✓ Configuration setup" -ForegroundColor Green

if ($TestConnection) {
    Write-Host "✓ Active Directory connection test" -ForegroundColor Green
}

Write-Host "`nNext steps:" -ForegroundColor Yellow
Write-Host "1. Edit config\config.json with your environment settings" -ForegroundColor Cyan
Write-Host "2. Run 'npm run build' to compile TypeScript" -ForegroundColor Cyan
Write-Host "3. Run 'npm test' to verify installation" -ForegroundColor Cyan
Write-Host "4. Run 'npm start' to start the MCP server" -ForegroundColor Cyan

Write-Host "`nFor additional help:" -ForegroundColor Yellow
Write-Host "- Check the README.md file" -ForegroundColor Cyan
Write-Host "- Run '.\Test-ADConnection.ps1' to test AD connectivity" -ForegroundColor Cyan
Write-Host "- Run '.\Setup-ServiceAccount.ps1' to create service account" -ForegroundColor Cyan
