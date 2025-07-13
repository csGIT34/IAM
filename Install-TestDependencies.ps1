# PowerShell Test Dependencies Installation Script

Write-Host "Installing PowerShell Test Dependencies..." -ForegroundColor Green

# Check if running as Administrator
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Warning "This script requires Administrator privileges to install modules system-wide."
    Write-Host "Please run PowerShell as Administrator and try again." -ForegroundColor Red
    exit 1
}

# Set PowerShell Gallery as trusted repository
Write-Host "Setting PowerShell Gallery as trusted repository..." -ForegroundColor Yellow
Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted

# Install/Update NuGet package provider
Write-Host "Installing NuGet package provider..." -ForegroundColor Yellow
Install-PackageProvider -Name NuGet -Force -MinimumVersion 2.8.5.201

# Install required modules for testing
$requiredModules = @(
    @{ Name = "Pester"; Version = "5.5.0" },
    @{ Name = "PSScriptAnalyzer"; Version = "1.21.0" },
    @{ Name = "PowerShellGet"; Version = "2.2.5" }
)

foreach ($module in $requiredModules) {
    Write-Host "Installing $($module.Name) version $($module.Version)..." -ForegroundColor Yellow
    
    try {
        # Check if module is already installed
        $installed = Get-Module -Name $module.Name -ListAvailable | Where-Object { $_.Version -ge $module.Version }
        
        if ($installed) {
            Write-Host "$($module.Name) version $($installed.Version) is already installed." -ForegroundColor Green
        } else {
            Install-Module -Name $module.Name -MinimumVersion $module.Version -Force -AllowClobber -Scope AllUsers
            Write-Host "$($module.Name) installed successfully." -ForegroundColor Green
        }
    } catch {
        Write-Error "Failed to install $($module.Name): $($_.Exception.Message)"
    }
}

# Install Azure modules for testing (if not already installed)
$azureModules = @(
    "Az.Accounts",
    "Az.Automation",
    "Az.Storage",
    "Az.KeyVault",
    "Az.ConnectedMachine",
    "AzTable"
)

Write-Host "Installing Azure PowerShell modules..." -ForegroundColor Yellow
foreach ($module in $azureModules) {
    try {
        $installed = Get-Module -Name $module -ListAvailable
        
        if ($installed) {
            Write-Host "$module is already installed." -ForegroundColor Green
        } else {
            Install-Module -Name $module -Force -AllowClobber -Scope AllUsers
            Write-Host "$module installed successfully." -ForegroundColor Green
        }
    } catch {
        Write-Warning "Failed to install $module : $($_.Exception.Message)"
    }
}

# Install Microsoft Graph modules for testing
$graphModules = @(
    "Microsoft.Graph.Authentication",
    "Microsoft.Graph.Users",
    "Microsoft.Graph.Mail",
    "Microsoft.Graph.Reports"
)

Write-Host "Installing Microsoft Graph PowerShell modules..." -ForegroundColor Yellow
foreach ($module in $graphModules) {
    try {
        $installed = Get-Module -Name $module -ListAvailable
        
        if ($installed) {
            Write-Host "$module is already installed." -ForegroundColor Green
        } else {
            Install-Module -Name $module -Force -AllowClobber -Scope AllUsers
            Write-Host "$module installed successfully." -ForegroundColor Green
        }
    } catch {
        Write-Warning "Failed to install $module : $($_.Exception.Message)"
    }
}

# Install Active Directory module (if available)
Write-Host "Checking for Active Directory module..." -ForegroundColor Yellow
try {
    $adModule = Get-WindowsFeature -Name "RSAT-AD-PowerShell" -ErrorAction SilentlyContinue
    if ($adModule -and $adModule.InstallState -ne "Installed") {
        Write-Host "Installing Active Directory PowerShell module..." -ForegroundColor Yellow
        Install-WindowsFeature -Name "RSAT-AD-PowerShell" -IncludeAllSubFeature
    } elseif ($adModule) {
        Write-Host "Active Directory PowerShell module is already installed." -ForegroundColor Green
    } else {
        Write-Warning "Active Directory PowerShell module is not available on this system."
        Write-Host "This is normal for non-domain-joined or non-Windows Server systems." -ForegroundColor Yellow
    }
} catch {
    Write-Warning "Could not check/install Active Directory module: $($_.Exception.Message)"
}

# Create test directory structure
Write-Host "Creating test directory structure..." -ForegroundColor Yellow
$testDir = Join-Path $PSScriptRoot "Tests"
$testResultsDir = Join-Path $PSScriptRoot "TestResults"

if (-not (Test-Path $testDir)) {
    New-Item -ItemType Directory -Path $testDir -Force | Out-Null
    Write-Host "Created Tests directory: $testDir" -ForegroundColor Green
}

if (-not (Test-Path $testResultsDir)) {
    New-Item -ItemType Directory -Path $testResultsDir -Force | Out-Null
    Write-Host "Created TestResults directory: $testResultsDir" -ForegroundColor Green
}

# Verify installations
Write-Host "`nVerifying installations..." -ForegroundColor Yellow

$verificationResults = @()

foreach ($module in $requiredModules) {
    $installed = Get-Module -Name $module.Name -ListAvailable
    $status = if ($installed) { "✓ Installed" } else { "✗ Missing" }
    $verificationResults += [PSCustomObject]@{
        Module = $module.Name
        Status = $status
        Version = if ($installed) { $installed.Version } else { "N/A" }
    }
}

foreach ($module in $azureModules) {
    $installed = Get-Module -Name $module -ListAvailable
    $status = if ($installed) { "✓ Installed" } else { "✗ Missing" }
    $verificationResults += [PSCustomObject]@{
        Module = $module
        Status = $status
        Version = if ($installed) { $installed.Version } else { "N/A" }
    }
}

foreach ($module in $graphModules) {
    $installed = Get-Module -Name $module -ListAvailable
    $status = if ($installed) { "✓ Installed" } else { "✗ Missing" }
    $verificationResults += [PSCustomObject]@{
        Module = $module
        Status = $status
        Version = if ($installed) { $installed.Version } else { "N/A" }
    }
}

# Display verification results
$verificationResults | Format-Table -AutoSize

# Check for any missing modules
$missingModules = $verificationResults | Where-Object { $_.Status -eq "✗ Missing" }
if ($missingModules) {
    Write-Warning "Some modules failed to install:"
    $missingModules | Format-Table -AutoSize
} else {
    Write-Host "`nAll required modules are installed successfully!" -ForegroundColor Green
}

# Final setup instructions
Write-Host "`n=================== SETUP COMPLETE ===================" -ForegroundColor Green
Write-Host "Test environment is ready!" -ForegroundColor Green
Write-Host ""
Write-Host "To run tests, use the Test-Runner.ps1 script:" -ForegroundColor Yellow
Write-Host "  .\Test-Runner.ps1" -ForegroundColor Cyan
Write-Host ""
Write-Host "Available test commands:" -ForegroundColor Yellow
Write-Host "  Invoke-AllTests -Coverage          # Run all tests with coverage" -ForegroundColor Cyan
Write-Host "  Invoke-TestFile -TestFile 'Name'   # Run specific test file" -ForegroundColor Cyan
Write-Host "  New-TestReport                     # Generate HTML report" -ForegroundColor Cyan
Write-Host "=======================================================" -ForegroundColor Green

# Create a quick test to verify Pester is working
Write-Host "`nTesting Pester installation..." -ForegroundColor Yellow
try {
    $testResult = Invoke-Pester -Path $PSScriptRoot -Name "Quick-Pester-Test" -PassThru -Configuration @{
        Run = @{ 
            ScriptBlock = { 
                Describe "Quick Pester Test" { 
                    It "Should work" { 
                        $true | Should -Be $true 
                    } 
                } 
            } 
        }
        Output = @{ Verbosity = 'Minimal' }
    }
    
    if ($testResult.PassedCount -eq 1) {
        Write-Host "✓ Pester is working correctly!" -ForegroundColor Green
    } else {
        Write-Warning "Pester test failed. Please check the installation."
    }
} catch {
    Write-Warning "Could not run Pester test: $($_.Exception.Message)"
}
