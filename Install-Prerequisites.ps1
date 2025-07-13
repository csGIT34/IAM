# Prerequisites Installation Script
# Run this script as Administrator to install required PowerShell modules

# Check if running as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script must be run as Administrator"
    exit 1
}

Write-Host "Installing required PowerShell modules..." -ForegroundColor Green

# List of required modules
$requiredModules = @(
    "ActiveDirectory",
    "Microsoft.Graph.Authentication",
    "Microsoft.Graph.Users", 
    "Microsoft.Graph.Mail",
    "Microsoft.Graph.Reports",
    "Az.Accounts",
    "Az.Storage",
    "Az.KeyVault",
    "AzTable"
)

foreach ($module in $requiredModules) {
    try {
        Write-Host "Checking module: $module" -ForegroundColor Yellow
        
        if (Get-Module -ListAvailable -Name $module) {
            Write-Host "Module $module is already installed" -ForegroundColor Green
        }
        else {
            Write-Host "Installing module: $module" -ForegroundColor Yellow
            Install-Module -Name $module -Force -AllowClobber -Scope AllUsers
            Write-Host "Module $module installed successfully" -ForegroundColor Green
        }
    }
    catch {
        Write-Warning "Failed to install module $module : $($_.Exception.Message)"
    }
}

Write-Host "`nModule installation completed!" -ForegroundColor Green

# Additional setup instructions
Write-Host "`n=== ADDITIONAL SETUP REQUIRED ===" -ForegroundColor Yellow
Write-Host "1. Ensure the computer is joined to your Active Directory domain" -ForegroundColor Yellow
Write-Host "2. Run the script with an account that has:" -ForegroundColor Yellow
Write-Host "   - Active Directory administrative rights" -ForegroundColor Yellow
Write-Host "   - Microsoft Graph administrative rights (User.ReadWrite.All, Mail.Send, etc.)" -ForegroundColor Yellow
Write-Host "   - Access to your Azure Storage Account" -ForegroundColor Yellow
Write-Host "3. Configure a valid Microsoft 365 user account for sending emails" -ForegroundColor Yellow
Write-Host "4. Test the script thoroughly before production use" -ForegroundColor Yellow
Write-Host "5. Consider using an Azure App Registration with certificate authentication for production" -ForegroundColor Yellow
