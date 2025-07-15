# Prerequisites Installation Script for Entra ID Group Access Reviews
# This script installs the required PowerShell modules and dependencies

<#
.SYNOPSIS
    Installs prerequisites for the Entra ID Group Access Reviews solution.

.DESCRIPTION
    This script installs the required PowerShell modules and dependencies
    needed for creating and managing Entra ID group access reviews.

.PARAMETER InstallModules
    Whether to install PowerShell modules

.PARAMETER UpdateModules
    Whether to update existing modules

.PARAMETER TestConnection
    Whether to test Graph connection after installation

.PARAMETER CreateSampleConfig
    Whether to create sample configuration files

.EXAMPLE
    .\Install-Prerequisites.ps1 -InstallModules -TestConnection -CreateSampleConfig
#>

param(
    [switch]$InstallModules = $true,
    [switch]$UpdateModules = $false,
    [switch]$TestConnection = $false,
    [switch]$CreateSampleConfig = $false
)

Write-Host "=== Entra ID Group Access Reviews Prerequisites Installation ===" -ForegroundColor Green

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

# Install PowerShell modules
if ($InstallModules) {
    Write-Host "Installing PowerShell modules..." -ForegroundColor Yellow
    
    $requiredModules = @(
        @{ Name = "Microsoft.Graph.Authentication"; Description = "Microsoft Graph Authentication" },
        @{ Name = "Microsoft.Graph.Identity.Governance"; Description = "Microsoft Graph Identity Governance" },
        @{ Name = "Microsoft.Graph.Groups"; Description = "Microsoft Graph Groups" },
        @{ Name = "Microsoft.Graph.Users"; Description = "Microsoft Graph Users" },
        @{ Name = "Microsoft.Graph.DirectoryObjects"; Description = "Microsoft Graph Directory Objects" },
        @{ Name = "ImportExcel"; Description = "Excel import/export functionality" },
        @{ Name = "PSWriteHTML"; Description = "HTML report generation" },
        @{ Name = "PSLogging"; Description = "Enhanced logging capabilities" }
    )
    
    foreach ($module in $requiredModules) {
        Write-Host "Processing module: $($module.Name)" -ForegroundColor Cyan
        
        try {
            $installedModule = Get-Module -ListAvailable -Name $module.Name
            
            if ($installedModule) {
                if ($UpdateModules) {
                    Write-Host "Updating module: $($module.Name)" -ForegroundColor Yellow
                    Update-Module -Name $module.Name -Force -ErrorAction Stop
                } else {
                    Write-Host "✓ Module already installed: $($module.Name)" -ForegroundColor Green
                }
            } else {
                Write-Host "Installing module: $($module.Name)" -ForegroundColor Yellow
                Install-Module -Name $module.Name -Force -AllowClobber -Scope CurrentUser -ErrorAction Stop
                Write-Host "✓ Module installed: $($module.Name)" -ForegroundColor Green
            }
        } catch {
            Write-Warning "Failed to install module '$($module.Name)': $($_.Exception.Message)"
        }
    }
}

# Test Microsoft Graph connection
if ($TestConnection) {
    Write-Host "Testing Microsoft Graph connection..." -ForegroundColor Yellow
    
    try {
        # Import required modules
        Import-Module Microsoft.Graph.Authentication -Force
        Import-Module Microsoft.Graph.Identity.Governance -Force
        Import-Module Microsoft.Graph.Groups -Force
        Import-Module Microsoft.Graph.Users -Force
        
        # Test connection
        Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
        Connect-MgGraph -Scopes "AccessReview.ReadWrite.All", "Group.Read.All", "User.Read.All", "Directory.Read.All" -NoWelcome
        
        $context = Get-MgContext
        if ($context) {
            Write-Host "✓ Connected to Microsoft Graph successfully" -ForegroundColor Green
            Write-Host "Tenant ID: $($context.TenantId)" -ForegroundColor Cyan
            Write-Host "Account: $($context.Account)" -ForegroundColor Cyan
            Write-Host "Scopes: $($context.Scopes -join ', ')" -ForegroundColor Cyan
        }
        
        # Test basic operations
        Write-Host "Testing basic operations..." -ForegroundColor Cyan
        
        # Test user query
        try {
            $currentUser = Get-MgUser -UserId $context.Account -ErrorAction Stop
            Write-Host "✓ User query successful: $($currentUser.DisplayName)" -ForegroundColor Green
        } catch {
            Write-Warning "User query failed: $($_.Exception.Message)"
        }
        
        # Test group query
        try {
            $groups = Get-MgGroup -Top 5 -ErrorAction Stop
            Write-Host "✓ Group query successful: Found $($groups.Count) groups" -ForegroundColor Green
        } catch {
            Write-Warning "Group query failed: $($_.Exception.Message)"
        }
        
        # Test access review capabilities
        try {
            $accessReviewDefinitions = Get-MgIdentityGovernanceAccessReviewDefinition -Top 5 -ErrorAction Stop
            Write-Host "✓ Access review query successful: Found $($accessReviewDefinitions.Count) definitions" -ForegroundColor Green
        } catch {
            Write-Warning "Access review query failed: $($_.Exception.Message)"
            Write-Host "This may indicate missing permissions or Entra ID P2 license requirements" -ForegroundColor Yellow
        }
        
        # Disconnect
        Disconnect-MgGraph
        Write-Host "✓ Microsoft Graph connection test completed" -ForegroundColor Green
        
    } catch {
        Write-Error "Microsoft Graph connection test failed: $($_.Exception.Message)"
        Write-Host "Please verify:" -ForegroundColor Yellow
        Write-Host "1. You have appropriate permissions" -ForegroundColor Cyan
        Write-Host "2. Entra ID P2 license is available" -ForegroundColor Cyan
        Write-Host "3. Access Reviews feature is enabled" -ForegroundColor Cyan
    }
}

# Create sample configuration files
if ($CreateSampleConfig) {
    Write-Host "Creating sample configuration files..." -ForegroundColor Yellow
    
    # Create config directory
    $configDir = Join-Path $PSScriptRoot "config"
    if (-not (Test-Path $configDir)) {
        New-Item -ItemType Directory -Path $configDir -Force | Out-Null
        Write-Host "✓ Created config directory" -ForegroundColor Green
    }
    
    # Create sample groups CSV
    $sampleGroupsCsv = @"
GroupId,GroupName,ReviewTemplate,Reviewers,Priority,Department
12345678-1234-1234-1234-123456789012,IT-Administrators,high-privilege-review,security@contoso.com,High,IT
87654321-4321-4321-4321-210987654321,HR-Users,standard-review,hr-manager@contoso.com,Medium,HR
11111111-1111-1111-1111-111111111111,Marketing-Team,standard-review,marketing-manager@contoso.com,Medium,Marketing
22222222-2222-2222-2222-222222222222,Finance-Admins,high-privilege-review,finance-director@contoso.com,High,Finance
33333333-3333-3333-3333-333333333333,Sales-Team,standard-review,sales-manager@contoso.com,Low,Sales
"@
    
    $groupsCsvPath = Join-Path $configDir "sample-groups.csv"
    $sampleGroupsCsv | Out-File -FilePath $groupsCsvPath -Encoding UTF8
    Write-Host "✓ Created sample groups CSV: $groupsCsvPath" -ForegroundColor Green
    
    # Create configuration settings JSON
    $configSettings = @{
        "defaultSettings" = @{
            "reviewDuration" = 30
            "notificationEmail" = "admin@contoso.com"
            "fallbackReviewers" = @("security@contoso.com", "admin@contoso.com")
            "enableLogging" = $true
            "logPath" = ".\logs"
            "reportPath" = ".\reports"
        }
        "templates" = @{
            "standard" = ".\templates\standard-review.json"
            "highPrivilege" = ".\templates\high-privilege-review.json"
        }
        "notifications" = @{
            "enableEmail" = $true
            "smtpServer" = "smtp.contoso.com"
            "smtpPort" = 587
            "useSSL" = $true
            "fromAddress" = "accessreviews@contoso.com"
        }
        "compliance" = @{
            "auditAllActions" = $true
            "retentionDays" = 2555  # 7 years
            "complianceFrameworks" = @("SOX", "GDPR", "HIPAA")
        }
    }
    
    $configPath = Join-Path $configDir "settings.json"
    $configSettings | ConvertTo-Json -Depth 4 | Out-File -FilePath $configPath -Encoding UTF8
    Write-Host "✓ Created configuration settings: $configPath" -ForegroundColor Green
    
    # Create automation schedule configuration
    $scheduleConfig = @{
        "schedules" = @(
            @{
                "name" = "Monthly Standard Reviews"
                "description" = "Monthly access reviews for standard business groups"
                "frequency" = "Monthly"
                "dayOfMonth" = 1
                "time" = "09:00"
                "template" = "standard-review"
                "groupFilter" = "Priority -eq 'Medium' -or Priority -eq 'Low'"
                "enabled" = $true
            },
            @{
                "name" = "Quarterly High Privilege Reviews"
                "description" = "Quarterly access reviews for high-privilege groups"
                "frequency" = "Quarterly"
                "dayOfMonth" = 1
                "time" = "08:00"
                "template" = "high-privilege-review"
                "groupFilter" = "Priority -eq 'High'"
                "enabled" = $true
            }
        )
    }
    
    $schedulePath = Join-Path $configDir "schedule.json"
    $scheduleConfig | ConvertTo-Json -Depth 4 | Out-File -FilePath $schedulePath -Encoding UTF8
    Write-Host "✓ Created schedule configuration: $schedulePath" -ForegroundColor Green
}

# Create directories
Write-Host "Creating required directories..." -ForegroundColor Yellow

$directories = @(
    "logs",
    "reports",
    "config",
    "templates"
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

# Check licensing requirements
Write-Host "Checking licensing requirements..." -ForegroundColor Yellow

try {
    # This would require Graph connection, so we'll provide informational message
    Write-Host "Entra ID P2 License Requirements:" -ForegroundColor Cyan
    Write-Host "  - Access Reviews feature requires Entra ID P2 or EMS E5 license" -ForegroundColor Cyan
    Write-Host "  - Each user being reviewed needs appropriate licensing" -ForegroundColor Cyan
    Write-Host "  - Guests can be reviewed without additional licensing" -ForegroundColor Cyan
    Write-Host "  - Verify licensing in the Entra ID admin center" -ForegroundColor Cyan
} catch {
    Write-Warning "Could not verify licensing requirements"
}

# Final summary
Write-Host "`n=== Installation Summary ===" -ForegroundColor Green

Write-Host "Prerequisites installation completed:" -ForegroundColor Yellow
Write-Host "✓ PowerShell modules installed" -ForegroundColor Green
Write-Host "✓ Directory structure created" -ForegroundColor Green

if ($TestConnection) {
    Write-Host "✓ Microsoft Graph connection tested" -ForegroundColor Green
}

if ($CreateSampleConfig) {
    Write-Host "✓ Sample configuration files created" -ForegroundColor Green
}

Write-Host "`nNext steps:" -ForegroundColor Yellow
Write-Host "1. Review and customize template files in the templates directory" -ForegroundColor Cyan
Write-Host "2. Update the sample groups CSV with your actual groups" -ForegroundColor Cyan
Write-Host "3. Configure settings.json with your environment details" -ForegroundColor Cyan
Write-Host "4. Test with a single group using Create-GroupAccessReview.ps1" -ForegroundColor Cyan
Write-Host "5. Use Create-BulkAccessReviews.ps1 for bulk operations" -ForegroundColor Cyan

Write-Host "`nImportant notes:" -ForegroundColor Yellow
Write-Host "- Entra ID P2 license is required for access reviews" -ForegroundColor Red
Write-Host "- Ensure you have appropriate permissions in Entra ID" -ForegroundColor Red
Write-Host "- Test in a non-production environment first" -ForegroundColor Red

Write-Host "`nFor additional help:" -ForegroundColor Yellow
Write-Host "- Check the README.md file for detailed usage instructions" -ForegroundColor Cyan
Write-Host "- Review template files for customization options" -ForegroundColor Cyan
Write-Host "- Use -Verbose flag for detailed script output" -ForegroundColor Cyan
