#Requires -Modules Microsoft.Graph.Reports, Microsoft.Graph.Users

<#
.SYNOPSIS
    Generates bulk MFA registration status reports for multiple tenants or scheduled execution
.DESCRIPTION
    This script enables bulk MFA registration reporting across multiple tenants, automated scheduling,
    and comprehensive management of MFA compliance reporting at scale.
.PARAMETER ConfigPath
    Path to the configuration file containing tenant and reporting settings
.PARAMETER TenantIds
    Array of tenant IDs to generate reports for
.PARAMETER OutputDirectory
    Directory to store all generated reports
.PARAMETER EmailConfiguration
    Configuration for email notifications
.PARAMETER ScheduleType
    Type of scheduling (Daily, Weekly, Monthly)
.PARAMETER ComplianceThreshold
    Minimum MFA registration percentage for compliance
.PARAMETER GenerateConsolidatedReport
    Generate a consolidated report across all tenants
.PARAMETER ArchiveOldReports
    Archive reports older than specified days
.PARAMETER ArchiveAfterDays
    Number of days after which to archive reports
.EXAMPLE
    .\Start-BulkMFAReporting.ps1 -ConfigPath ".\config\reporting-config.json" -OutputDirectory "C:\Reports\MFA"
.EXAMPLE
    .\Start-BulkMFAReporting.ps1 -TenantIds @("tenant1", "tenant2") -OutputDirectory ".\Reports" -GenerateConsolidatedReport
.EXAMPLE
    .\Start-BulkMFAReporting.ps1 -ConfigPath ".\config\config.json" -ScheduleType Daily -ComplianceThreshold 95
.NOTES
    Author: GitHub Copilot
    Version: 1.0
    Requires: Microsoft.Graph.Reports, Microsoft.Graph.Users modules
    Permissions: Reports.Read.All, User.Read.All, UserAuthenticationMethod.Read.All
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ConfigPath = ".\config\reporting-config.json",
    
    [Parameter(Mandatory = $false)]
    [string[]]$TenantIds,
    
    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory,
    
    [Parameter(Mandatory = $false)]
    [hashtable]$EmailConfiguration,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet('Daily', 'Weekly', 'Monthly')]
    [string]$ScheduleType,
    
    [Parameter(Mandatory = $false)]
    [int]$ComplianceThreshold = 90,
    
    [Parameter(Mandatory = $false)]
    [switch]$GenerateConsolidatedReport,
    
    [Parameter(Mandatory = $false)]
    [switch]$ArchiveOldReports,
    
    [Parameter(Mandatory = $false)]
    [int]$ArchiveAfterDays = 30
)

# Initialize logging
$LogDirectory = Join-Path $OutputDirectory "logs"
$null = New-Item -Path $LogDirectory -ItemType Directory -Force -ErrorAction SilentlyContinue
$LogPath = Join-Path $LogDirectory "BulkMFAReporting_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

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

function Get-Configuration {
    param([string]$ConfigPath)
    
    try {
        if (Test-Path $ConfigPath) {
            Write-Log "Loading configuration from $ConfigPath"
            $config = Get-Content -Path $ConfigPath | ConvertFrom-Json
            return $config
        } else {
            Write-Log "Configuration file not found, using defaults" -Level Warning
            return $null
        }
    } catch {
        Write-Log "Failed to load configuration: $($_.Exception.Message)" -Level Error
        throw
    }
}

function Initialize-Environment {
    param([string]$OutputDirectory)
    
    try {
        Write-Log "Initializing environment..."
        
        # Create directory structure
        $directories = @(
            $OutputDirectory,
            (Join-Path $OutputDirectory "reports"),
            (Join-Path $OutputDirectory "logs"),
            (Join-Path $OutputDirectory "archive"),
            (Join-Path $OutputDirectory "config"),
            (Join-Path $OutputDirectory "temp")
        )
        
        foreach ($dir in $directories) {
            $null = New-Item -Path $dir -ItemType Directory -Force -ErrorAction SilentlyContinue
            Write-Log "Created directory: $dir"
        }
        
        # Check for required modules
        $requiredModules = @('Microsoft.Graph.Reports', 'Microsoft.Graph.Users', 'Microsoft.Graph.Authentication')
        foreach ($module in $requiredModules) {
            if (-not (Get-Module -ListAvailable -Name $module)) {
                Write-Log "Installing required module: $module"
                Install-Module -Name $module -Scope CurrentUser -Force
            }
        }
        
        Write-Log "Environment initialized successfully"
        
    } catch {
        Write-Log "Failed to initialize environment: $($_.Exception.Message)" -Level Error
        throw
    }
}

function Get-TenantConfiguration {
    param([object]$Config, [string[]]$TenantIds)
    
    try {
        $tenantConfigs = @()
        
        if ($Config -and $Config.tenants) {
            # Use configuration file tenants
            foreach ($tenant in $Config.tenants) {
                if (-not $TenantIds -or $tenant.id -in $TenantIds) {
                    $tenantConfigs += $tenant
                }
            }
        } elseif ($TenantIds) {
            # Use provided tenant IDs
            foreach ($tenantId in $TenantIds) {
                $tenantConfigs += @{
                    id = $tenantId
                    name = $tenantId
                    description = "Tenant $tenantId"
                }
            }
        } else {
            throw "No tenant configuration found"
        }
        
        Write-Log "Configured $($tenantConfigs.Count) tenants for reporting"
        return $tenantConfigs
        
    } catch {
        Write-Log "Failed to get tenant configuration: $($_.Exception.Message)" -Level Error
        throw
    }
}

function Test-TenantConnection {
    param([string]$TenantId)
    
    try {
        Write-Log "Testing connection to tenant: $TenantId"
        
        $connectParams = @{
            TenantId = $TenantId
            Scopes = @('Reports.Read.All', 'User.Read.All', 'UserAuthenticationMethod.Read.All')
            NoWelcome = $true
        }
        
        Connect-MgGraph @connectParams
        
        $context = Get-MgContext
        if ($context.TenantId -eq $TenantId) {
            Write-Log "Successfully connected to tenant: $TenantId"
            return $true
        } else {
            Write-Log "Failed to connect to tenant: $TenantId" -Level Error
            return $false
        }
        
    } catch {
        Write-Log "Error connecting to tenant $TenantId`: $($_.Exception.Message)" -Level Error
        return $false
    }
}

function Invoke-TenantMFAReport {
    param(
        [object]$TenantConfig,
        [string]$OutputDirectory,
        [object]$ReportConfig
    )
    
    try {
        Write-Log "Generating MFA report for tenant: $($TenantConfig.name)"
        
        # Test connection
        if (-not (Test-TenantConnection -TenantId $TenantConfig.id)) {
            throw "Failed to connect to tenant: $($TenantConfig.id)"
        }
        
        # Prepare report parameters
        $reportDate = Get-Date -Format 'yyyyMMdd_HHmmss'
        $tenantReportDir = Join-Path $OutputDirectory "reports\$($TenantConfig.id)"
        $null = New-Item -Path $tenantReportDir -ItemType Directory -Force -ErrorAction SilentlyContinue
        
        # Generate reports in multiple formats
        $reportFiles = @()
        
        # HTML Report
        $htmlPath = Join-Path $tenantReportDir "MFA-Report-$($TenantConfig.id)-$reportDate.html"
        $scriptPath = Join-Path $PSScriptRoot "Get-MFARegistrationStatus.ps1"
        
        $reportParams = @{
            TenantId = $TenantConfig.id
            OutputFormat = 'HTML'
            ExportPath = $htmlPath
            IncludeAuthMethods = $true
            GenerateRecommendations = $true
        }
        
        # Add configuration-specific parameters
        if ($ReportConfig) {
            if ($ReportConfig.includeDisabledUsers) {
                $reportParams.IncludeDisabledUsers = $true
            }
            if ($ReportConfig.filterByDepartment) {
                $reportParams.FilterByDepartment = $ReportConfig.filterByDepartment
            }
            if ($ReportConfig.filterByLicenseStatus) {
                $reportParams.FilterByLicenseStatus = $ReportConfig.filterByLicenseStatus
            }
        }
        
        & $scriptPath @reportParams
        
        if (Test-Path $htmlPath) {
            $reportFiles += $htmlPath
            Write-Log "HTML report generated: $htmlPath"
        }
        
        # CSV Report
        $csvPath = Join-Path $tenantReportDir "MFA-Report-$($TenantConfig.id)-$reportDate.csv"
        $reportParams.OutputFormat = 'CSV'
        $reportParams.ExportPath = $csvPath
        
        & $scriptPath @reportParams
        
        if (Test-Path $csvPath) {
            $reportFiles += $csvPath
            Write-Log "CSV report generated: $csvPath"
        }
        
        # JSON Report
        $jsonPath = Join-Path $tenantReportDir "MFA-Report-$($TenantConfig.id)-$reportDate.json"
        $reportParams.OutputFormat = 'JSON'
        $reportParams.ExportPath = $jsonPath
        
        & $scriptPath @reportParams
        
        if (Test-Path $jsonPath) {
            $reportFiles += $jsonPath
            Write-Log "JSON report generated: $jsonPath"
        }
        
        # Analyze compliance
        $complianceStatus = Test-TenantCompliance -JsonReportPath $jsonPath -Threshold $ComplianceThreshold
        
        $result = @{
            TenantId = $TenantConfig.id
            TenantName = $TenantConfig.name
            ReportFiles = $reportFiles
            ComplianceStatus = $complianceStatus
            GeneratedAt = Get-Date
            Success = $true
        }
        
        Write-Log "MFA report completed for tenant: $($TenantConfig.name)"
        return $result
        
    } catch {
        Write-Log "Failed to generate MFA report for tenant $($TenantConfig.name): $($_.Exception.Message)" -Level Error
        
        return @{
            TenantId = $TenantConfig.id
            TenantName = $TenantConfig.name
            ReportFiles = @()
            ComplianceStatus = $null
            GeneratedAt = Get-Date
            Success = $false
            Error = $_.Exception.Message
        }
    } finally {
        # Disconnect from Graph
        try {
            Disconnect-MgGraph -ErrorAction SilentlyContinue
        } catch {
            Write-Log "Failed to disconnect from Graph: $($_.Exception.Message)" -Level Warning
        }
    }
}

function Test-TenantCompliance {
    param([string]$JsonReportPath, [int]$Threshold)
    
    try {
        if (-not (Test-Path $JsonReportPath)) {
            return $null
        }
        
        $reportData = Get-Content -Path $JsonReportPath | ConvertFrom-Json
        
        $totalUsers = $reportData.Statistics.TotalUsers
        $registeredUsers = $reportData.Statistics.MFARegistered
        $registrationRate = if ($totalUsers -gt 0) { ($registeredUsers / $totalUsers) * 100 } else { 0 }
        
        $complianceStatus = @{
            TotalUsers = $totalUsers
            RegisteredUsers = $registeredUsers
            RegistrationRate = [math]::Round($registrationRate, 2)
            ComplianceThreshold = $Threshold
            IsCompliant = $registrationRate -ge $Threshold
            RiskLevel = if ($registrationRate -ge 90) { 'Low' } elseif ($registrationRate -ge 75) { 'Medium' } else { 'High' }
        }
        
        return $complianceStatus
        
    } catch {
        Write-Log "Failed to analyze compliance: $($_.Exception.Message)" -Level Error
        return $null
    }
}

function New-ConsolidatedReport {
    param([object[]]$TenantResults, [string]$OutputDirectory)
    
    try {
        Write-Log "Generating consolidated report..."
        
        $consolidatedData = @{
            GeneratedAt = Get-Date
            TotalTenants = $TenantResults.Count
            SuccessfulReports = ($TenantResults | Where-Object { $_.Success }).Count
            FailedReports = ($TenantResults | Where-Object { -not $_.Success }).Count
            TenantSummary = @()
            OverallCompliance = @{
                TotalUsers = 0
                RegisteredUsers = 0
                ComplianceTenants = 0
                NonComplianceTenants = 0
            }
        }
        
        foreach ($result in $TenantResults) {
            $tenantSummary = @{
                TenantId = $result.TenantId
                TenantName = $result.TenantName
                Success = $result.Success
                GeneratedAt = $result.GeneratedAt
            }
            
            if ($result.Success -and $result.ComplianceStatus) {
                $compliance = $result.ComplianceStatus
                $tenantSummary.TotalUsers = $compliance.TotalUsers
                $tenantSummary.RegisteredUsers = $compliance.RegisteredUsers
                $tenantSummary.RegistrationRate = $compliance.RegistrationRate
                $tenantSummary.IsCompliant = $compliance.IsCompliant
                $tenantSummary.RiskLevel = $compliance.RiskLevel
                
                # Update overall compliance
                $consolidatedData.OverallCompliance.TotalUsers += $compliance.TotalUsers
                $consolidatedData.OverallCompliance.RegisteredUsers += $compliance.RegisteredUsers
                
                if ($compliance.IsCompliant) {
                    $consolidatedData.OverallCompliance.ComplianceTenants++
                } else {
                    $consolidatedData.OverallCompliance.NonComplianceTenants++
                }
            } else {
                $tenantSummary.Error = $result.Error
            }
            
            $consolidatedData.TenantSummary += $tenantSummary
        }
        
        # Calculate overall registration rate
        if ($consolidatedData.OverallCompliance.TotalUsers -gt 0) {
            $consolidatedData.OverallCompliance.RegistrationRate = [math]::Round(
                ($consolidatedData.OverallCompliance.RegisteredUsers / $consolidatedData.OverallCompliance.TotalUsers) * 100, 2
            )
        } else {
            $consolidatedData.OverallCompliance.RegistrationRate = 0
        }
        
        # Export consolidated report
        $reportDate = Get-Date -Format 'yyyyMMdd_HHmmss'
        $consolidatedPath = Join-Path $OutputDirectory "reports\Consolidated-MFA-Report-$reportDate.json"
        $consolidatedData | ConvertTo-Json -Depth 10 | Out-File -FilePath $consolidatedPath -Encoding UTF8
        
        # Generate HTML dashboard
        $dashboardPath = Join-Path $OutputDirectory "reports\MFA-Dashboard-$reportDate.html"
        $dashboardHtml = New-ConsolidatedHTML -Data $consolidatedData
        $dashboardHtml | Out-File -FilePath $dashboardPath -Encoding UTF8
        
        Write-Log "Consolidated report generated: $consolidatedPath"
        Write-Log "Dashboard generated: $dashboardPath"
        
        return @{
            ConsolidatedReport = $consolidatedPath
            Dashboard = $dashboardPath
            Data = $consolidatedData
        }
        
    } catch {
        Write-Log "Failed to generate consolidated report: $($_.Exception.Message)" -Level Error
        throw
    }
}

function New-ConsolidatedHTML {
    param([object]$Data)
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>MFA Registration Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .header { background-color: #0078d4; color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
        .summary { background-color: white; padding: 20px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; }
        .stats { display: flex; flex-wrap: wrap; gap: 20px; margin: 20px 0; }
        .stat-box { background-color: white; padding: 20px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); min-width: 200px; text-align: center; }
        .stat-value { font-size: 36px; font-weight: bold; color: #0078d4; }
        .stat-label { font-size: 14px; color: #666; margin-top: 5px; }
        .tenant-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 20px; margin: 20px 0; }
        .tenant-card { background-color: white; padding: 20px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .tenant-header { font-size: 18px; font-weight: bold; margin-bottom: 10px; }
        .compliance-badge { padding: 5px 10px; border-radius: 3px; font-size: 12px; font-weight: bold; }
        .compliant { background-color: #d4edda; color: #155724; }
        .non-compliant { background-color: #f8d7da; color: #721c24; }
        .risk-low { color: #28a745; }
        .risk-medium { color: #ffc107; }
        .risk-high { color: #dc3545; }
        .progress-bar { width: 100%; height: 20px; background-color: #e9ecef; border-radius: 10px; margin: 10px 0; }
        .progress-fill { height: 100%; background-color: #0078d4; border-radius: 10px; transition: width 0.3s ease; }
        .error { color: #dc3545; font-style: italic; }
    </style>
</head>
<body>
    <div class="header">
        <h1>MFA Registration Dashboard</h1>
        <p>Generated: $($Data.GeneratedAt.ToString('yyyy-MM-dd HH:mm:ss'))</p>
        <p>Total Tenants: $($Data.TotalTenants) | Successful: $($Data.SuccessfulReports) | Failed: $($Data.FailedReports)</p>
    </div>
    
    <div class="summary">
        <h2>Overall Summary</h2>
        <div class="stats">
            <div class="stat-box">
                <div class="stat-value">$($Data.OverallCompliance.TotalUsers)</div>
                <div class="stat-label">Total Users</div>
            </div>
            <div class="stat-box">
                <div class="stat-value">$($Data.OverallCompliance.RegisteredUsers)</div>
                <div class="stat-label">Registered Users</div>
            </div>
            <div class="stat-box">
                <div class="stat-value">$($Data.OverallCompliance.RegistrationRate)%</div>
                <div class="stat-label">Registration Rate</div>
            </div>
            <div class="stat-box">
                <div class="stat-value">$($Data.OverallCompliance.ComplianceTenants)</div>
                <div class="stat-label">Compliant Tenants</div>
            </div>
            <div class="stat-box">
                <div class="stat-value">$($Data.OverallCompliance.NonComplianceTenants)</div>
                <div class="stat-label">Non-Compliant Tenants</div>
            </div>
        </div>
    </div>
    
    <div class="summary">
        <h2>Tenant Details</h2>
        <div class="tenant-grid">
"@
    
    foreach ($tenant in $Data.TenantSummary) {
        if ($tenant.Success) {
            $complianceClass = if ($tenant.IsCompliant) { 'compliant' } else { 'non-compliant' }
            $complianceText = if ($tenant.IsCompliant) { 'Compliant' } else { 'Non-Compliant' }
            $riskClass = "risk-$($tenant.RiskLevel.ToLower())"
            
            $html += @"
            <div class="tenant-card">
                <div class="tenant-header">$($tenant.TenantName)</div>
                <p><strong>Tenant ID:</strong> $($tenant.TenantId)</p>
                <p><strong>Total Users:</strong> $($tenant.TotalUsers)</p>
                <p><strong>Registered:</strong> $($tenant.RegisteredUsers)</p>
                <div class="progress-bar">
                    <div class="progress-fill" style="width: $($tenant.RegistrationRate)%"></div>
                </div>
                <p><strong>Registration Rate:</strong> $($tenant.RegistrationRate)%</p>
                <p><strong>Compliance:</strong> <span class="compliance-badge $complianceClass">$complianceText</span></p>
                <p><strong>Risk Level:</strong> <span class="$riskClass">$($tenant.RiskLevel)</span></p>
                <p><strong>Generated:</strong> $($tenant.GeneratedAt.ToString('yyyy-MM-dd HH:mm:ss'))</p>
            </div>
"@
        } else {
            $html += @"
            <div class="tenant-card">
                <div class="tenant-header">$($tenant.TenantName)</div>
                <p><strong>Tenant ID:</strong> $($tenant.TenantId)</p>
                <p class="error">Report Generation Failed</p>
                <p class="error">Error: $($tenant.Error)</p>
                <p><strong>Attempted:</strong> $($tenant.GeneratedAt.ToString('yyyy-MM-dd HH:mm:ss'))</p>
            </div>
"@
        }
    }
    
    $html += @"
        </div>
    </div>
</body>
</html>
"@
    
    return $html
}

function Send-ConsolidatedReport {
    param([object]$ConsolidatedResult, [object]$EmailConfig)
    
    if (-not $EmailConfig) {
        return
    }
    
    try {
        Write-Log "Sending consolidated report via email..."
        
        $subject = "MFA Registration Dashboard - $(Get-Date -Format 'yyyy-MM-dd')"
        $body = @"
MFA Registration Dashboard Summary

Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

Overall Statistics:
- Total Tenants: $($ConsolidatedResult.Data.TotalTenants)
- Successful Reports: $($ConsolidatedResult.Data.SuccessfulReports)
- Failed Reports: $($ConsolidatedResult.Data.FailedReports)
- Total Users: $($ConsolidatedResult.Data.OverallCompliance.TotalUsers)
- Registered Users: $($ConsolidatedResult.Data.OverallCompliance.RegisteredUsers)
- Registration Rate: $($ConsolidatedResult.Data.OverallCompliance.RegistrationRate)%
- Compliant Tenants: $($ConsolidatedResult.Data.OverallCompliance.ComplianceTenants)
- Non-Compliant Tenants: $($ConsolidatedResult.Data.OverallCompliance.NonComplianceTenants)

Please find the detailed dashboard attached.
"@
        
        # Log email details (actual sending would require email configuration)
        Write-Log "Email prepared for: $($EmailConfig.recipients -join ', ')"
        Write-Log "Subject: $subject"
        Write-Log "Body: $body"
        Write-Log "Attachments: $($ConsolidatedResult.Dashboard), $($ConsolidatedResult.ConsolidatedReport)"
        
        # TODO: Implement actual email sending
        # Send-MailMessage or Send-MgUserMessage based on configuration
        
    } catch {
        Write-Log "Failed to send consolidated report: $($_.Exception.Message)" -Level Error
    }
}

function Invoke-ReportArchival {
    param([string]$OutputDirectory, [int]$ArchiveAfterDays)
    
    if (-not $ArchiveOldReports) {
        return
    }
    
    try {
        Write-Log "Archiving old reports..."
        
        $reportsDir = Join-Path $OutputDirectory "reports"
        $archiveDir = Join-Path $OutputDirectory "archive"
        $cutoffDate = (Get-Date).AddDays(-$ArchiveAfterDays)
        
        $oldFiles = Get-ChildItem -Path $reportsDir -Recurse -File | Where-Object { $_.CreationTime -lt $cutoffDate }
        
        foreach ($file in $oldFiles) {
            $relativePath = $file.FullName.Substring($reportsDir.Length + 1)
            $archivePath = Join-Path $archiveDir $relativePath
            
            $archiveSubDir = Split-Path $archivePath -Parent
            $null = New-Item -Path $archiveSubDir -ItemType Directory -Force -ErrorAction SilentlyContinue
            
            Move-Item -Path $file.FullName -Destination $archivePath -Force
            Write-Log "Archived: $($file.Name)"
        }
        
        Write-Log "Archived $($oldFiles.Count) old files"
        
    } catch {
        Write-Log "Failed to archive old reports: $($_.Exception.Message)" -Level Error
    }
}

# Main execution
try {
    Write-Log "Starting bulk MFA registration reporting..."
    
    # Initialize environment
    Initialize-Environment -OutputDirectory $OutputDirectory
    
    # Load configuration
    $config = Get-Configuration -ConfigPath $ConfigPath
    
    # Get tenant configuration
    $tenantConfigs = Get-TenantConfiguration -Config $config -TenantIds $TenantIds
    
    if ($tenantConfigs.Count -eq 0) {
        throw "No tenants configured for reporting"
    }
    
    # Generate reports for each tenant
    $tenantResults = @()
    foreach ($tenantConfig in $tenantConfigs) {
        $result = Invoke-TenantMFAReport -TenantConfig $tenantConfig -OutputDirectory $OutputDirectory -ReportConfig $config.reportSettings
        $tenantResults += $result
    }
    
    # Generate consolidated report if requested
    if ($GenerateConsolidatedReport) {
        $consolidatedResult = New-ConsolidatedReport -TenantResults $tenantResults -OutputDirectory $OutputDirectory
        
        # Send email if configured
        if ($config.emailConfiguration -or $EmailConfiguration) {
            $emailConfig = $EmailConfiguration -or $config.emailConfiguration
            Send-ConsolidatedReport -ConsolidatedResult $consolidatedResult -EmailConfig $emailConfig
        }
    }
    
    # Archive old reports if requested
    if ($ArchiveOldReports) {
        Invoke-ReportArchival -OutputDirectory $OutputDirectory -ArchiveAfterDays $ArchiveAfterDays
    }
    
    # Summary
    $successCount = ($tenantResults | Where-Object { $_.Success }).Count
    $failureCount = ($tenantResults | Where-Object { -not $_.Success }).Count
    
    Write-Log "Bulk MFA reporting completed successfully"
    Write-Log "Total tenants: $($tenantResults.Count)"
    Write-Log "Successful reports: $successCount"
    Write-Log "Failed reports: $failureCount"
    
    if ($failureCount -gt 0) {
        Write-Log "Some reports failed - check individual tenant logs for details" -Level Warning
    }
    
} catch {
    Write-Log "Bulk MFA reporting failed: $($_.Exception.Message)" -Level Error
    Write-Log "Stack trace: $($_.Exception.StackTrace)" -Level Error
    throw
}
