#Requires -Modules Microsoft.Graph.Users, Microsoft.Graph.Authentication

<#
.SYNOPSIS
    Bulk verification of user termination status across multiple SAP SuccessFactors companies
.DESCRIPTION
    This script enables bulk processing of termination verification across multiple SAP SuccessFactors
    companies, automated scheduling, and comprehensive compliance reporting at enterprise scale.
.PARAMETER ConfigPath
    Path to the configuration file containing company and processing settings
.PARAMETER CompanyIds
    Array of company IDs to process
.PARAMETER OutputDirectory
    Directory to store all generated reports
.PARAMETER GenerateConsolidatedReport
    Generate a consolidated report across all companies
.PARAMETER AutoRemediate
    Automatically remediate non-compliant users
.PARAMETER DryRun
    Perform a dry run without making actual changes
.PARAMETER NotificationSettings
    Configuration for email notifications
.PARAMETER ScheduleType
    Type of scheduling (Daily, Weekly, Monthly)
.PARAMETER ComplianceThreshold
    Minimum compliance percentage threshold
.PARAMETER ArchiveOldReports
    Archive reports older than specified days
.EXAMPLE
    .\Start-BulkTerminationVerification.ps1 -ConfigPath ".\config\verification-config.json" -OutputDirectory "C:\Reports\Terminations"
.EXAMPLE
    .\Start-BulkTerminationVerification.ps1 -CompanyIds @("COMP1", "COMP2") -OutputDirectory ".\Reports" -GenerateConsolidatedReport
.EXAMPLE
    .\Start-BulkTerminationVerification.ps1 -ConfigPath ".\config\config.json" -AutoRemediate -DryRun -ComplianceThreshold 95
.NOTES
    Author: GitHub Copilot
    Version: 1.0
    Requires: Microsoft.Graph.Users, Microsoft.Graph.Authentication modules
    Dependencies: SAP SuccessFactors OData API access
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ConfigPath = ".\config\verification-config.json",
    
    [Parameter(Mandatory = $false)]
    [string[]]$CompanyIds,
    
    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory,
    
    [Parameter(Mandatory = $false)]
    [switch]$GenerateConsolidatedReport,
    
    [Parameter(Mandatory = $false)]
    [switch]$AutoRemediate,
    
    [Parameter(Mandatory = $false)]
    [switch]$DryRun,
    
    [Parameter(Mandatory = $false)]
    [hashtable]$NotificationSettings,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet('Daily', 'Weekly', 'Monthly')]
    [string]$ScheduleType,
    
    [Parameter(Mandatory = $false)]
    [int]$ComplianceThreshold = 95,
    
    [Parameter(Mandatory = $false)]
    [switch]$ArchiveOldReports,
    
    [Parameter(Mandatory = $false)]
    [int]$ArchiveAfterDays = 30
)

# Initialize logging
$LogDirectory = Join-Path $OutputDirectory "logs"
$null = New-Item -Path $LogDirectory -ItemType Directory -Force -ErrorAction SilentlyContinue
$LogPath = Join-Path $LogDirectory "BulkTerminationVerification_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

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

function Get-VerificationConfiguration {
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

function Initialize-BulkEnvironment {
    param([string]$OutputDirectory)
    
    try {
        Write-Log "Initializing bulk processing environment..."
        
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
        $requiredModules = @('Microsoft.Graph.Users', 'Microsoft.Graph.Authentication')
        foreach ($module in $requiredModules) {
            if (-not (Get-Module -ListAvailable -Name $module)) {
                Write-Log "Installing required module: $module"
                Install-Module -Name $module -Scope CurrentUser -Force
            }
        }
        
        Write-Log "Bulk processing environment initialized successfully"
        
    } catch {
        Write-Log "Failed to initialize environment: $($_.Exception.Message)" -Level Error
        throw
    }
}

function Get-CompanyConfiguration {
    param([object]$Config, [string[]]$CompanyIds)
    
    try {
        $companyConfigs = @()
        
        if ($Config -and $Config.companies) {
            # Use configuration file companies
            foreach ($company in $Config.companies) {
                if (-not $CompanyIds -or $company.id -in $CompanyIds) {
                    $companyConfigs += $company
                }
            }
        } elseif ($CompanyIds) {
            # Use provided company IDs
            foreach ($companyId in $CompanyIds) {
                $companyConfigs += @{
                    id = $companyId
                    name = $companyId
                    description = "Company $companyId"
                    endpoint = $Config.successFactors.endpoint
                    clientId = $Config.successFactors.clientId
                    clientSecret = $Config.successFactors.clientSecret
                }
            }
        } else {
            throw "No company configuration found"
        }
        
        Write-Log "Configured $($companyConfigs.Count) companies for verification"
        return $companyConfigs
        
    } catch {
        Write-Log "Failed to get company configuration: $($_.Exception.Message)" -Level Error
        throw
    }
}

function Test-CompanyConnection {
    param([object]$CompanyConfig)
    
    try {
        Write-Log "Testing connection to company: $($CompanyConfig.name)"
        
        # Create authentication header
        $authString = "$($CompanyConfig.clientId):$($CompanyConfig.clientSecret)"
        $encodedAuth = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($authString))
        
        $headers = @{
            'Authorization' = "Basic $encodedAuth"
            'Content-Type' = 'application/json'
            'Accept' = 'application/json'
        }
        
        # Test connection
        $testUrl = "$($CompanyConfig.endpoint)/$($CompanyConfig.id)/User?`$select=userId,username,status&`$top=1"
        $null = Invoke-RestMethod -Uri $testUrl -Headers $headers -Method Get -ErrorAction Stop
        
        Write-Log "Successfully connected to company: $($CompanyConfig.name)"
        return $true
        
    } catch {
        Write-Log "Failed to connect to company $($CompanyConfig.name): $($_.Exception.Message)" -Level Error
        return $false
    }
}

function Invoke-CompanyVerification {
    param(
        [object]$CompanyConfig,
        [string]$OutputDirectory,
        [object]$ProcessingConfig
    )
    
    try {
        Write-Log "Starting verification for company: $($CompanyConfig.name)"
        
        # Test connection
        if (-not (Test-CompanyConnection -CompanyConfig $CompanyConfig)) {
            throw "Failed to connect to company: $($CompanyConfig.name)"
        }
        
        # Prepare verification parameters
        $verificationDate = Get-Date -Format 'yyyyMMdd_HHmmss'
        $companyReportDir = Join-Path $OutputDirectory "reports\$($CompanyConfig.id)"
        $null = New-Item -Path $companyReportDir -ItemType Directory -Force -ErrorAction SilentlyContinue
        
        # Generate reports in multiple formats
        $reportFiles = @()
        
        # HTML Report
        $htmlPath = Join-Path $companyReportDir "Termination-Verification-$($CompanyConfig.id)-$verificationDate.html"
        $scriptPath = Join-Path $PSScriptRoot "Verify-TerminatedUsers.ps1"
        
        $verificationParams = @{
            SuccessFactorsEndpoint = $CompanyConfig.endpoint
            ClientId = $CompanyConfig.clientId
            ClientSecret = $CompanyConfig.clientSecret
            CompanyId = $CompanyConfig.id
            OutputFormat = 'HTML'
            ExportPath = $htmlPath
        }
        
        # Add configuration-specific parameters
        if ($ProcessingConfig) {
            if ($ProcessingConfig.gracePeriodDays) {
                $verificationParams.GracePeriodDays = $ProcessingConfig.gracePeriodDays
            }
            if ($ProcessingConfig.includeActiveUsers) {
                $verificationParams.IncludeActiveUsers = $true
            }
            if ($AutoRemediate) {
                $verificationParams.AutoRemediate = $true
            }
            if ($DryRun) {
                $verificationParams.DryRun = $true
            }
        }
        
        & $scriptPath @verificationParams
        
        if (Test-Path $htmlPath) {
            $reportFiles += $htmlPath
            Write-Log "HTML report generated: $htmlPath"
        }
        
        # CSV Report
        $csvPath = Join-Path $companyReportDir "Termination-Verification-$($CompanyConfig.id)-$verificationDate.csv"
        $verificationParams.OutputFormat = 'CSV'
        $verificationParams.ExportPath = $csvPath
        
        & $scriptPath @verificationParams
        
        if (Test-Path $csvPath) {
            $reportFiles += $csvPath
            Write-Log "CSV report generated: $csvPath"
        }
        
        # JSON Report
        $jsonPath = Join-Path $companyReportDir "Termination-Verification-$($CompanyConfig.id)-$verificationDate.json"
        $verificationParams.OutputFormat = 'JSON'
        $verificationParams.ExportPath = $jsonPath
        
        & $scriptPath @verificationParams
        
        if (Test-Path $jsonPath) {
            $reportFiles += $jsonPath
            Write-Log "JSON report generated: $jsonPath"
        }
        
        # Analyze compliance
        $complianceStatus = Get-CompanyCompliance -JsonReportPath $jsonPath -Threshold $ComplianceThreshold
        
        $result = @{
            CompanyId = $CompanyConfig.id
            CompanyName = $CompanyConfig.name
            ReportFiles = $reportFiles
            ComplianceStatus = $complianceStatus
            GeneratedAt = Get-Date
            Success = $true
        }
        
        Write-Log "Verification completed for company: $($CompanyConfig.name)"
        return $result
        
    } catch {
        Write-Log "Failed to verify company $($CompanyConfig.name): $($_.Exception.Message)" -Level Error
        
        return @{
            CompanyId = $CompanyConfig.id
            CompanyName = $CompanyConfig.name
            ReportFiles = @()
            ComplianceStatus = $null
            GeneratedAt = Get-Date
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Get-CompanyCompliance {
    param([string]$JsonReportPath, [int]$Threshold)
    
    try {
        if (-not (Test-Path $JsonReportPath)) {
            return $null
        }
        
        $reportData = Get-Content -Path $JsonReportPath | ConvertFrom-Json
        
        $totalTerminated = $reportData.Statistics.TotalTerminatedInSF
        $compliantTerminations = $reportData.Statistics.CompliantTerminations
        $nonCompliantTerminations = $reportData.Statistics.NonCompliantTerminations
        
        $complianceRate = if ($totalTerminated -gt 0) { 
            ($compliantTerminations / $totalTerminated) * 100 
        } else { 
            100 
        }
        
        $complianceStatus = @{
            TotalTerminated = $totalTerminated
            CompliantTerminations = $compliantTerminations
            NonCompliantTerminations = $nonCompliantTerminations
            ComplianceRate = [math]::Round($complianceRate, 2)
            ComplianceThreshold = $Threshold
            IsCompliant = $complianceRate -ge $Threshold
            RiskLevel = if ($complianceRate -ge 95) { 'Low' } elseif ($complianceRate -ge 80) { 'Medium' } else { 'High' }
            CriticalUsers = ($reportData.Results | Where-Object { $_.RiskLevel -eq 'Critical' }).Count
            HighRiskUsers = ($reportData.Results | Where-Object { $_.RiskLevel -eq 'High' }).Count
        }
        
        return $complianceStatus
        
    } catch {
        Write-Log "Failed to analyze company compliance: $($_.Exception.Message)" -Level Error
        return $null
    }
}

function New-ConsolidatedComplianceReport {
    param([object[]]$CompanyResults, [string]$OutputDirectory)
    
    try {
        Write-Log "Generating consolidated compliance report..."
        
        $consolidatedData = @{
            GeneratedAt = Get-Date
            TotalCompanies = $CompanyResults.Count
            SuccessfulVerifications = ($CompanyResults | Where-Object { $_.Success }).Count
            FailedVerifications = ($CompanyResults | Where-Object { -not $_.Success }).Count
            CompanySummary = @()
            OverallCompliance = @{
                TotalTerminated = 0
                CompliantTerminations = 0
                NonCompliantTerminations = 0
                ComplianceCompanies = 0
                NonComplianceCompanies = 0
                CriticalUsers = 0
                HighRiskUsers = 0
            }
        }
        
        foreach ($result in $CompanyResults) {
            $companySummary = @{
                CompanyId = $result.CompanyId
                CompanyName = $result.CompanyName
                Success = $result.Success
                GeneratedAt = $result.GeneratedAt
            }
            
            if ($result.Success -and $result.ComplianceStatus) {
                $compliance = $result.ComplianceStatus
                $companySummary.TotalTerminated = $compliance.TotalTerminated
                $companySummary.CompliantTerminations = $compliance.CompliantTerminations
                $companySummary.NonCompliantTerminations = $compliance.NonCompliantTerminations
                $companySummary.ComplianceRate = $compliance.ComplianceRate
                $companySummary.IsCompliant = $compliance.IsCompliant
                $companySummary.RiskLevel = $compliance.RiskLevel
                $companySummary.CriticalUsers = $compliance.CriticalUsers
                $companySummary.HighRiskUsers = $compliance.HighRiskUsers
                
                # Update overall compliance
                $consolidatedData.OverallCompliance.TotalTerminated += $compliance.TotalTerminated
                $consolidatedData.OverallCompliance.CompliantTerminations += $compliance.CompliantTerminations
                $consolidatedData.OverallCompliance.NonCompliantTerminations += $compliance.NonCompliantTerminations
                $consolidatedData.OverallCompliance.CriticalUsers += $compliance.CriticalUsers
                $consolidatedData.OverallCompliance.HighRiskUsers += $compliance.HighRiskUsers
                
                if ($compliance.IsCompliant) {
                    $consolidatedData.OverallCompliance.ComplianceCompanies++
                } else {
                    $consolidatedData.OverallCompliance.NonComplianceCompanies++
                }
            } else {
                $companySummary.Error = $result.Error
            }
            
            $consolidatedData.CompanySummary += $companySummary
        }
        
        # Calculate overall compliance rate
        if ($consolidatedData.OverallCompliance.TotalTerminated -gt 0) {
            $consolidatedData.OverallCompliance.ComplianceRate = [math]::Round(
                ($consolidatedData.OverallCompliance.CompliantTerminations / $consolidatedData.OverallCompliance.TotalTerminated) * 100, 2
            )
        } else {
            $consolidatedData.OverallCompliance.ComplianceRate = 100
        }
        
        # Export consolidated report
        $reportDate = Get-Date -Format 'yyyyMMdd_HHmmss'
        $consolidatedPath = Join-Path $OutputDirectory "reports\Consolidated-Termination-Compliance-$reportDate.json"
        $consolidatedData | ConvertTo-Json -Depth 10 | Out-File -FilePath $consolidatedPath -Encoding UTF8
        
        # Generate HTML dashboard
        $dashboardPath = Join-Path $OutputDirectory "reports\Termination-Compliance-Dashboard-$reportDate.html"
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
    <title>SAP SuccessFactors Termination Compliance Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .header { background-color: #0078d4; color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
        .summary { background-color: white; padding: 20px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; }
        .stats { display: flex; flex-wrap: wrap; gap: 20px; margin: 20px 0; }
        .stat-box { background-color: white; padding: 20px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); min-width: 200px; text-align: center; }
        .stat-value { font-size: 36px; font-weight: bold; color: #0078d4; }
        .stat-label { font-size: 14px; color: #666; margin-top: 5px; }
        .company-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 20px; margin: 20px 0; }
        .company-card { background-color: white; padding: 20px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .company-header { font-size: 18px; font-weight: bold; margin-bottom: 10px; }
        .compliance-badge { padding: 5px 10px; border-radius: 3px; font-size: 12px; font-weight: bold; }
        .compliant { background-color: #d4edda; color: #155724; }
        .non-compliant { background-color: #f8d7da; color: #721c24; }
        .risk-low { color: #28a745; }
        .risk-medium { color: #ffc107; }
        .risk-high { color: #dc3545; }
        .progress-bar { width: 100%; height: 20px; background-color: #e9ecef; border-radius: 10px; margin: 10px 0; }
        .progress-fill { height: 100%; background-color: #0078d4; border-radius: 10px; transition: width 0.3s ease; }
        .error { color: #dc3545; font-style: italic; }
        .critical-alert { background-color: #721c24; color: white; padding: 15px; border-radius: 5px; margin: 10px 0; }
    </style>
</head>
<body>
    <div class="header">
        <h1>SAP SuccessFactors Termination Compliance Dashboard</h1>
        <p>Generated: $($Data.GeneratedAt.ToString('yyyy-MM-dd HH:mm:ss'))</p>
        <p>Total Companies: $($Data.TotalCompanies) | Successful: $($Data.SuccessfulVerifications) | Failed: $($Data.FailedVerifications)</p>
    </div>
    
    <div class="summary">
        <h2>Enterprise Summary</h2>
        <div class="stats">
            <div class="stat-box">
                <div class="stat-value">$($Data.OverallCompliance.TotalTerminated)</div>
                <div class="stat-label">Total Terminated</div>
            </div>
            <div class="stat-box">
                <div class="stat-value">$($Data.OverallCompliance.CompliantTerminations)</div>
                <div class="stat-label">Compliant</div>
            </div>
            <div class="stat-box">
                <div class="stat-value">$($Data.OverallCompliance.NonCompliantTerminations)</div>
                <div class="stat-label">Non-Compliant</div>
            </div>
            <div class="stat-box">
                <div class="stat-value">$($Data.OverallCompliance.ComplianceRate)%</div>
                <div class="stat-label">Compliance Rate</div>
            </div>
            <div class="stat-box">
                <div class="stat-value">$($Data.OverallCompliance.CriticalUsers)</div>
                <div class="stat-label">Critical Risk Users</div>
            </div>
        </div>
    </div>
    
    $(if ($Data.OverallCompliance.CriticalUsers -gt 0) {
        "<div class='critical-alert'>
            <strong>⚠️ CRITICAL ALERT:</strong> $($Data.OverallCompliance.CriticalUsers) users have been terminated for over 30 days but still have active accounts!
        </div>"
    })
    
    <div class="summary">
        <h2>Company Details</h2>
        <div class="company-grid">
"@
    
    foreach ($company in $Data.CompanySummary) {
        if ($company.Success) {
            $complianceClass = if ($company.IsCompliant) { 'compliant' } else { 'non-compliant' }
            $complianceText = if ($company.IsCompliant) { 'Compliant' } else { 'Non-Compliant' }
            $riskClass = "risk-$($company.RiskLevel.ToLower())"
            
            $html += @"
            <div class="company-card">
                <div class="company-header">$($company.CompanyName)</div>
                <p><strong>Company ID:</strong> $($company.CompanyId)</p>
                <p><strong>Terminated Users:</strong> $($company.TotalTerminated)</p>
                <p><strong>Compliant:</strong> $($company.CompliantTerminations)</p>
                <p><strong>Non-Compliant:</strong> $($company.NonCompliantTerminations)</p>
                <div class="progress-bar">
                    <div class="progress-fill" style="width: $($company.ComplianceRate)%"></div>
                </div>
                <p><strong>Compliance Rate:</strong> $($company.ComplianceRate)%</p>
                <p><strong>Status:</strong> <span class="compliance-badge $complianceClass">$complianceText</span></p>
                <p><strong>Risk Level:</strong> <span class="$riskClass">$($company.RiskLevel)</span></p>
                $(if ($company.CriticalUsers -gt 0) { "<p><strong>Critical Users:</strong> <span style='color: #dc3545;'>$($company.CriticalUsers)</span></p>" })
                <p><strong>Generated:</strong> $($company.GeneratedAt.ToString('yyyy-MM-dd HH:mm:ss'))</p>
            </div>
"@
        } else {
            $html += @"
            <div class="company-card">
                <div class="company-header">$($company.CompanyName)</div>
                <p><strong>Company ID:</strong> $($company.CompanyId)</p>
                <p class="error">Verification Failed</p>
                <p class="error">Error: $($company.Error)</p>
                <p><strong>Attempted:</strong> $($company.GeneratedAt.ToString('yyyy-MM-dd HH:mm:ss'))</p>
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

function Send-ConsolidatedNotification {
    param([object]$ConsolidatedResult, [object]$NotificationConfig)
    
    if (-not $NotificationConfig) {
        return
    }
    
    try {
        Write-Log "Sending consolidated compliance notification..."
        
        $totalNonCompliant = $ConsolidatedResult.Data.OverallCompliance.NonCompliantTerminations
        $totalCritical = $ConsolidatedResult.Data.OverallCompliance.CriticalUsers
        $complianceRate = $ConsolidatedResult.Data.OverallCompliance.ComplianceRate
        
        $subject = "SAP SuccessFactors Enterprise Compliance Report - $totalNonCompliant Non-Compliant Users"
        $bodyContent = @"
SAP SuccessFactors Enterprise Termination Compliance Report

Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

Enterprise Summary:
- Total Companies: $($ConsolidatedResult.Data.TotalCompanies)
- Total Terminated Users: $($ConsolidatedResult.Data.OverallCompliance.TotalTerminated)
- Compliant Terminations: $($ConsolidatedResult.Data.OverallCompliance.CompliantTerminations)
- Non-Compliant Terminations: $($ConsolidatedResult.Data.OverallCompliance.NonCompliantTerminations)
- Overall Compliance Rate: $complianceRate%
- Critical Risk Users: $totalCritical

$(if ($totalCritical -gt 0) { "🚨 CRITICAL ALERT: $totalCritical users terminated over 30 days ago still have active accounts!" })

$(if ($totalNonCompliant -gt 0) { "⚠️  ATTENTION: $totalNonCompliant terminated users still have active accounts across all companies!" } else { "✅ All terminated users have been properly disabled across all companies." })

Company Breakdown:
$(foreach ($company in $ConsolidatedResult.Data.CompanySummary) {
    if ($company.Success) {
        "• $($company.CompanyName): $($company.ComplianceRate)% compliant ($($company.NonCompliantTerminations) non-compliant)`n"
    } else {
        "• $($company.CompanyName): Verification failed`n"
    }
})

Please review the detailed dashboard for specific remediation actions.
"@
        
        # Log notification details (actual sending would require email configuration)
        Write-Log "Notification prepared for: $($NotificationConfig.recipients -join ', ')"
        Write-Log "Subject: $subject"
        Write-Log "Body content prepared with $($bodyContent.Length) characters"
        Write-Log "Total non-compliant users: $totalNonCompliant"
        Write-Log "Critical users: $totalCritical"
        Write-Log "Overall compliance rate: $complianceRate%"
        
        # TODO: Implement actual email sending
        # This could use Send-MailMessage, Send-MgUserMessage, or other email solutions
        
    } catch {
        Write-Log "Failed to send consolidated notification: $($_.Exception.Message)" -Level Error
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
    Write-Log "Starting bulk SAP SuccessFactors termination verification..."
    
    # Initialize environment
    Initialize-BulkEnvironment -OutputDirectory $OutputDirectory
    
    # Load configuration
    $config = Get-VerificationConfiguration -ConfigPath $ConfigPath
    
    # Get company configuration
    $companyConfigs = Get-CompanyConfiguration -Config $config -CompanyIds $CompanyIds
    
    if ($companyConfigs.Count -eq 0) {
        throw "No companies configured for verification"
    }
    
    # Process each company
    $companyResults = @()
    foreach ($companyConfig in $companyConfigs) {
        $result = Invoke-CompanyVerification -CompanyConfig $companyConfig -OutputDirectory $OutputDirectory -ProcessingConfig $config.processingSettings
        $companyResults += $result
    }
    
    # Generate consolidated report if requested
    if ($GenerateConsolidatedReport) {
        $consolidatedResult = New-ConsolidatedComplianceReport -CompanyResults $companyResults -OutputDirectory $OutputDirectory
        
        # Send email if configured
        if ($config.notificationSettings -or $NotificationSettings) {
            $notificationConfig = $NotificationSettings -or $config.notificationSettings
            Send-ConsolidatedNotification -ConsolidatedResult $consolidatedResult -NotificationConfig $notificationConfig
        }
    }
    
    # Archive old reports if requested
    if ($ArchiveOldReports) {
        Invoke-ReportArchival -OutputDirectory $OutputDirectory -ArchiveAfterDays $ArchiveAfterDays
    }
    
    # Summary
    $successCount = ($companyResults | Where-Object { $_.Success }).Count
    $failureCount = ($companyResults | Where-Object { -not $_.Success }).Count
    
    Write-Log "Bulk termination verification completed successfully"
    Write-Log "Total companies: $($companyResults.Count)"
    Write-Log "Successful verifications: $successCount"
    Write-Log "Failed verifications: $failureCount"
    
    if ($failureCount -gt 0) {
        Write-Log "Some verifications failed - check individual company logs for details" -Level Warning
    }
    
} catch {
    Write-Log "Bulk termination verification failed: $($_.Exception.Message)" -Level Error
    Write-Log "Stack trace: $($_.Exception.StackTrace)" -Level Error
    throw
}
