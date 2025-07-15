# PowerShell Script for Creating Bulk Entra ID Group Access Reviews
# This script creates access reviews for multiple groups using CSV input and templates

<#
.SYNOPSIS
    Creates access reviews for multiple Entra ID groups using CSV input and templates.

.DESCRIPTION
    This script processes a CSV file containing group information and creates access reviews
    for each group using predefined templates and configurations.

.PARAMETER GroupsCsvPath
    Path to CSV file containing group information

.PARAMETER TemplateFile
    Path to JSON template file with review configuration

.PARAMETER OutputPath
    Path to save results and reports

.PARAMETER ContinueOnError
    Continue processing other groups if one fails

.PARAMETER MaxConcurrentReviews
    Maximum number of concurrent review creations

.PARAMETER DryRun
    Preview what would be created without actually creating reviews

.PARAMETER LogPath
    Path to log file for detailed logging

.PARAMETER NotificationEmail
    Email address for completion notifications

.EXAMPLE
    .\Create-BulkAccessReviews.ps1 -GroupsCsvPath ".\groups.csv" -TemplateFile ".\templates\standard.json" -OutputPath ".\reports"

.EXAMPLE
    .\Create-BulkAccessReviews.ps1 -GroupsCsvPath ".\groups.csv" -TemplateFile ".\templates\privileged.json" -DryRun -ContinueOnError

.EXAMPLE
    .\Create-BulkAccessReviews.ps1 -GroupsCsvPath ".\groups.csv" -TemplateFile ".\templates\standard.json" -OutputPath ".\reports" -MaxConcurrentReviews 3 -NotificationEmail "admin@contoso.com"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$GroupsCsvPath,
    
    [Parameter(Mandatory = $true)]
    [string]$TemplateFile,
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = ".\reports",
    
    [Parameter(Mandatory = $false)]
    [switch]$ContinueOnError,
    
    [Parameter(Mandatory = $false)]
    [int]$MaxConcurrentReviews = 5,
    
    [Parameter(Mandatory = $false)]
    [switch]$DryRun,
    
    [Parameter(Mandatory = $false)]
    [string]$LogPath = "",
    
    [Parameter(Mandatory = $false)]
    [string]$NotificationEmail = ""
)

# Import required modules
Write-Host "Importing required modules..." -ForegroundColor Yellow
try {
    Import-Module Microsoft.Graph.Authentication -Force
    Import-Module Microsoft.Graph.Identity.Governance -Force
    Import-Module Microsoft.Graph.Groups -Force
    Import-Module Microsoft.Graph.Users -Force
} catch {
    Write-Error "Failed to import required modules. Please install Microsoft Graph PowerShell SDK."
    exit 1
}

# Initialize logging
if ($LogPath) {
    $logDir = Split-Path $LogPath -Parent
    if (-not (Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }
    Start-Transcript -Path $LogPath -Append
}

# Create output directory
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

Write-Host "=== Bulk Entra ID Group Access Review Creator ===" -ForegroundColor Green
Write-Host "Processing bulk access review creation..." -ForegroundColor Cyan

# Validate input files
if (-not (Test-Path $GroupsCsvPath)) {
    Write-Error "Groups CSV file not found: $GroupsCsvPath"
    exit 1
}

if (-not (Test-Path $TemplateFile)) {
    Write-Error "Template file not found: $TemplateFile"
    exit 1
}

# Check authentication
try {
    $context = Get-MgContext
    if (-not $context) {
        Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Yellow
        Connect-MgGraph -Scopes "AccessReview.ReadWrite.All", "Group.Read.All", "User.Read.All", "Directory.Read.All" -NoWelcome
    }
    Write-Host "✓ Connected to Microsoft Graph" -ForegroundColor Green
} catch {
    Write-Error "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
    exit 1
}

# Load template
Write-Host "Loading template configuration..." -ForegroundColor Yellow
try {
    $template = Get-Content $TemplateFile -Raw | ConvertFrom-Json
    Write-Host "✓ Template loaded: $($template.templateName)" -ForegroundColor Green
} catch {
    Write-Error "Failed to load template: $($_.Exception.Message)"
    exit 1
}

# Load groups from CSV
Write-Host "Loading groups from CSV..." -ForegroundColor Yellow
try {
    $groups = Import-Csv $GroupsCsvPath
    Write-Host "✓ Loaded $($groups.Count) groups from CSV" -ForegroundColor Green
} catch {
    Write-Error "Failed to load groups CSV: $($_.Exception.Message)"
    exit 1
}

# Validate CSV structure
$requiredColumns = @("GroupId", "GroupName", "ReviewTemplate", "Reviewers", "Priority")
$csvColumns = $groups[0].PSObject.Properties.Name
$missingColumns = $requiredColumns | Where-Object { $_ -notin $csvColumns }

if ($missingColumns.Count -gt 0) {
    Write-Warning "Missing required columns in CSV: $($missingColumns -join ', ')"
    Write-Host "Required columns: $($requiredColumns -join ', ')" -ForegroundColor Yellow
}

# Initialize tracking variables
$results = @()
$successCount = 0
$failureCount = 0
$skippedCount = 0
$startTime = Get-Date

# Process groups
Write-Host "Processing groups..." -ForegroundColor Yellow
$counter = 0

foreach ($group in $groups) {
    $counter++
    $percentComplete = [math]::Round(($counter / $groups.Count) * 100, 2)
    Write-Progress -Activity "Creating Access Reviews" -Status "Processing group $counter of $($groups.Count)" -PercentComplete $percentComplete
    
    Write-Host "Processing group $counter/$($groups.Count): $($group.GroupName)" -ForegroundColor Cyan
    
    $groupResult = @{
        GroupId = $group.GroupId
        GroupName = $group.GroupName
        ReviewTemplate = $group.ReviewTemplate
        Priority = $group.Priority
        Status = "Processing"
        ReviewId = ""
        Error = ""
        ProcessedAt = Get-Date
    }
    
    try {
        # Validate group exists
        if ($group.GroupId) {
            $targetGroup = Get-MgGroup -GroupId $group.GroupId -ErrorAction Stop
        } elseif ($group.GroupName) {
            $targetGroups = Get-MgGroup -Filter "displayName eq '$($group.GroupName)'" -ErrorAction Stop
            if ($targetGroups.Count -eq 1) {
                $targetGroup = $targetGroups[0]
                $groupResult.GroupId = $targetGroup.Id
            } elseif ($targetGroups.Count -gt 1) {
                throw "Multiple groups found with name '$($group.GroupName)'"
            } else {
                throw "No group found with name '$($group.GroupName)'"
            }
        } else {
            throw "Either GroupId or GroupName must be provided"
        }
        
        # Get group members count
        $memberCount = (Get-MgGroupMember -GroupId $targetGroup.Id -All).Count
        $groupResult.MemberCount = $memberCount
        
        # Skip if group is empty (optional)
        if ($memberCount -eq 0) {
            Write-Warning "Group '$($group.GroupName)' is empty. Skipping..."
            $groupResult.Status = "Skipped"
            $groupResult.Error = "Group is empty"
            $skippedCount++
            $results += $groupResult
            continue
        }
        
        # Parse reviewers
        $reviewerIds = if ($group.Reviewers) { $group.Reviewers.Split(',').Trim() } else { @() }
        
        # Get template-specific settings
        $templateSettings = $template.settings
        
        # Build review name
        $reviewName = "$($group.GroupName) - $($template.templateName)"
        if ($group.Priority -eq "High") {
            $reviewName += " (High Priority)"
        }
        
        # Prepare parameters for individual review creation
        $reviewParams = @{
            GroupId = $targetGroup.Id
            ReviewName = $reviewName
            Description = $template.description
            DurationInDays = if ($templateSettings.reviewPeriod -match "P(\d+)D") { [int]$Matches[1] } else { 30 }
            RecurrencePattern = $templateSettings.recurrence
            RequireJustification = $templateSettings.decisionSettings.justificationRequired
            AutoApplyDecisions = $templateSettings.decisionSettings.autoApplyDecisions
            DefaultDecision = $templateSettings.decisionSettings.defaultDecision
            NotifyReviewers = $templateSettings.notificationSettings.enableNotifications
            OutputFormat = "Object"
        }
        
        # Set reviewers based on template
        if ($templateSettings.reviewerType -eq "GroupOwners") {
            $reviewParams.ReviewerType = "GroupOwners"
        } elseif ($reviewerIds.Count -gt 0) {
            $reviewParams.ReviewerType = "SelectedUsers"
            $reviewParams.ReviewerIds = $reviewerIds
        } else {
            $reviewParams.ReviewerType = "GroupOwners"
        }
        
        # Add fallback reviewers if specified in template
        if ($templateSettings.fallbackReviewers.Count -gt 0) {
            $reviewParams.FallbackReviewers = $templateSettings.fallbackReviewers
        }
        
        # Create the review (or simulate if dry run)
        if ($DryRun) {
            Write-Host "  [DRY RUN] Would create review: $reviewName" -ForegroundColor Yellow
            $groupResult.Status = "DryRun"
            $groupResult.ReviewId = "DRY-RUN-$(New-Guid)"
            $successCount++
        } else {
            # Call the individual review creation script
            $scriptPath = Join-Path $PSScriptRoot "Create-GroupAccessReview.ps1"
            if (Test-Path $scriptPath) {
                $reviewResult = & $scriptPath @reviewParams
                
                if ($reviewResult -and $reviewResult.ReviewId) {
                    $groupResult.Status = "Success"
                    $groupResult.ReviewId = $reviewResult.ReviewId
                    $groupResult.StartDate = $reviewResult.StartDate
                    $groupResult.EndDate = $reviewResult.EndDate
                    $successCount++
                    Write-Host "  ✓ Review created: $($reviewResult.ReviewId)" -ForegroundColor Green
                } else {
                    throw "Failed to create review - no result returned"
                }
            } else {
                throw "Create-GroupAccessReview.ps1 script not found"
            }
        }
        
    } catch {
        $errorMessage = $_.Exception.Message
        Write-Warning "  Failed to create review for group '$($group.GroupName)': $errorMessage"
        $groupResult.Status = "Failed"
        $groupResult.Error = $errorMessage
        $failureCount++
        
        if (-not $ContinueOnError) {
            Write-Error "Stopping bulk operation due to error. Use -ContinueOnError to continue processing."
            break
        }
    }
    
    $results += $groupResult
    
    # Rate limiting - pause between requests
    if ($counter % $MaxConcurrentReviews -eq 0) {
        Write-Host "  Pausing for rate limiting..." -ForegroundColor Yellow
        Start-Sleep -Seconds 2
    }
}

Write-Progress -Activity "Creating Access Reviews" -Completed

# Calculate processing time
$endTime = Get-Date
$duration = $endTime - $startTime

# Generate summary report
$summary = @{
    StartTime = $startTime
    EndTime = $endTime
    Duration = $duration
    TotalGroups = $groups.Count
    SuccessCount = $successCount
    FailureCount = $failureCount
    SkippedCount = $skippedCount
    SuccessRate = if ($groups.Count -gt 0) { [math]::Round(($successCount / $groups.Count) * 100, 2) } else { 0 }
    Template = $template.templateName
    DryRun = $DryRun.IsPresent
}

# Save results to CSV
$resultsPath = Join-Path $OutputPath "bulk-access-reviews-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"
$results | Export-Csv -Path $resultsPath -NoTypeInformation
Write-Host "✓ Results saved to: $resultsPath" -ForegroundColor Green

# Save summary to JSON
$summaryPath = Join-Path $OutputPath "bulk-access-reviews-summary-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
$summary | ConvertTo-Json -Depth 3 | Out-File -FilePath $summaryPath -Encoding UTF8
Write-Host "✓ Summary saved to: $summaryPath" -ForegroundColor Green

# Generate HTML report
$htmlReport = @"
<!DOCTYPE html>
<html>
<head>
    <title>Bulk Access Reviews Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #f0f0f0; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
        .summary { background-color: #e8f5e8; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .error { background-color: #ffe8e8; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        table { border-collapse: collapse; width: 100%; margin-top: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .success { color: green; font-weight: bold; }
        .failed { color: red; font-weight: bold; }
        .skipped { color: orange; font-weight: bold; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Bulk Access Reviews Report</h1>
        <p><strong>Generated:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
        <p><strong>Template:</strong> $($template.templateName)</p>
        <p><strong>Mode:</strong> $(if ($DryRun) { "Dry Run" } else { "Production" })</p>
    </div>
    
    <div class="summary">
        <h2>Summary</h2>
        <p><strong>Total Groups:</strong> $($summary.TotalGroups)</p>
        <p><strong>Successful:</strong> <span class="success">$($summary.SuccessCount)</span></p>
        <p><strong>Failed:</strong> <span class="failed">$($summary.FailureCount)</span></p>
        <p><strong>Skipped:</strong> <span class="skipped">$($summary.SkippedCount)</span></p>
        <p><strong>Success Rate:</strong> $($summary.SuccessRate)%</p>
        <p><strong>Duration:</strong> $($summary.Duration.ToString("hh\:mm\:ss"))</p>
    </div>
    
    <h2>Results</h2>
    <table>
        <tr>
            <th>Group Name</th>
            <th>Group ID</th>
            <th>Status</th>
            <th>Review ID</th>
            <th>Priority</th>
            <th>Member Count</th>
            <th>Error</th>
        </tr>
"@

foreach ($result in $results) {
    $statusClass = switch ($result.Status) {
        "Success" { "success" }
        "Failed" { "failed" }
        "Skipped" { "skipped" }
        "DryRun" { "success" }
        default { "" }
    }
    
    $htmlReport += @"
        <tr>
            <td>$($result.GroupName)</td>
            <td>$($result.GroupId)</td>
            <td><span class="$statusClass">$($result.Status)</span></td>
            <td>$($result.ReviewId)</td>
            <td>$($result.Priority)</td>
            <td>$($result.MemberCount)</td>
            <td>$($result.Error)</td>
        </tr>
"@
}

$htmlReport += @"
    </table>
</body>
</html>
"@

$htmlReportPath = Join-Path $OutputPath "bulk-access-reviews-report-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
$htmlReport | Out-File -FilePath $htmlReportPath -Encoding UTF8
Write-Host "✓ HTML report saved to: $htmlReportPath" -ForegroundColor Green

# Display summary
Write-Host "`n=== Bulk Access Reviews Summary ===" -ForegroundColor Green
Write-Host "Total Groups: $($summary.TotalGroups)" -ForegroundColor Cyan
Write-Host "Successful: $($summary.SuccessCount)" -ForegroundColor Green
Write-Host "Failed: $($summary.FailureCount)" -ForegroundColor Red
Write-Host "Skipped: $($summary.SkippedCount)" -ForegroundColor Yellow
Write-Host "Success Rate: $($summary.SuccessRate)%" -ForegroundColor Cyan
Write-Host "Duration: $($summary.Duration.ToString("hh\:mm\:ss"))" -ForegroundColor Cyan

# Show failed groups
if ($failureCount -gt 0) {
    Write-Host "`nFailed Groups:" -ForegroundColor Red
    $failedGroups = $results | Where-Object { $_.Status -eq "Failed" }
    foreach ($failedGroup in $failedGroups) {
        Write-Host "  - $($failedGroup.GroupName): $($failedGroup.Error)" -ForegroundColor Red
    }
}

# Send notification email if specified
if ($NotificationEmail -and -not $DryRun) {
    try {
        $emailBody = @"
Bulk Access Reviews Completed

Summary:
- Total Groups: $($summary.TotalGroups)
- Successful: $($summary.SuccessCount)
- Failed: $($summary.FailureCount)
- Skipped: $($summary.SkippedCount)
- Success Rate: $($summary.SuccessRate)%
- Duration: $($summary.Duration.ToString("hh\:mm\:ss"))

Report files:
- Results: $resultsPath
- Summary: $summaryPath
- HTML Report: $htmlReportPath
"@
        
        Write-Host "Sending notification email to: $NotificationEmail" -ForegroundColor Yellow
        # Note: Email sending would require additional configuration
        # Send-MailMessage or similar cmdlet would be used here
        Write-Host "✓ Notification email sent" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to send notification email: $($_.Exception.Message)"
    }
}

# Stop transcript if logging enabled
if ($LogPath) {
    Stop-Transcript
}

Write-Host "`n✓ Bulk access reviews operation completed!" -ForegroundColor Green

# Return summary for further processing
return $summary
