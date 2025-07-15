# PowerShell Script for Creating Entra ID Group Access Reviews
# This script creates access reviews for Entra ID groups with comprehensive configuration options

<#
.SYNOPSIS
    Creates an access review for a specific Entra ID group.

.DESCRIPTION
    This script creates an access review for a specified Entra ID group with customizable
    settings including reviewers, duration, notifications, and recurrence patterns.

.PARAMETER GroupId
    The Object ID of the Entra ID group to review

.PARAMETER GroupName
    The name of the group (if GroupId is not provided, will search by name)

.PARAMETER ReviewName
    The display name for the access review

.PARAMETER Description
    Description of the access review

.PARAMETER ReviewerIds
    Array of user IDs or email addresses who will perform the review

.PARAMETER ReviewerType
    Type of reviewers: GroupOwners, SelectedUsers, Manager, or Self

.PARAMETER FallbackReviewers
    Array of fallback reviewers if primary reviewers are unavailable

.PARAMETER DurationInDays
    Duration of the review in days (default: 30)

.PARAMETER StartDate
    Start date for the review (default: today)

.PARAMETER RecurrencePattern
    Recurrence pattern: None, Weekly, Monthly, Quarterly, SemiAnnually, Annually

.PARAMETER NotifyReviewers
    Whether to notify reviewers when review starts

.PARAMETER RequireJustification
    Whether reviewers must provide justification for their decisions

.PARAMETER AutoApplyDecisions
    Whether to automatically apply decisions when review completes

.PARAMETER DefaultDecision
    Default decision if no response: None, Approve, Deny, or Recommendation

.PARAMETER IncludeGuestUsers
    Whether to include guest users in the review

.PARAMETER IncludeServicePrincipals
    Whether to include service principals in the review

.PARAMETER EmailNotificationFrequency
    Frequency of email notifications: None, Weekly, Biweekly

.PARAMETER OutputFormat
    Output format: Object, JSON, or Table

.PARAMETER LogPath
    Path to log file for detailed logging

.EXAMPLE
    .\Create-GroupAccessReview.ps1 -GroupId "12345678-1234-1234-1234-123456789012" -ReviewName "IT Admin Review" -ReviewerIds @("manager@contoso.com")

.EXAMPLE
    .\Create-GroupAccessReview.ps1 -GroupName "IT-Administrators" -ReviewName "Monthly IT Admin Review" -ReviewerType "GroupOwners" -DurationInDays 14 -RecurrencePattern "Monthly" -RequireJustification

.EXAMPLE
    .\Create-GroupAccessReview.ps1 -GroupId "12345678-1234-1234-1234-123456789012" -ReviewName "Privileged Access Review" -ReviewerIds @("security@contoso.com") -FallbackReviewers @("admin@contoso.com") -AutoApplyDecisions -DefaultDecision "Deny"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$GroupId,
    
    [Parameter(Mandatory = $false)]
    [string]$GroupName,
    
    [Parameter(Mandatory = $true)]
    [string]$ReviewName,
    
    [Parameter(Mandatory = $false)]
    [string]$Description = "",
    
    [Parameter(Mandatory = $false)]
    [string[]]$ReviewerIds = @(),
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("GroupOwners", "SelectedUsers", "Manager", "Self")]
    [string]$ReviewerType = "GroupOwners",
    
    [Parameter(Mandatory = $false)]
    [string[]]$FallbackReviewers = @(),
    
    [Parameter(Mandatory = $false)]
    [int]$DurationInDays = 30,
    
    [Parameter(Mandatory = $false)]
    [DateTime]$StartDate = (Get-Date),
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("None", "Weekly", "Monthly", "Quarterly", "SemiAnnually", "Annually")]
    [string]$RecurrencePattern = "None",
    
    [Parameter(Mandatory = $false)]
    [bool]$NotifyReviewers = $true,
    
    [Parameter(Mandatory = $false)]
    [bool]$RequireJustification = $false,
    
    [Parameter(Mandatory = $false)]
    [bool]$AutoApplyDecisions = $false,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("None", "Approve", "Deny", "Recommendation")]
    [string]$DefaultDecision = "None",
    
    [Parameter(Mandatory = $false)]
    [bool]$IncludeGuestUsers = $true,
    
    [Parameter(Mandatory = $false)]
    [bool]$IncludeServicePrincipals = $false,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("None", "Weekly", "Biweekly")]
    [string]$EmailNotificationFrequency = "Weekly",
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Object", "JSON", "Table")]
    [string]$OutputFormat = "Object",
    
    [Parameter(Mandatory = $false)]
    [string]$LogPath = ""
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
    Write-Host "Install with: Install-Module Microsoft.Graph -Scope CurrentUser" -ForegroundColor Yellow
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

Write-Host "=== Entra ID Group Access Review Creator ===" -ForegroundColor Green
Write-Host "Starting access review creation process..." -ForegroundColor Cyan

# Check authentication
try {
    $context = Get-MgContext
    if (-not $context) {
        Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Yellow
        Connect-MgGraph -Scopes "AccessReview.ReadWrite.All", "Group.Read.All", "User.Read.All", "Directory.Read.All" -NoWelcome
    }
    
    Write-Host "✓ Connected to Microsoft Graph" -ForegroundColor Green
    Write-Host "Tenant: $($context.TenantId)" -ForegroundColor Cyan
    Write-Host "Account: $($context.Account)" -ForegroundColor Cyan
} catch {
    Write-Error "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
    exit 1
}

# Resolve group
Write-Host "Resolving target group..." -ForegroundColor Yellow
$targetGroup = $null

try {
    if ($GroupId) {
        $targetGroup = Get-MgGroup -GroupId $GroupId -ErrorAction Stop
        Write-Host "✓ Found group by ID: $($targetGroup.DisplayName)" -ForegroundColor Green
    } elseif ($GroupName) {
        $groups = Get-MgGroup -Filter "displayName eq '$GroupName'" -ErrorAction Stop
        if ($groups.Count -eq 1) {
            $targetGroup = $groups[0]
            Write-Host "✓ Found group by name: $($targetGroup.DisplayName)" -ForegroundColor Green
        } elseif ($groups.Count -gt 1) {
            Write-Error "Multiple groups found with name '$GroupName'. Please use GroupId parameter."
            exit 1
        } else {
            Write-Error "No group found with name '$GroupName'."
            exit 1
        }
    } else {
        Write-Error "Either GroupId or GroupName must be provided."
        exit 1
    }
} catch {
    Write-Error "Failed to find group: $($_.Exception.Message)"
    exit 1
}

# Get group members count
try {
    $groupMembers = Get-MgGroupMember -GroupId $targetGroup.Id -All
    $memberCount = $groupMembers.Count
    Write-Host "✓ Group has $memberCount members" -ForegroundColor Green
} catch {
    Write-Warning "Could not retrieve group members count: $($_.Exception.Message)"
    $memberCount = 0
}

# Resolve reviewers
Write-Host "Resolving reviewers..." -ForegroundColor Yellow
$reviewers = @()

if ($ReviewerType -eq "GroupOwners") {
    try {
        $groupOwners = Get-MgGroupOwner -GroupId $targetGroup.Id -All
        if ($groupOwners.Count -gt 0) {
            foreach ($owner in $groupOwners) {
                $reviewers += @{
                    "@odata.type" = "#microsoft.graph.singleUser"
                    "id" = $owner.Id
                }
            }
            Write-Host "✓ Using $($groupOwners.Count) group owners as reviewers" -ForegroundColor Green
        } else {
            Write-Warning "No group owners found. Using fallback reviewers."
            $ReviewerType = "SelectedUsers"
            $ReviewerIds = $FallbackReviewers
        }
    } catch {
        Write-Warning "Could not retrieve group owners: $($_.Exception.Message)"
        $ReviewerType = "SelectedUsers"
        $ReviewerIds = $FallbackReviewers
    }
}

if ($ReviewerType -eq "SelectedUsers" -and $ReviewerIds.Count -gt 0) {
    foreach ($reviewerId in $ReviewerIds) {
        try {
            if ($reviewerId -match "^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$") {
                # It's a GUID
                $user = Get-MgUser -UserId $reviewerId -ErrorAction Stop
            } else {
                # It's an email address
                $user = Get-MgUser -Filter "mail eq '$reviewerId' or userPrincipalName eq '$reviewerId'" -ErrorAction Stop
                if ($user -is [array]) {
                    $user = $user[0]
                }
            }
            
            $reviewers += @{
                "@odata.type" = "#microsoft.graph.singleUser"
                "id" = $user.Id
            }
            Write-Host "✓ Added reviewer: $($user.DisplayName) ($($user.UserPrincipalName))" -ForegroundColor Green
        } catch {
            Write-Warning "Could not find reviewer: $reviewerId"
        }
    }
}

if ($reviewers.Count -eq 0) {
    Write-Error "No valid reviewers found. Cannot create access review."
    exit 1
}

# Calculate end date
$endDate = $StartDate.AddDays($DurationInDays)

# Build recurrence settings
$recurrence = $null
if ($RecurrencePattern -ne "None") {
    $recurrenceInterval = switch ($RecurrencePattern) {
        "Weekly" { 1 }
        "Monthly" { 1 }
        "Quarterly" { 3 }
        "SemiAnnually" { 6 }
        "Annually" { 12 }
    }
    
    $recurrenceType = switch ($RecurrencePattern) {
        "Weekly" { "weekly" }
        default { "monthly" }
    }
    
    $recurrence = @{
        "pattern" = @{
            "type" = $recurrenceType
            "interval" = $recurrenceInterval
        }
        "range" = @{
            "type" = "noEnd"
        }
    }
}

# Build access review settings
$accessReviewSettings = @{
    "displayName" = $ReviewName
    "descriptionForAdmins" = if ($Description) { $Description } else { "Access review for group: $($targetGroup.DisplayName)" }
    "descriptionForReviewers" = "Please review the members of the group '$($targetGroup.DisplayName)' and determine if they should retain access."
    "scope" = @{
        "@odata.type" = "#microsoft.graph.groupMembersScope"
        "groupId" = $targetGroup.Id
    }
    "reviewers" = $reviewers
    "settings" = @{
        "mailNotificationsEnabled" = $NotifyReviewers
        "reminderNotificationsEnabled" = $NotifyReviewers
        "justificationRequiredOnApproval" = $RequireJustification
        "defaultDecisionEnabled" = ($DefaultDecision -ne "None")
        "defaultDecision" = $DefaultDecision.ToLower()
        "instanceDurationInDays" = $DurationInDays
        "autoApplyDecisionsEnabled" = $AutoApplyDecisions
        "recommendationsEnabled" = $true
        "recurrence" = $recurrence
    }
    "stageSettings" = @(
        @{
            "stageId" = "1"
            "dependsOn" = @()
            "durationInDays" = $DurationInDays
            "reviewers" = $reviewers
            "settings" = @{
                "mailNotificationsEnabled" = $NotifyReviewers
                "reminderNotificationsEnabled" = $NotifyReviewers
                "justificationRequiredOnApproval" = $RequireJustification
                "defaultDecisionEnabled" = ($DefaultDecision -ne "None")
                "defaultDecision" = $DefaultDecision.ToLower()
                "recommendationsEnabled" = $true
            }
        }
    )
}

# Add fallback reviewers if specified
if ($FallbackReviewers.Count -gt 0) {
    $fallbackReviewerObjects = @()
    foreach ($fallbackId in $FallbackReviewers) {
        try {
            if ($fallbackId -match "^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$") {
                $user = Get-MgUser -UserId $fallbackId -ErrorAction Stop
            } else {
                $user = Get-MgUser -Filter "mail eq '$fallbackId' or userPrincipalName eq '$fallbackId'" -ErrorAction Stop
                if ($user -is [array]) {
                    $user = $user[0]
                }
            }
            
            $fallbackReviewerObjects += @{
                "@odata.type" = "#microsoft.graph.singleUser"
                "id" = $user.Id
            }
            Write-Host "✓ Added fallback reviewer: $($user.DisplayName)" -ForegroundColor Green
        } catch {
            Write-Warning "Could not find fallback reviewer: $fallbackId"
        }
    }
    
    if ($fallbackReviewerObjects.Count -gt 0) {
        $accessReviewSettings.stageSettings[0].fallbackReviewers = $fallbackReviewerObjects
    }
}

# Create the access review
Write-Host "Creating access review..." -ForegroundColor Yellow
try {
    $createdReview = New-MgIdentityGovernanceAccessReviewDefinition -BodyParameter $accessReviewSettings
    Write-Host "✓ Access review created successfully!" -ForegroundColor Green
    Write-Host "Review ID: $($createdReview.Id)" -ForegroundColor Cyan
    Write-Host "Review Name: $($createdReview.DisplayName)" -ForegroundColor Cyan
    Write-Host "Status: $($createdReview.Status)" -ForegroundColor Cyan
} catch {
    Write-Error "Failed to create access review: $($_.Exception.Message)"
    if ($_.Exception.Response) {
        Write-Host "Response: $($_.Exception.Response)" -ForegroundColor Red
    }
    exit 1
}

# Start the access review instance
Write-Host "Starting access review instance..." -ForegroundColor Yellow
try {
    $reviewInstance = Start-MgIdentityGovernanceAccessReviewDefinitionInstance -AccessReviewDefinitionId $createdReview.Id
    Write-Host "✓ Access review instance started!" -ForegroundColor Green
} catch {
    Write-Warning "Access review created but failed to start instance: $($_.Exception.Message)"
}

# Generate summary
$summary = @{
    "ReviewId" = $createdReview.Id
    "ReviewName" = $createdReview.DisplayName
    "GroupName" = $targetGroup.DisplayName
    "GroupId" = $targetGroup.Id
    "MemberCount" = $memberCount
    "ReviewerCount" = $reviewers.Count
    "DurationInDays" = $DurationInDays
    "StartDate" = $StartDate
    "EndDate" = $endDate
    "RecurrencePattern" = $RecurrencePattern
    "Status" = $createdReview.Status
    "RequireJustification" = $RequireJustification
    "AutoApplyDecisions" = $AutoApplyDecisions
    "DefaultDecision" = $DefaultDecision
    "CreatedDateTime" = $createdReview.CreatedDateTime
}

# Output results
Write-Host "`n=== Access Review Summary ===" -ForegroundColor Green
Write-Host "Review ID: $($summary.ReviewId)" -ForegroundColor Cyan
Write-Host "Review Name: $($summary.ReviewName)" -ForegroundColor Cyan
Write-Host "Target Group: $($summary.GroupName)" -ForegroundColor Cyan
Write-Host "Group Members: $($summary.MemberCount)" -ForegroundColor Cyan
Write-Host "Reviewers: $($summary.ReviewerCount)" -ForegroundColor Cyan
Write-Host "Duration: $($summary.DurationInDays) days" -ForegroundColor Cyan
Write-Host "Start Date: $($summary.StartDate.ToString('yyyy-MM-dd'))" -ForegroundColor Cyan
Write-Host "End Date: $($summary.EndDate.ToString('yyyy-MM-dd'))" -ForegroundColor Cyan
Write-Host "Recurrence: $($summary.RecurrencePattern)" -ForegroundColor Cyan
Write-Host "Status: $($summary.Status)" -ForegroundColor Cyan

# Format output based on OutputFormat parameter
switch ($OutputFormat) {
    "JSON" {
        return $summary | ConvertTo-Json -Depth 3
    }
    "Table" {
        return $summary | Format-Table -AutoSize
    }
    default {
        return $summary
    }
}

# Stop transcript if logging enabled
if ($LogPath) {
    Stop-Transcript
}

Write-Host "`n✓ Access review creation completed successfully!" -ForegroundColor Green
