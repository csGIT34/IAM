# Entra ID Group Access Reviews

A comprehensive PowerShell solution for creating, managing, and automating Entra ID group access reviews. This solution helps organizations maintain proper access governance by regularly reviewing group memberships and ensuring compliance with security policies.

## Overview

The Entra ID Group Access Reviews solution provides:
- Automated creation of access reviews for groups
- Bulk operations for multiple groups
- Customizable review settings and notifications
- Integration with Azure Automation for scheduled reviews
- Comprehensive reporting and analytics
- Compliance tracking and audit trails

## Features

### 🔍 **Access Review Management**
- **Single Group Reviews**: Create reviews for individual groups
- **Bulk Group Reviews**: Process multiple groups simultaneously
- **Recurring Reviews**: Set up automated recurring reviews
- **Custom Templates**: Use predefined review templates
- **Review Scheduling**: Schedule reviews for optimal timing

### 📊 **Review Configuration**
- **Review Scope**: Configure what to review (members, owners, guests)
- **Review Period**: Set review duration and frequency
- **Reviewers**: Assign group owners, managers, or specific users
- **Notifications**: Configure email notifications and reminders
- **Decision Options**: Customize approval/denial options

### 🚀 **Automation Features**
- **Azure Automation**: Schedule reviews through Azure Automation
- **PowerShell Scripting**: Fully scriptable for CI/CD integration
- **Batch Processing**: Handle large numbers of groups efficiently
- **Error Handling**: Comprehensive error handling and retry logic
- **Logging**: Detailed logging for audit and troubleshooting

### 📈 **Reporting & Analytics**
- **Review Status**: Track review progress and completion
- **Compliance Reports**: Generate compliance and governance reports
- **Decision Analytics**: Analyze review decisions and patterns
- **Audit Trails**: Maintain detailed audit logs
- **PowerBI Integration**: Ready for PowerBI dashboard integration

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Entra ID Access Reviews                      │
├─────────────────────────────────────────────────────────────────┤
│                    PowerShell Scripts                           │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
│  │ Create Reviews  │  │ Manage Reviews  │  │ Report Reviews  │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘ │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
│  │ Bulk Operations │  │ Notifications   │  │ Compliance      │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘ │
├─────────────────────────────────────────────────────────────────┤
│                    Microsoft Graph API                          │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
│  │ Access Reviews  │  │ Groups API      │  │ Users API       │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘ │
├─────────────────────────────────────────────────────────────────┤
│                    Entra ID Tenant                              │
└─────────────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites

- **PowerShell 5.1+**: Windows PowerShell or PowerShell Core
- **Microsoft Graph PowerShell SDK**: For Entra ID operations
- **Entra ID P2 License**: Required for access reviews functionality
- **Appropriate Permissions**: User Access Administrator or Global Administrator

### Installation

1. **Install required modules:**
   ```powershell
   .\Install-Prerequisites.ps1
   ```

2. **Configure authentication:**
   ```powershell
   .\Setup-Authentication.ps1
   ```

3. **Test connectivity:**
   ```powershell
   .\Test-AccessReviewsConnection.ps1
   ```

### Basic Usage

**Create a single group access review:**
```powershell
.\Create-GroupAccessReview.ps1 -GroupId "12345678-1234-1234-1234-123456789012" -ReviewName "IT Admin Group Review" -ReviewerIds @("user1@contoso.com", "user2@contoso.com")
```

**Create bulk access reviews:**
```powershell
.\Create-BulkAccessReviews.ps1 -GroupsCsvPath ".\groups.csv" -TemplateFile ".\templates\standard-review.json"
```

**Generate compliance report:**
```powershell
.\Get-AccessReviewsReport.ps1 -OutputPath ".\reports" -IncludeDecisions
```

## Scripts Overview

### Core Scripts

| Script | Description | Purpose |
|--------|-------------|---------|
| `Create-GroupAccessReview.ps1` | Create access review for single group | Primary creation script |
| `Create-BulkAccessReviews.ps1` | Create reviews for multiple groups | Bulk operations |
| `Manage-AccessReviews.ps1` | Manage existing reviews | Review management |
| `Get-AccessReviewsReport.ps1` | Generate reports and analytics | Reporting |
| `Setup-RecurringReviews.ps1` | Configure recurring reviews | Automation |

### Utility Scripts

| Script | Description | Purpose |
|--------|-------------|---------|
| `Install-Prerequisites.ps1` | Install required modules | Setup |
| `Setup-Authentication.ps1` | Configure authentication | Setup |
| `Test-AccessReviewsConnection.ps1` | Test connectivity | Validation |
| `Export-GroupsForReview.ps1` | Export groups for review | Data preparation |
| `Import-ReviewTemplates.ps1` | Import review templates | Configuration |

### Azure Automation Scripts

| Script | Description | Purpose |
|--------|-------------|---------|
| `AzureAutomation-AccessReviews.ps1` | Azure Automation runbook | Automation |
| `Setup-AzureAutomation.ps1` | Configure Azure Automation | Setup |
| `Schedule-AccessReviews.ps1` | Schedule automated reviews | Scheduling |

## Configuration

### Review Templates

Create standardized review templates for different scenarios:

```json
{
  "templateName": "Standard Group Review",
  "description": "Standard monthly group access review",
  "settings": {
    "reviewPeriod": "P30D",
    "recurrence": "Monthly",
    "autoReviewEnabled": false,
    "reviewerType": "GroupOwners",
    "fallbackReviewers": ["admin@contoso.com"],
    "notificationSettings": {
      "enableNotifications": true,
      "reminderFrequency": "Weekly",
      "escalationEnabled": true
    },
    "decisionSettings": {
      "defaultDecision": "None",
      "autoApplyDecisions": false,
      "justificationRequired": true
    }
  }
}
```

### Group Configuration

Define which groups should be reviewed:

```csv
GroupId,GroupName,ReviewTemplate,Reviewers,Priority
12345678-1234-1234-1234-123456789012,IT-Admins,HighPrivilege,manager@contoso.com,High
87654321-4321-4321-4321-210987654321,HR-Users,Standard,hr-manager@contoso.com,Medium
```

## Usage Examples

### Create Standard Access Review

```powershell
# Create a standard 30-day group access review
$params = @{
    GroupId = "12345678-1234-1234-1234-123456789012"
    ReviewName = "IT Admin Group - Monthly Review"
    Description = "Monthly access review for IT administrators"
    ReviewerIds = @("manager@contoso.com")
    DurationInDays = 30
    NotifyReviewers = $true
    RequireJustification = $true
}

.\Create-GroupAccessReview.ps1 @params
```

### Create Recurring Review

```powershell
# Create a recurring quarterly review
$params = @{
    GroupId = "12345678-1234-1234-1234-123456789012"
    ReviewName = "Privileged Access Review"
    ReviewerIds = @("security@contoso.com")
    RecurrencePattern = "Quarterly"
    DurationInDays = 14
    AutoApplyDecisions = $false
    FallbackReviewers = @("admin@contoso.com")
}

.\Create-GroupAccessReview.ps1 @params
```

### Bulk Create Reviews

```powershell
# Create reviews for multiple groups using CSV
$params = @{
    GroupsCsvPath = ".\config\groups-for-review.csv"
    TemplateFile = ".\templates\standard-review.json"
    OutputPath = ".\reports"
    ContinueOnError = $true
    MaxConcurrentReviews = 5
}

.\Create-BulkAccessReviews.ps1 @params
```

### Generate Compliance Report

```powershell
# Generate comprehensive compliance report
$params = @{
    OutputPath = ".\reports"
    IncludeDecisions = $true
    IncludeRecommendations = $true
    TimeRange = "Last90Days"
    OutputFormat = "HTML"
    GroupFilterPattern = "IT-*"
}

.\Get-AccessReviewsReport.ps1 @params
```

## Azure Automation Integration

### Setup Azure Automation

```powershell
# Configure Azure Automation for scheduled reviews
$params = @{
    SubscriptionId = "your-subscription-id"
    ResourceGroupName = "rg-automation"
    AutomationAccountName = "aa-access-reviews"
    RunbookName = "AccessReviews-Scheduler"
    Schedule = "Monthly"
    TimeZone = "Eastern Standard Time"
}

.\Setup-AzureAutomation.ps1 @params
```

### Scheduled Review Example

```powershell
# Azure Automation runbook for scheduled reviews
param(
    [string]$ConfigurationFile = "groups-config.json",
    [string]$NotificationEmail = "admin@contoso.com"
)

# Import configuration
$config = Get-AutomationVariable -Name "AccessReviewsConfig" | ConvertFrom-Json

# Create reviews for all configured groups
foreach ($group in $config.groups) {
    try {
        $reviewParams = @{
            GroupId = $group.id
            ReviewName = "$($group.name) - Scheduled Review"
            ReviewerIds = $group.reviewers
            DurationInDays = $group.reviewDuration
            NotifyReviewers = $true
        }
        
        .\Create-GroupAccessReview.ps1 @reviewParams
        Write-Output "Review created for group: $($group.name)"
    }
    catch {
        Write-Error "Failed to create review for group $($group.name): $($_.Exception.Message)"
    }
}
```

## Permissions Required

### Microsoft Graph API Permissions

**Application Permissions:**
- `AccessReview.ReadWrite.All`
- `Group.Read.All`
- `User.Read.All`
- `Directory.Read.All`

**Delegated Permissions:**
- `AccessReview.ReadWrite.All`
- `Group.Read.All`
- `User.Read.All`

### Entra ID Roles

**Required Roles:**
- **User Access Administrator**: For creating and managing access reviews
- **Global Administrator**: For full access review capabilities
- **Privileged Role Administrator**: For reviewing privileged groups

## Best Practices

### Security Considerations

1. **Principle of Least Privilege**: Only grant necessary permissions
2. **Regular Review Schedules**: Establish consistent review cycles
3. **Fallback Reviewers**: Always configure backup reviewers
4. **Audit Logging**: Enable comprehensive audit logging
5. **Secure Authentication**: Use managed identities where possible

### Operational Guidelines

1. **Review Frequency**: Align with business requirements and risk levels
2. **Reviewer Training**: Ensure reviewers understand their responsibilities
3. **Escalation Procedures**: Define clear escalation paths
4. **Documentation**: Maintain detailed documentation of review processes
5. **Testing**: Regularly test review processes and scripts

### Performance Optimization

1. **Batch Processing**: Process multiple groups efficiently
2. **Caching**: Cache frequently accessed data
3. **Parallel Processing**: Use parallel execution for bulk operations
4. **Error Handling**: Implement robust error handling and retry logic
5. **Monitoring**: Monitor performance and resource usage

## Troubleshooting

### Common Issues

**Issue**: Access reviews not created
- **Cause**: Insufficient permissions or missing Entra ID P2 license
- **Solution**: Verify permissions and licensing requirements

**Issue**: Reviewers not receiving notifications
- **Cause**: Email settings or reviewer configuration issues
- **Solution**: Check notification settings and reviewer email addresses

**Issue**: Bulk operations failing
- **Cause**: Rate limiting or timeout issues
- **Solution**: Implement retry logic and adjust batch sizes

### Debugging

Enable detailed logging:
```powershell
$VerbosePreference = "Continue"
$DebugPreference = "Continue"
.\Create-GroupAccessReview.ps1 -Verbose -Debug
```

## Compliance and Governance

### Regulatory Compliance

- **SOX**: Supports Sarbanes-Oxley compliance requirements
- **GDPR**: Helps with data protection and privacy requirements
- **HIPAA**: Supports healthcare compliance needs
- **PCI DSS**: Assists with payment card industry compliance

### Audit Requirements

- **Audit Trails**: Comprehensive logging of all activities
- **Decision Tracking**: Track all review decisions and justifications
- **Compliance Reports**: Generate reports for compliance audits
- **Data Retention**: Configurable data retention policies

## Integration

### PowerBI Integration

Create PowerBI dashboards for access review analytics:
- Review completion rates
- Decision trends and patterns
- Compliance metrics
- Risk indicators

### SIEM Integration

Export logs to SIEM solutions for security monitoring:
- Access review events
- Decision anomalies
- Compliance violations
- Security alerts

## Support and Maintenance

### Regular Tasks

1. **Monthly**: Review access review effectiveness
2. **Quarterly**: Update review templates and configurations
3. **Annually**: Conduct comprehensive review of the entire process
4. **As Needed**: Update scripts and address issues

### Updates and Patches

- Monitor Microsoft Graph API updates
- Update PowerShell modules regularly
- Test changes in non-production environments
- Maintain documentation and procedures

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Resources

- [Microsoft Graph Access Reviews API](https://docs.microsoft.com/en-us/graph/api/resources/accessreviews-root)
- [Entra ID Access Reviews Documentation](https://docs.microsoft.com/en-us/azure/active-directory/governance/access-reviews-overview)
- [PowerShell Gallery - Microsoft.Graph](https://www.powershellgallery.com/packages/Microsoft.Graph)
- [Azure Automation Documentation](https://docs.microsoft.com/en-us/azure/automation/)

---

**Note**: This solution requires Entra ID P2 licensing and appropriate permissions. Ensure you have the necessary licenses and permissions before implementing access reviews in your environment.
