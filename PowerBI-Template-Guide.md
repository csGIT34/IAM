# PowerBI Dashboard Template for Inactive Users

## Solution Architecture

For detailed architecture diagrams showing how this PowerBI dashboard integrates with the Azure Automation solution, see [Architecture-Diagrams.md](Architecture-Diagrams.md#powerbi-dashboard-architecture).

This template provides a pre-configured PowerBI dashboard for visualizing inactive user data from Azure Storage Table.

## Template Contents

### Data Source Configuration
- **Azure Storage Table** connection
- **Parameterized** for easy deployment
- **Optimized queries** for performance

### Pre-built Visualizations
1. **Executive Summary Cards**
2. **Activity Trends**
3. **Domain Analysis**
4. **Risk Assessment**
5. **Compliance Reporting**

### Key Metrics
- Total users processed
- Users disabled per month
- Notification effectiveness
- Average days inactive
- Risk distribution

## Using the Template

### Step 1: Download Template
Download the PowerBI template file (`InactiveUsersTemplate.pbit`) from the repository.

### Step 2: Open Template
1. Open PowerBI Desktop
2. File > Open > Browse to the template file
3. Double-click the `.pbit` file

### Step 3: Configure Parameters
When prompted, enter:
- **Storage Account Name**: Your Azure Storage account name
- **Storage Account Key**: Your storage account access key
- **Table Name**: "InactiveUsers" (or your configured table name)
- **Date Range**: Number of days to include (e.g., 365)

### Step 4: Refresh Data
1. Click **Refresh** to load data
2. Review the visualizations
3. Customize as needed

### Step 5: Publish to PowerBI Service
1. Sign in to PowerBI Service
2. File > Publish > To PowerBI
3. Select your workspace
4. Configure scheduled refresh

## Template Structure

```
Dashboard Pages:
├── Executive Summary
│   ├── Key Metrics Cards
│   ├── Monthly Trends
│   └── Risk Overview
├── Detailed Analysis
│   ├── User Activity Table
│   ├── Domain Breakdown
│   └── Action Timeline
├── Compliance Report
│   ├── Audit Summary
│   ├── Policy Compliance
│   └── Exception Tracking
└── Operational Metrics
    ├── Processing Performance
    ├── Error Tracking
    └── System Health
```

## Customization Options

### Branding
- Replace logo placeholder with your organization's logo
- Update color scheme to match corporate branding
- Modify report titles and descriptions

### Filters
- Add department-specific filters
- Include geographic region filters
- Create role-based access filters

### Additional Visualizations
- Add custom KPIs
- Include forecast models
- Create drill-through pages

## Data Model

### Tables
- **InactiveUsers**: Main fact table
- **Calendar**: Date dimension
- **AccountTypes**: Account type lookup
- **Actions**: Action type lookup

### Relationships
- InactiveUsers[ProcessedDate] → Calendar[Date]
- InactiveUsers[AccountType] → AccountTypes[Type]
- InactiveUsers[Action] → Actions[ActionType]

### Measures
```dax
// Key Performance Indicators
Total Users = COUNTROWS(InactiveUsers)
Users Disabled = CALCULATE(COUNTROWS(InactiveUsers), SEARCH("Disabled", InactiveUsers[Action], 1, 0) > 0)
Notification Rate = DIVIDE([Notifications Sent], [Users Disabled], 0)
Avg Days Inactive = AVERAGE(InactiveUsers[DaysInactive])

// Time Intelligence
Users Disabled MTD = CALCULATE([Users Disabled], DATESMTD(Calendar[Date]))
Users Disabled YTD = CALCULATE([Users Disabled], DATESYTD(Calendar[Date]))
MoM Growth = DIVIDE([Users Disabled] - [Users Disabled Previous Month], [Users Disabled Previous Month])

// Risk Assessment
High Risk Users = CALCULATE(COUNTROWS(InactiveUsers), InactiveUsers[DaysInactive] >= 180)
Medium Risk Users = CALCULATE(COUNTROWS(InactiveUsers), InactiveUsers[DaysInactive] >= 90 && InactiveUsers[DaysInactive] < 180)
Low Risk Users = CALCULATE(COUNTROWS(InactiveUsers), InactiveUsers[DaysInactive] < 90)
```

## Row-Level Security

### Setup
1. **Create Security Roles**:
   - Domain Admins: See all data
   - Department Managers: See department data only
   - Auditors: Read-only access to all data

2. **Define Filters**:
   ```dax
   // Department Filter
   [Department] = USERNAME()
   
   // Domain Filter
   [AccountType] = LOOKUPVALUE(UserDomains[Domain], UserDomains[Email], USERNAME())
   ```

3. **Test Security**:
   - Use "View as" feature in PowerBI Desktop
   - Test with different user accounts
   - Validate filter effectiveness

## Deployment Guide

### PowerBI Service
1. **Create Workspace**: Dedicated workspace for IAM reports
2. **Import Template**: Upload and configure
3. **Set Permissions**: Assign user roles
4. **Schedule Refresh**: Configure automatic updates

### PowerBI Premium
1. **Paginated Reports**: For detailed compliance reports
2. **Dataflows**: For data transformation
3. **Deployment Pipelines**: For Dev/Test/Prod environments

### PowerBI Embedded
1. **App Registration**: Create Azure AD app
2. **Embed Code**: Integrate into existing applications
3. **Security**: Implement app-owns-data model

## Monitoring and Maintenance

### Refresh Monitoring
```powershell
# PowerShell script to monitor refresh status
$workspaceId = "your-workspace-id"
$datasetId = "your-dataset-id"

# Get refresh history
$refreshHistory = Get-PowerBIDatasetRefreshHistory -WorkspaceId $workspaceId -DatasetId $datasetId

# Check latest refresh status
$latestRefresh = $refreshHistory | Select-Object -First 1
if ($latestRefresh.Status -eq "Failed") {
    # Send alert
    Send-MailMessage -To "admin@company.com" -Subject "PowerBI Refresh Failed" -Body "Dashboard refresh failed: $($latestRefresh.ErrorMessage)"
}
```

### Performance Optimization
1. **Query Optimization**: Use query folding where possible
2. **Incremental Refresh**: For large datasets
3. **Aggregations**: Pre-calculate common metrics
4. **Composite Models**: Combine DirectQuery and Import

## Troubleshooting

### Common Issues
1. **Data Source Errors**:
   - Verify storage account credentials
   - Check network connectivity
   - Validate table schema

2. **Performance Issues**:
   - Optimize DAX queries
   - Use appropriate data types
   - Implement incremental refresh

3. **Visual Errors**:
   - Check data model relationships
   - Validate measure calculations
   - Review filter interactions

### Support Resources
- PowerBI Community Forums
- Microsoft Documentation
- Internal IT Support
- Azure Support (for storage issues)

## Security Best Practices

1. **Data Protection**:
   - Use Azure AD authentication
   - Implement row-level security
   - Regular access reviews

2. **Compliance**:
   - Data retention policies
   - Audit trail maintenance
   - GDPR compliance considerations

3. **Monitoring**:
   - Usage metrics tracking
   - Access pattern analysis
   - Security incident detection

This template provides a solid foundation for monitoring and analyzing inactive user data, helping organizations maintain security compliance and make informed decisions about user access management.
