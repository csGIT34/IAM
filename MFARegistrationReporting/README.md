# MFA Registration Reporting Solution

## 🚀 Overview

The MFA Registration Reporting solution provides comprehensive analysis and reporting of Multi-Factor Authentication (MFA) registration status across your Entra ID environment. This PowerShell-based solution delivers detailed insights into user compliance, authentication methods, and security posture.

## ✨ Features

### 📊 Comprehensive Reporting
- **Real-time MFA registration status** for all users
- **Authentication method analysis** (SMS, Authenticator, FIDO2, etc.)
- **Risk level assessment** based on multiple factors
- **Compliance threshold monitoring** with customizable limits
- **Department and license-based filtering**
- **Executive dashboards** with visual summaries

### 🔄 Multi-Tenant Support
- **Bulk reporting across multiple tenants**
- **Consolidated cross-tenant dashboards**
- **Tenant-specific compliance tracking**
- **Centralized report management**

### 📈 Output Formats
- **HTML dashboards** with interactive charts
- **CSV exports** for data analysis
- **JSON format** for API integration
- **Console output** for quick checks

### 🛡️ Security & Compliance
- **Audit logging** of all report activities
- **Secure credential management**
- **Data retention policies**
- **Compliance framework alignment** (SOX, GDPR, HIPAA)

### ⚡ Automation & Scheduling
- **Automated report generation** via scheduled tasks
- **Email notifications** with report attachments
- **Configurable scheduling** (Daily, Weekly, Monthly)
- **Failure alerts** and retry mechanisms

## 🎯 Use Cases

### IT Security Teams
- Monitor MFA adoption rates across the organization
- Identify users at risk due to weak authentication
- Generate compliance reports for auditors
- Track security posture improvements over time

### IT Operations
- Automate routine MFA compliance reporting
- Bulk assessment of authentication methods
- Identify departments needing additional training
- Monitor license utilization and requirements

### Compliance Officers
- Generate reports for regulatory requirements
- Track progress against security policies
- Document security controls for audits
- Maintain evidence of due diligence

## 🏗️ Architecture

```mermaid
graph TB
    subgraph "Entra ID"
        USERS[Users]
        AUTHMETHODS[Authentication Methods]
        REPORTS[Reports API]
    end
    
    subgraph "MFA Reporting Solution"
        SCRIPT[PowerShell Scripts]
        CONFIG[Configuration]
        SCHEDULER[Scheduled Tasks]
    end
    
    subgraph "Microsoft Graph"
        GRAPH[Graph API]
        PERMISSIONS[Permissions]
    end
    
    subgraph "Output"
        HTML[HTML Reports]
        CSV[CSV Files]
        JSON[JSON Data]
        EMAIL[Email Notifications]
    end
    
    USERS --> GRAPH
    AUTHMETHODS --> GRAPH
    REPORTS --> GRAPH
    GRAPH --> SCRIPT
    CONFIG --> SCRIPT
    SCHEDULER --> SCRIPT
    SCRIPT --> HTML
    SCRIPT --> CSV
    SCRIPT --> JSON
    SCRIPT --> EMAIL
    
    classDef entra fill:#0078d4,stroke:#ffffff,stroke-width:2px,color:#ffffff
    classDef solution fill:#00bcf2,stroke:#ffffff,stroke-width:2px,color:#ffffff
    classDef graph fill:#5c2d91,stroke:#ffffff,stroke-width:2px,color:#ffffff
    classDef output fill:#107c10,stroke:#ffffff,stroke-width:2px,color:#ffffff
    
    class USERS,AUTHMETHODS,REPORTS entra
    class SCRIPT,CONFIG,SCHEDULER solution
    class GRAPH,PERMISSIONS graph
    class HTML,CSV,JSON,EMAIL output
```

## 🔧 Prerequisites

### Required Software
- **PowerShell 5.1** or later
- **Microsoft Graph PowerShell modules**
- **Windows 10/11** or **Windows Server 2016+**
- **Internet connectivity** to Microsoft Graph

### Required Permissions
- **Reports.Read.All** (Application permission)
- **User.Read.All** (Application permission)
- **UserAuthenticationMethod.Read.All** (Application permission)
- **Directory.Read.All** (Application permission)
- **AuditLog.Read.All** (Application permission)

### License Requirements
- **Entra ID P1** or **P2** licenses for users
- **Microsoft 365** or **Azure AD** subscription
- **MFA licenses** for authentication methods

## 🚀 Quick Start

### 1. Install Prerequisites
```powershell
# Run as Administrator
.\Install-Prerequisites.ps1
```

### 2. Configure Settings
Edit `config\reporting-config.json`:
```json
{
  "tenants": [
    {
      "id": "your-tenant-id",
      "name": "Production Tenant",
      "enabled": true
    }
  ],
  "reportSettings": {
    "complianceThreshold": 90,
    "includeAuthMethods": true,
    "generateRecommendations": true
  }
}
```

### 3. Generate Your First Report
```powershell
# Single tenant HTML report
.\Get-MFARegistrationStatus.ps1 -OutputFormat HTML -ExportPath ".\mfa-report.html" -IncludeAuthMethods

# Multi-tenant consolidated report
.\Start-BulkMFAReporting.ps1 -ConfigPath ".\config\reporting-config.json" -OutputDirectory ".\reports" -GenerateConsolidatedReport
```

## 📖 Detailed Usage

### Single Tenant Reporting

#### Basic Console Report
```powershell
.\Get-MFARegistrationStatus.ps1 -OutputFormat Console
```

#### Comprehensive HTML Report
```powershell
.\Get-MFARegistrationStatus.ps1 `
    -OutputFormat HTML `
    -ExportPath "C:\Reports\MFA-Status.html" `
    -IncludeAuthMethods `
    -GenerateRecommendations `
    -TenantId "your-tenant-id"
```

#### Filtered CSV Report
```powershell
.\Get-MFARegistrationStatus.ps1 `
    -OutputFormat CSV `
    -ExportPath ".\reports\mfa-report.csv" `
    -FilterByDepartment "IT" `
    -FilterByLicenseStatus "Licensed" `
    -IncludeDisabledUsers
```

#### JSON Export for Integration
```powershell
.\Get-MFARegistrationStatus.ps1 `
    -OutputFormat JSON `
    -ExportPath ".\data\mfa-status.json" `
    -IncludeAuthMethods `
    -GenerateRecommendations
```

### Multi-Tenant Bulk Reporting

#### Configuration-Based Bulk Reporting
```powershell
.\Start-BulkMFAReporting.ps1 `
    -ConfigPath ".\config\reporting-config.json" `
    -OutputDirectory "C:\Reports\MFA" `
    -GenerateConsolidatedReport `
    -ArchiveOldReports `
    -ArchiveAfterDays 30
```

#### Tenant-Specific Bulk Reporting
```powershell
.\Start-BulkMFAReporting.ps1 `
    -TenantIds @("tenant-1", "tenant-2") `
    -OutputDirectory ".\reports" `
    -ComplianceThreshold 95 `
    -GenerateConsolidatedReport
```

### Email Notifications

#### With Configuration File
```powershell
# Configure email in reporting-config.json
.\Start-BulkMFAReporting.ps1 `
    -ConfigPath ".\config\reporting-config.json" `
    -OutputDirectory ".\reports" `
    -GenerateConsolidatedReport
```

#### With Runtime Parameters
```powershell
$emailConfig = @{
    recipients = @("admin@company.com", "security@company.com")
    smtpServer = "smtp.office365.com"
    sender = "reports@company.com"
}

.\Start-BulkMFAReporting.ps1 `
    -TenantIds @("tenant-id") `
    -OutputDirectory ".\reports" `
    -EmailConfiguration $emailConfig
```

## 🔧 Configuration

### Main Configuration File
Location: `config\reporting-config.json`

```json
{
  "version": "1.0",
  "tenants": [
    {
      "id": "tenant-id",
      "name": "Tenant Name",
      "description": "Tenant description",
      "enabled": true,
      "priority": 1
    }
  ],
  "reportSettings": {
    "includeDisabledUsers": false,
    "includeAuthMethods": true,
    "generateRecommendations": true,
    "filterByLicenseStatus": "All",
    "complianceThreshold": 90,
    "outputFormats": ["HTML", "CSV", "JSON"],
    "archiveAfterDays": 30
  },
  "scheduling": {
    "enabled": false,
    "frequency": "Daily",
    "time": "09:00",
    "daysOfWeek": ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]
  },
  "emailConfiguration": {
    "enabled": false,
    "smtpServer": "smtp.office365.com",
    "smtpPort": 587,
    "useSSL": true,
    "sender": "reports@yourdomain.com",
    "recipients": ["admin@yourdomain.com"],
    "subject": "MFA Registration Status Report",
    "attachReports": true
  },
  "security": {
    "enableAuditLogging": true,
    "auditLogPath": "./logs/audit.log",
    "encryptReports": false,
    "dataRetentionDays": 365
  }
}
```

### Enterprise Template
Location: `config\enterprise-template.json`

Advanced configuration with compliance frameworks, custom fields, and branding options.

## 📊 Report Types

### Executive Summary Report
- **High-level statistics** and compliance rates
- **Trend analysis** and comparisons
- **Risk assessment** summary
- **Recommendation highlights**

### Detailed User Report
- **Individual user status** and authentication methods
- **Risk level assessment** per user
- **Compliance status** and recommendations
- **Department and license** breakdown

### Compliance Dashboard
- **Compliance framework** alignment
- **Policy adherence** tracking
- **Audit trail** information
- **Remediation** recommendations

### Consolidated Multi-Tenant Report
- **Cross-tenant** statistics
- **Tenant comparison** analysis
- **Consolidated compliance** status
- **Organization-wide** trends

## 🛠️ Automation & Scheduling

### Scheduled Tasks
Create automated reports using Windows Task Scheduler:

```powershell
# Create daily scheduled task
.\Install-Prerequisites.ps1 -CreateScheduledTask -TenantId "your-tenant-id"
```

### Custom Scheduling
Configure custom scheduling in `reporting-config.json`:

```json
{
  "scheduling": {
    "enabled": true,
    "frequency": "Weekly",
    "time": "08:00",
    "daysOfWeek": ["Monday"]
  }
}
```

### Azure Automation Integration
Deploy to Azure Automation for cloud-based scheduling:

```powershell
# Upload scripts to Azure Automation
# Configure managed identity permissions
# Create runbooks for scheduled execution
```

## 🔒 Security Considerations

### Permission Management
- Use **application permissions** for unattended execution
- Implement **least privilege** access principles
- Regular **permission audits** and reviews
- **Conditional access** policies for admin accounts

### Data Protection
- **Audit logging** of all report activities
- **Secure storage** of configuration files
- **Data retention** policies for reports
- **Access controls** for report directories

### Compliance Alignment
- **SOX** compliance for financial organizations
- **GDPR** requirements for EU data handling
- **HIPAA** standards for healthcare
- **Industry-specific** regulatory requirements

## 🚨 Troubleshooting

### Common Issues

#### Authentication Failures
```powershell
# Check current Graph connection
Get-MgContext

# Reconnect with required scopes
Connect-MgGraph -Scopes "Reports.Read.All","User.Read.All","UserAuthenticationMethod.Read.All"

# Verify permissions
(Get-MgContext).Scopes
```

#### Module Installation Issues
```powershell
# Install modules with elevated permissions
Install-Module Microsoft.Graph.Reports -Force -AllowClobber
Install-Module Microsoft.Graph.Users -Force -AllowClobber
Install-Module Microsoft.Graph.Authentication -Force -AllowClobber

# Check module versions
Get-Module Microsoft.Graph.* -ListAvailable
```

#### Permission Errors
```powershell
# Check current permissions
Get-MgContext | Select-Object Scopes

# Request additional permissions
Connect-MgGraph -Scopes "Reports.Read.All","User.Read.All","UserAuthenticationMethod.Read.All"
```

### Error Codes
- **AADSTS50001**: Invalid resource identifier
- **AADSTS65001**: User consent required
- **AADSTS90002**: Tenant not found
- **AADSTS16000**: Application not found

### Log Analysis
Check logs in `logs\` directory:
- `MFARegistrationReport_*.log` - Main execution logs
- `BulkMFAReporting_*.log` - Bulk operation logs
- `Install-Prerequisites_*.log` - Installation logs
- `audit.log` - Security audit trail

## 📈 Performance Optimization

### Batch Processing
- **Batch size**: 100 users per request
- **Concurrent requests**: 10 maximum
- **Request timeout**: 30 seconds
- **Retry logic**: 3 attempts with exponential backoff

### Memory Management
- **Streaming data** for large datasets
- **Garbage collection** optimization
- **Memory usage** monitoring
- **Resource cleanup** after operations

### Network Optimization
- **Connection pooling** for Graph requests
- **Compression** for large reports
- **CDN usage** for static resources
- **Caching** of frequently accessed data

## 📚 Best Practices

### Report Management
- **Regular archival** of old reports
- **Consistent naming** conventions
- **Version control** for configurations
- **Change tracking** for modifications

### Security Operations
- **Regular permission** reviews
- **Audit log** monitoring
- **Access control** implementation
- **Incident response** procedures

### Monitoring & Alerting
- **Success/failure** notifications
- **Performance metrics** tracking
- **Compliance threshold** alerts
- **Trend analysis** and reporting

## 🔄 Version History

### Version 1.0 (Current)
- Initial release with core functionality
- Single and multi-tenant reporting
- HTML, CSV, and JSON output formats
- Basic scheduling and automation
- Security and compliance features

### Planned Features
- **PowerBI integration** for advanced analytics
- **Teams notifications** for alerts
- **API endpoint** for real-time queries
- **Machine learning** for anomaly detection
- **Advanced compliance** frameworks

## 🤝 Contributing

### Development Environment
1. Clone the repository
2. Install development dependencies
3. Run tests and validation
4. Submit pull requests

### Code Standards
- **PowerShell best practices**
- **Error handling** implementation
- **Logging and debugging**
- **Documentation** requirements

## 📄 License

This solution is provided as-is under the MIT License. See LICENSE file for details.

## 🆘 Support

### Documentation
- **README files** for each component
- **Inline comments** in scripts
- **Configuration examples**
- **Troubleshooting guides**

### Community Resources
- **Issue tracking** via GitHub
- **Discussion forums** for questions
- **Feature requests** and feedback
- **Community contributions**

### Professional Support
- **Enterprise consulting** services
- **Custom development** options
- **Training and workshops**
- **Managed services** offerings

---

## 🎯 Getting Started Checklist

- [ ] Install prerequisites using `Install-Prerequisites.ps1`
- [ ] Configure tenant settings in `reporting-config.json`
- [ ] Set up required Microsoft Graph permissions
- [ ] Test connection with `Get-MFARegistrationStatus.ps1`
- [ ] Generate your first report
- [ ] Configure email notifications (optional)
- [ ] Set up automated scheduling (optional)
- [ ] Review security and compliance settings
- [ ] Plan report archival and retention
- [ ] Document your deployment and configuration

---

*For the latest updates and documentation, visit the [GitHub repository](https://github.com/your-org/iam-solutions).*
