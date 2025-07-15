# Active Directory MCP Server

A Model Context Protocol (MCP) server implementation for Active Directory operations and management. This server provides a standardized interface for AI assistants to interact with Active Directory services through the MCP protocol.

## Overview

The Active Directory MCP Server enables AI assistants to:
- Query Active Directory objects (users, groups, computers, OUs)
- Perform directory operations (create, update, disable users/groups)
- Retrieve security and permissions information
- Monitor directory health and status
- Generate reports on directory structure and membership

## Features

### 🔍 **Directory Queries**
- **User Management**: Query user accounts, properties, and membership
- **Group Management**: Retrieve group information and membership details
- **Computer Objects**: Access computer account information and status
- **Organizational Units**: Navigate OU structure and permissions
- **Security Principals**: Query security identifiers and permissions

### 📝 **Directory Operations**
- **User Operations**: Create, update, enable/disable user accounts
- **Group Operations**: Create/modify groups and manage membership
- **Password Management**: Reset passwords and manage password policies
- **Organizational Structure**: Create and manage OUs
- **Bulk Operations**: Process multiple directory changes efficiently

### 🔐 **Security Features**
- **Authentication**: Secure connection to Active Directory
- **Authorization**: Role-based access control for operations
- **Audit Logging**: Comprehensive logging of all directory operations
- **Permission Validation**: Verify permissions before operations
- **Compliance**: Support for regulatory compliance requirements

### 📊 **Reporting & Analytics**
- **Directory Health**: Monitor directory service health
- **User Analytics**: Track user activity and access patterns
- **Group Analysis**: Analyze group membership and permissions
- **Security Reports**: Generate security and compliance reports
- **Performance Metrics**: Monitor directory operation performance

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    MCP Client (AI Assistant)                    │
├─────────────────────────────────────────────────────────────────┤
│                    MCP Protocol Layer                           │
├─────────────────────────────────────────────────────────────────┤
│                 Active Directory MCP Server                     │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
│  │  Query Handler  │  │ Operation Handler│  │  Report Handler │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘ │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
│  │ Security Layer  │  │  Audit Logger   │  │  Cache Manager  │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘ │
├─────────────────────────────────────────────────────────────────┤
│                    Active Directory APIs                        │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
│  │   LDAP Client   │  │  PowerShell AD  │  │  .NET Directory │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘ │
├─────────────────────────────────────────────────────────────────┤
│                    Active Directory Domain                      │
└─────────────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites

- **Active Directory Domain**: Access to an Active Directory domain
- **PowerShell 5.1+**: Windows PowerShell or PowerShell Core
- **Node.js 18+**: Required for MCP server runtime
- **Active Directory Module**: PowerShell Active Directory module
- **Appropriate Permissions**: Domain user or service account with required permissions

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/your-org/IAM.git
   cd IAM/ActiveDirectoryMCP
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Configure the server:**
   ```bash
   cp config.example.json config.json
   # Edit config.json with your AD settings
   ```

4. **Install PowerShell modules:**
   ```powershell
   .\Install-Prerequisites.ps1
   ```

5. **Start the server:**
   ```bash
   npm start
   ```

### Configuration

Create a `config.json` file with your Active Directory settings:

```json
{
  "activeDirectory": {
    "domain": "contoso.com",
    "server": "dc01.contoso.com",
    "port": 389,
    "useSSL": true,
    "baseDN": "DC=contoso,DC=com"
  },
  "authentication": {
    "useServiceAccount": true,
    "serviceAccountUsername": "svc-mcp-ad",
    "serviceAccountPassword": "password-or-use-keyfile",
    "useIntegratedAuth": false
  },
  "security": {
    "enableAuditLogging": true,
    "auditLogPath": "./logs/audit.log",
    "requireSecureConnection": true,
    "allowedOperations": ["query", "create", "update", "disable"],
    "restrictedOUs": ["CN=Domain Controllers,DC=contoso,DC=com"]
  },
  "performance": {
    "enableCaching": true,
    "cacheExpiryMinutes": 15,
    "maxConcurrentOperations": 10,
    "queryTimeout": 30000
  },
  "mcp": {
    "serverName": "active-directory-mcp",
    "serverVersion": "1.0.0",
    "port": 3000,
    "enableMetrics": true
  }
}
```

## Usage Examples

### Basic User Query

```typescript
// Query user information
const userInfo = await mcpClient.callTool('query-user', {
  identifier: 'john.doe',
  properties: ['displayName', 'mail', 'department', 'manager']
});
```

### Group Management

```typescript
// Get group membership
const groupMembers = await mcpClient.callTool('get-group-members', {
  groupName: 'Domain Admins',
  includeNestedGroups: true
});

// Add user to group
await mcpClient.callTool('add-group-member', {
  groupName: 'IT-Users',
  memberIdentifier: 'jane.smith'
});
```

### Directory Operations

```typescript
// Create new user
await mcpClient.callTool('create-user', {
  username: 'new.user',
  displayName: 'New User',
  email: 'new.user@contoso.com',
  department: 'IT',
  organizationalUnit: 'OU=Users,DC=contoso,DC=com'
});

// Disable user account
await mcpClient.callTool('disable-user', {
  identifier: 'former.employee',
  reason: 'Employee termination'
});
```

### Reporting

```typescript
// Generate security report
const securityReport = await mcpClient.callTool('generate-security-report', {
  reportType: 'privileged-users',
  includeGroups: ['Domain Admins', 'Enterprise Admins'],
  outputFormat: 'json'
});
```

## Available Tools

### Query Tools
- `query-user` - Retrieve user account information
- `query-group` - Get group details and membership
- `query-computer` - Access computer account information
- `query-ou` - Navigate organizational unit structure
- `search-directory` - Perform LDAP searches

### Operation Tools
- `create-user` - Create new user accounts
- `update-user` - Modify user properties
- `disable-user` - Disable user accounts
- `enable-user` - Enable user accounts
- `reset-password` - Reset user passwords
- `create-group` - Create new groups
- `update-group` - Modify group properties
- `add-group-member` - Add members to groups
- `remove-group-member` - Remove members from groups

### Management Tools
- `get-directory-health` - Check directory service health
- `get-replication-status` - Monitor AD replication
- `get-password-policy` - Retrieve password policies
- `get-group-policy` - Query group policy settings

### Reporting Tools
- `generate-user-report` - Create user activity reports
- `generate-group-report` - Generate group membership reports
- `generate-security-report` - Security and compliance reports
- `generate-audit-report` - Audit log analysis

## Security Considerations

### Authentication
- Use dedicated service accounts with minimal required permissions
- Support for integrated Windows authentication
- Secure credential storage and management

### Authorization
- Role-based access control for MCP operations
- Granular permission validation
- Restricted operations for sensitive OUs

### Auditing
- Comprehensive audit logging of all operations
- Integration with Windows Event Log
- Support for SIEM integration

### Network Security
- SSL/TLS encryption for LDAP connections
- Network segmentation recommendations
- Firewall configuration guidelines

## Development

### Setup Development Environment

```bash
# Install development dependencies
npm install --dev

# Run tests
npm test

# Run with development settings
npm run dev
```

### Project Structure

```
ActiveDirectoryMCP/
├── src/
│   ├── server.ts              # Main MCP server implementation
│   ├── handlers/              # Tool handlers
│   │   ├── query-handlers.ts  # Directory query operations
│   │   ├── operation-handlers.ts # Directory modification operations
│   │   └── report-handlers.ts # Reporting and analytics
│   ├── services/              # Core services
│   │   ├── ad-service.ts      # Active Directory service layer
│   │   ├── auth-service.ts    # Authentication service
│   │   ├── audit-service.ts   # Audit logging service
│   │   └── cache-service.ts   # Caching service
│   ├── types/                 # TypeScript type definitions
│   └── utils/                 # Utility functions
├── scripts/                   # PowerShell scripts
│   ├── Install-Prerequisites.ps1
│   ├── Test-ADConnection.ps1
│   └── Setup-ServiceAccount.ps1
├── tests/                     # Test suites
├── config/                    # Configuration files
├── docs/                      # Additional documentation
└── package.json
```

### Testing

```bash
# Run all tests
npm test

# Run integration tests
npm run test:integration

# Run PowerShell tests
pwsh -Command "Invoke-Pester ./tests/powershell"

# Test AD connection
.\scripts\Test-ADConnection.ps1
```

## Deployment

### Production Deployment

1. **Server Setup:**
   ```bash
   # Create production build
   npm run build
   
   # Install PM2 for process management
   npm install -g pm2
   
   # Start with PM2
   pm2 start ecosystem.config.js
   ```

2. **Service Account Setup:**
   ```powershell
   # Create service account
   .\scripts\Setup-ServiceAccount.ps1 -Username "svc-mcp-ad" -Description "MCP AD Service Account"
   ```

3. **Monitoring:**
   ```bash
   # Monitor with PM2
   pm2 monitor
   
   # View logs
   pm2 logs
   ```

### Docker Deployment

```dockerfile
# Use official Node.js runtime
FROM node:18-alpine

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --production

# Copy source code
COPY . .

# Build application
RUN npm run build

# Expose port
EXPOSE 3000

# Start application
CMD ["npm", "start"]
```

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/new-feature`
3. Commit your changes: `git commit -am 'Add new feature'`
4. Push to the branch: `git push origin feature/new-feature`
5. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

For support and questions:
- **Documentation**: Check the [docs/](docs/) directory
- **Issues**: Submit issues on GitHub
- **Discussions**: Use GitHub Discussions for questions

## Roadmap

- [ ] **v1.1**: Enhanced security features and compliance reporting
- [ ] **v1.2**: Azure AD integration and hybrid scenarios
- [ ] **v1.3**: Advanced analytics and machine learning insights
- [ ] **v1.4**: Multi-domain and forest support
- [ ] **v2.0**: Cloud-native architecture and microservices
