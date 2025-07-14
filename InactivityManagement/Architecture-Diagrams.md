# Architecture Diagrams

This document contains architecture diagrams for both the on-premises and Azure Automation versions of the Disable Inactive Users solution.

## Azure Automation Architecture

```mermaid
graph TB
    subgraph "Azure Cloud"
        subgraph "Azure Automation Account"
            AA[Azure Automation Account]
            MI[Managed Identity]
            RB[Runbook: DisableInactiveUsers]
            SCHED[Schedule]
            VARS[Variables]
            CREDS[Credentials]
        end
        
        subgraph "Azure Storage"
            ST[Storage Table: InactiveUsers]
        end
        
        subgraph "Microsoft Graph"
            MG[Microsoft Graph API]
            ENTRA[Entra ID Users]
            MAIL[Mail Service]
        end
        
        subgraph "PowerBI Service"
            PBI[PowerBI Dashboard]
            DS[Dataset]
            REFRESH[Scheduled Refresh]
        end
    end
    
    subgraph "On-Premises"
        subgraph "Hybrid Worker Server"
            HW[Hybrid Runbook Worker]
            ADMOD[ActiveDirectory Module]
        end
        
        subgraph "Active Directory"
            AD[Active Directory]
            DC[Domain Controllers]
            USERS[AD Users]
        end
    end
    
    subgraph "Email Recipients"
        RECIPIENTS[User Email Recipients]
    end
    
    %% Connections
    AA --> RB
    AA --> MI
    SCHED --> RB
    RB --> VARS
    RB --> CREDS
    RB --> HW
    HW --> ADMOD
    ADMOD --> AD
    AD --> DC
    DC --> USERS
    
    MI --> MG
    MG --> ENTRA
    MG --> MAIL
    MAIL --> RECIPIENTS
    
    RB --> ST
    ST --> PBI
    PBI --> DS
    DS --> REFRESH
    
    %% Styling
    classDef azure fill:#0078d4,stroke:#ffffff,stroke-width:2px,color:#ffffff
    classDef onprem fill:#00bcf2,stroke:#ffffff,stroke-width:2px,color:#ffffff
    classDef external fill:#107c10,stroke:#ffffff,stroke-width:2px,color:#ffffff
    
    class AA,MI,RB,SCHED,VARS,CREDS,ST,MG,ENTRA,MAIL,PBI,DS,REFRESH azure
    class HW,ADMOD,AD,DC,USERS onprem
    class RECIPIENTS external
```

## On-Premises Architecture (Legacy)

```mermaid
graph TB
    subgraph "On-Premises Server"
        subgraph "Windows Server"
            PS[PowerShell Script]
            TASK[Scheduled Task]
            CONFIG[Config File]
            LOG[Log Files]
        end
        
        subgraph "Active Directory"
            AD[Active Directory]
            DC[Domain Controllers]
            USERS[AD Users]
        end
    end
    
    subgraph "Azure Cloud"
        subgraph "Azure Key Vault"
            KV[Key Vault]
            SECRETS[Domain Credentials]
        end
        
        subgraph "Azure Storage"
            ST[Storage Table: InactiveUsers]
        end
        
        subgraph "Microsoft Graph"
            MG[Microsoft Graph API]
            ENTRA[Entra ID Users]
            MAIL[Mail Service]
            SP[Service Principal]
        end
        
        subgraph "PowerBI Service"
            PBI[PowerBI Dashboard]
            DS[Dataset]
            REFRESH[Scheduled Refresh]
        end
    end
    
    subgraph "Email Recipients"
        RECIPIENTS[User Email Recipients]
    end
    
    %% Connections
    TASK --> PS
    PS --> CONFIG
    PS --> LOG
    PS --> AD
    AD --> DC
    DC --> USERS
    
    PS --> KV
    KV --> SECRETS
    PS --> SP
    SP --> MG
    MG --> ENTRA
    MG --> MAIL
    MAIL --> RECIPIENTS
    
    PS --> ST
    ST --> PBI
    PBI --> DS
    DS --> REFRESH
    
    %% Styling
    classDef onprem fill:#00bcf2,stroke:#ffffff,stroke-width:2px,color:#ffffff
    classDef azure fill:#0078d4,stroke:#ffffff,stroke-width:2px,color:#ffffff
    classDef external fill:#107c10,stroke:#ffffff,stroke-width:2px,color:#ffffff
    
    class PS,TASK,CONFIG,LOG,AD,DC,USERS onprem
    class KV,SECRETS,ST,MG,ENTRA,MAIL,SP,PBI,DS,REFRESH azure
    class RECIPIENTS external
```

## Data Flow Diagram

```mermaid
sequenceDiagram
    participant SCHED as Scheduler
    participant RB as Runbook
    participant HW as Hybrid Worker
    participant AD as Active Directory
    participant MG as Microsoft Graph
    participant ST as Storage Table
    participant MAIL as Mail Service
    participant PBI as PowerBI
    
    SCHED->>RB: Trigger execution
    RB->>HW: Execute on Hybrid Worker
    
    Note over HW,AD: Process AD Users
    HW->>AD: Query inactive users
    AD-->>HW: Return user list
    HW->>AD: Disable inactive users
    
    Note over RB,MG: Process Entra ID Users
    RB->>MG: Query cloud users
    MG-->>RB: Return user list
    RB->>MG: Disable inactive users
    
    Note over RB,ST: Log Activities
    RB->>ST: Log processed users
    RB->>ST: Log actions taken
    
    Note over RB,MAIL: Send Notifications
    RB->>MG: Send email notifications
    MG->>MAIL: Process email
    MAIL-->>RB: Delivery confirmation
    
    Note over ST,PBI: Dashboard Updates
    ST->>PBI: Data refresh
    PBI->>PBI: Update visualizations
```

## Security Architecture

```mermaid
graph TB
    subgraph "Identity & Access"
        subgraph "Azure AD"
            MI[Managed Identity]
            API[Graph API Permissions]
            ROLES[RBAC Roles]
        end
        
        subgraph "Domain Authentication"
            CREDS[Automation Credentials]
            DOMAIN[Domain Service Accounts]
        end
    end
    
    subgraph "Data Protection"
        subgraph "Encryption"
            TLS[TLS/HTTPS]
            AES[AES-256 Encryption]
        end
        
        subgraph "Access Control"
            RBAC[Role-Based Access]
            RLS[Row-Level Security]
        end
    end
    
    subgraph "Monitoring & Auditing"
        subgraph "Logging"
            AALOG[Azure Automation Logs]
            STLOG[Storage Table Logs]
            ADLOG[AD Audit Logs]
        end
        
        subgraph "Alerting"
            ALERTS[Azure Alerts]
            PBIALT[PowerBI Alerts]
        end
    end
    
    %% Connections
    MI --> API
    MI --> ROLES
    CREDS --> DOMAIN
    
    API --> TLS
    STLOG --> AES
    
    RBAC --> RLS
    
    AALOG --> ALERTS
    STLOG --> PBIALT
    
    %% Styling
    classDef security fill:#d83b01,stroke:#ffffff,stroke-width:2px,color:#ffffff
    classDef monitoring fill:#ca5010,stroke:#ffffff,stroke-width:2px,color:#ffffff
    classDef protection fill:#8764b8,stroke:#ffffff,stroke-width:2px,color:#ffffff
    
    class MI,API,ROLES,CREDS,DOMAIN security
    class TLS,AES,RBAC,RLS protection
    class AALOG,STLOG,ADLOG,ALERTS,PBIALT monitoring
```

## Hybrid Worker Architecture

```mermaid
graph TB
    subgraph "Azure Cloud"
        subgraph "Azure Automation"
            AA[Automation Account]
            RB[Runbook]
            HWG[Hybrid Worker Group]
        end
        
        subgraph "Azure Arc"
            ARC[Arc Agent]
            EXT[Hybrid Worker Extension]
        end
    end
    
    subgraph "On-Premises Network"
        subgraph "Hybrid Worker Server"
            HW[Hybrid Runbook Worker]
            PS[PowerShell Runtime]
            ADMOD[AD PowerShell Module]
        end
        
        subgraph "Active Directory"
            DC1[Domain Controller 1]
            DC2[Domain Controller 2]
            FOREST[AD Forest]
        end
        
        subgraph "Network Security"
            FW[Firewall]
            PROXY[Proxy Server]
        end
    end
    
    %% Connections
    AA --> HWG
    HWG --> ARC
    ARC --> EXT
    EXT --> HW
    HW --> PS
    PS --> ADMOD
    
    ADMOD --> DC1
    ADMOD --> DC2
    DC1 --> FOREST
    DC2 --> FOREST
    
    HW --> FW
    FW --> PROXY
    PROXY --> ARC
    
    %% Styling
    classDef azure fill:#0078d4,stroke:#ffffff,stroke-width:2px,color:#ffffff
    classDef onprem fill:#00bcf2,stroke:#ffffff,stroke-width:2px,color:#ffffff
    classDef security fill:#d83b01,stroke:#ffffff,stroke-width:2px,color:#ffffff
    
    class AA,RB,HWG,ARC,EXT azure
    class HW,PS,ADMOD,DC1,DC2,FOREST onprem
    class FW,PROXY security
```

## PowerBI Dashboard Architecture

```mermaid
graph TB
    subgraph "Data Sources"
        ST[Azure Storage Table]
        AA[Azure Automation Logs]
        AD[Active Directory]
    end
    
    subgraph "PowerBI Service"
        subgraph "Data Layer"
            DS[Dataset]
            DM[Data Model]
            REFRESH[Scheduled Refresh]
        end
        
        subgraph "Visualization Layer"
            DASH[Dashboard]
            REPORT[Reports]
            ALERTS[Alerts]
        end
        
        subgraph "Security Layer"
            RLS[Row-Level Security]
            WORKSPACE[Workspace Security]
        end
    end
    
    subgraph "Access & Distribution"
        subgraph "Users"
            EXEC[Executives]
            ADMIN[IT Administrators]
            AUDIT[Auditors]
        end
        
        subgraph "Integration"
            TEAMS[Microsoft Teams]
            SP[SharePoint]
            EMAIL[Email Subscriptions]
        end
    end
    
    %% Connections
    ST --> DS
    AA --> DS
    AD --> DS
    
    DS --> DM
    DM --> REFRESH
    
    DM --> DASH
    DM --> REPORT
    DASH --> ALERTS
    
    RLS --> DASH
    WORKSPACE --> DASH
    
    DASH --> EXEC
    DASH --> ADMIN
    DASH --> AUDIT
    
    DASH --> TEAMS
    DASH --> SP
    ALERTS --> EMAIL
    
    %% Styling
    classDef data fill:#004578,stroke:#ffffff,stroke-width:2px,color:#ffffff
    classDef powerbi fill:#f2c811,stroke:#000000,stroke-width:2px,color:#000000
    classDef users fill:#107c10,stroke:#ffffff,stroke-width:2px,color:#ffffff
    classDef integration fill:#5c2d91,stroke:#ffffff,stroke-width:2px,color:#ffffff
    
    class ST,AA,AD data
    class DS,DM,REFRESH,DASH,REPORT,ALERTS,RLS,WORKSPACE powerbi
    class EXEC,ADMIN,AUDIT users
    class TEAMS,SP,EMAIL integration
```

## Network Architecture

```mermaid
graph TB
    subgraph "Internet"
        AZURE[Azure Cloud]
        O365[Microsoft 365]
    end
    
    subgraph "Corporate Network"
        subgraph "DMZ"
            PROXY[Proxy Server]
            FW[Firewall]
        end
        
        subgraph "Internal Network"
            subgraph "Server Subnet"
                HW[Hybrid Worker]
                DC[Domain Controllers]
            end
            
            subgraph "User Subnet"
                USERS[End Users]
                DEVICES[Devices]
            end
        end
    end
    
    %% Connections
    AZURE -.->|HTTPS 443| PROXY
    O365 -.->|HTTPS 443| PROXY
    PROXY --> FW
    FW --> HW
    HW --> DC
    DC --> USERS
    
    %% Styling
    classDef cloud fill:#0078d4,stroke:#ffffff,stroke-width:2px,color:#ffffff
    classDef network fill:#00bcf2,stroke:#ffffff,stroke-width:2px,color:#ffffff
    classDef security fill:#d83b01,stroke:#ffffff,stroke-width:2px,color:#ffffff
    classDef internal fill:#107c10,stroke:#ffffff,stroke-width:2px,color:#ffffff
    
    class AZURE,O365 cloud
    class PROXY,FW security
    class HW,DC,USERS,DEVICES internal
```

## Deployment Architecture

```mermaid
graph TB
    subgraph "Development"
        DEV[Development Environment]
        DEVTEST[Development Testing]
    end
    
    subgraph "Testing"
        TEST[Test Environment]
        UAT[User Acceptance Testing]
    end
    
    subgraph "Production"
        PROD[Production Environment]
        MONITOR[Production Monitoring]
    end
    
    subgraph "Disaster Recovery"
        DR[DR Environment]
        BACKUP[Backup & Recovery]
    end
    
    %% Connections
    DEV --> DEVTEST
    DEVTEST --> TEST
    TEST --> UAT
    UAT --> PROD
    PROD --> MONITOR
    PROD --> DR
    DR --> BACKUP
    
    %% Styling
    classDef dev fill:#40e0d0,stroke:#000000,stroke-width:2px,color:#000000
    classDef test fill:#ffb900,stroke:#000000,stroke-width:2px,color:#000000
    classDef prod fill:#107c10,stroke:#ffffff,stroke-width:2px,color:#ffffff
    classDef dr fill:#d83b01,stroke:#ffffff,stroke-width:2px,color:#ffffff
    
    class DEV,DEVTEST dev
    class TEST,UAT test
    class PROD,MONITOR prod
    class DR,BACKUP dr
```

## Key Architecture Benefits

### Azure Automation Architecture
- **Managed Identity**: Eliminates credential management overhead
- **Hybrid Worker**: Secure bridge between cloud and on-premises
- **Centralized Management**: Single pane of glass for configuration
- **Scalability**: Automatic scaling based on workload
- **High Availability**: Built-in redundancy and failover

### Security Architecture
- **Zero Trust**: Principle of least privilege access
- **Encryption**: Data encrypted in transit and at rest
- **Audit Trail**: Complete logging of all activities
- **Multi-Factor Authentication**: Required for administrative access
- **Role-Based Access**: Granular permission control

### Monitoring Architecture
- **Real-time Dashboards**: Live monitoring of system health
- **Predictive Analytics**: Identify trends and patterns
- **Automated Alerts**: Proactive issue detection
- **Compliance Reporting**: Automated compliance documentation
- **Performance Metrics**: Track system performance over time

These diagrams provide a comprehensive view of the solution architecture, helping stakeholders understand the system design, data flow, and security considerations.
