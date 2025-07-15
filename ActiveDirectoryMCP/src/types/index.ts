/**
 * Type definitions for Active Directory MCP Server
 */

export interface ADConfig {
  activeDirectory: {
    domain: string;
    server: string;
    port: number;
    useSSL: boolean;
    baseDN: string;
    searchSizeLimit: number;
    searchTimeLimit: number;
  };
  authentication: {
    useServiceAccount: boolean;
    serviceAccountUsername: string;
    serviceAccountPassword: string;
    useIntegratedAuth: boolean;
    credentialSource: string;
  };
  security: {
    enableAuditLogging: boolean;
    auditLogPath: string;
    requireSecureConnection: boolean;
    allowedOperations: string[];
    restrictedOUs: string[];
    allowedAttributes: string[];
  };
  performance: {
    enableCaching: boolean;
    cacheExpiryMinutes: number;
    maxConcurrentOperations: number;
    queryTimeout: number;
    connectionPoolSize: number;
    retryAttempts: number;
    retryDelay: number;
  };
  mcp: {
    serverName: string;
    serverVersion: string;
    port: number;
    enableMetrics: boolean;
    enableHealthCheck: boolean;
    healthCheckInterval: number;
    maxRequestSize: string;
    requestTimeout: number;
  };
  logging: {
    level: string;
    format: string;
    logFile: string;
    maxFiles: number;
    maxSize: string;
    enableConsole: boolean;
    enableFile: boolean;
  };
  features: {
    enableUserOperations: boolean;
    enableGroupOperations: boolean;
    enableComputerOperations: boolean;
    enableOUOperations: boolean;
    enablePasswordReset: boolean;
    enableBulkOperations: boolean;
    enableReporting: boolean;
    enableMetrics: boolean;
  };
}

export interface ADUser {
  dn: string;
  cn: string;
  sAMAccountName: string;
  userPrincipalName: string;
  displayName: string;
  givenName: string;
  sn: string;
  mail: string;
  telephoneNumber: string;
  mobile: string;
  department: string;
  title: string;
  company: string;
  manager: string;
  directReports: string[];
  memberOf: string[];
  userAccountControl: number;
  accountExpires: Date | null;
  lastLogon: Date | null;
  lastLogonTimestamp: Date | null;
  pwdLastSet: Date | null;
  lockoutTime: Date | null;
  badPwdCount: number;
  whenCreated: Date;
  whenChanged: Date;
  description: string;
  enabled: boolean;
  locked: boolean;
  passwordExpired: boolean;
  passwordNeverExpires: boolean;
  mustChangePassword: boolean;
}

export interface ADGroup {
  dn: string;
  cn: string;
  sAMAccountName: string;
  displayName: string;
  description: string;
  groupType: number;
  groupScope: 'Global' | 'Universal' | 'DomainLocal';
  members: string[];
  memberOf: string[];
  managedBy: string;
  whenCreated: Date;
  whenChanged: Date;
  mail: string;
  groupCategory: 'Security' | 'Distribution';
}

export interface ADComputer {
  dn: string;
  cn: string;
  sAMAccountName: string;
  dNSHostName: string;
  operatingSystem: string;
  operatingSystemVersion: string;
  operatingSystemServicePack: string;
  lastLogon: Date | null;
  lastLogonTimestamp: Date | null;
  pwdLastSet: Date | null;
  userAccountControl: number;
  whenCreated: Date;
  whenChanged: Date;
  description: string;
  enabled: boolean;
  location: string;
  managedBy: string;
  memberOf: string[];
}

export interface ADOU {
  dn: string;
  name: string;
  ou: string;
  description: string;
  managedBy: string;
  whenCreated: Date;
  whenChanged: Date;
  children: ADOU[];
  users: ADUser[];
  groups: ADGroup[];
  computers: ADComputer[];
  gPLink: string;
  gPOptions: number;
}

export interface ADObject {
  dn: string;
  objectClass: string[];
  attributes: Record<string, any>;
  whenCreated: Date;
  whenChanged: Date;
}

export interface LDAPSearchOptions {
  filter: string;
  baseDN?: string;
  scope?: 'base' | 'one' | 'sub';
  attributes?: string[];
  limit?: number;
  timeout?: number;
}

export interface LDAPSearchResult {
  objects: ADObject[];
  hasMore: boolean;
  totalCount: number;
  executionTime: number;
}

export interface ToolRequest {
  name: string;
  arguments: Record<string, any>;
}

export interface ToolResponse {
  content: Array<{
    type: 'text' | 'json';
    text?: string;
    json?: any;
  }>;
  isError?: boolean;
}

export interface MCPTool {
  name: string;
  description: string;
  inputSchema: {
    type: string;
    properties: Record<string, any>;
    required?: string[];
  };
}

export interface ServerContext {
  config: ADConfig;
  logger: any;
  adService: any;
  authService: any;
  auditService: any;
  cacheService: any;
  metricsService: any;
}

export interface UserCreateRequest {
  username: string;
  displayName: string;
  email?: string;
  password: string;
  organizationalUnit?: string;
  department?: string;
  title?: string;
  manager?: string;
  enabled?: boolean;
  mustChangePassword?: boolean;
  passwordNeverExpires?: boolean;
  customAttributes?: Record<string, any>;
}

export interface UserUpdateRequest {
  identifier: string;
  properties: Record<string, any>;
  reason?: string;
}

export interface GroupCreateRequest {
  name: string;
  description?: string;
  organizationalUnit?: string;
  groupType?: 'security' | 'distribution';
  scope?: 'global' | 'universal' | 'domain-local';
  managedBy?: string;
  mail?: string;
}

export interface GroupMembershipRequest {
  groupIdentifier: string;
  memberIdentifier: string;
  reason?: string;
}

export interface PasswordResetRequest {
  identifier: string;
  newPassword: string;
  forceChange?: boolean;
  reason?: string;
}

export interface ReportRequest {
  reportType: string;
  timeRange?: string;
  outputFormat?: 'json' | 'csv' | 'html';
  organizationalUnit?: string;
  includeMembers?: boolean;
  includeRecommendations?: boolean;
  customFilters?: Record<string, any>;
}

export interface DirectoryHealthStatus {
  overall: 'healthy' | 'warning' | 'critical';
  domainControllers: DomainControllerStatus[];
  replication: ReplicationStatus;
  services: ServiceStatus[];
  lastChecked: Date;
  issues: HealthIssue[];
}

export interface DomainControllerStatus {
  name: string;
  ipAddress: string;
  site: string;
  roles: string[];
  status: 'online' | 'offline' | 'unreachable';
  lastContact: Date;
  responseTime: number;
  services: ServiceStatus[];
}

export interface ReplicationStatus {
  status: 'healthy' | 'warning' | 'critical';
  lastReplication: Date;
  replicationPartners: ReplicationPartner[];
  failures: ReplicationFailure[];
}

export interface ReplicationPartner {
  name: string;
  site: string;
  lastReplication: Date;
  status: 'healthy' | 'failed' | 'warning';
}

export interface ReplicationFailure {
  partner: string;
  error: string;
  failureTime: Date;
  failureCount: number;
}

export interface ServiceStatus {
  name: string;
  status: 'running' | 'stopped' | 'error';
  startType: 'automatic' | 'manual' | 'disabled';
  processId?: number;
}

export interface HealthIssue {
  severity: 'low' | 'medium' | 'high' | 'critical';
  category: string;
  message: string;
  recommendation: string;
  affectedObjects: string[];
  timestamp: Date;
}

export interface AuditLogEntry {
  timestamp: Date;
  operation: string;
  user: string;
  target: string;
  details: Record<string, any>;
  success: boolean;
  error?: string;
  ipAddress?: string;
  userAgent?: string;
}

export interface CacheEntry {
  key: string;
  value: any;
  timestamp: Date;
  expiresAt: Date;
  hitCount: number;
}

export interface MetricsData {
  timestamp: Date;
  toolCalls: Record<string, number>;
  errors: Record<string, number>;
  responseTime: Record<string, number>;
  cacheHits: number;
  cacheMisses: number;
  activeConnections: number;
  memoryUsage: number;
}

export interface PasswordPolicy {
  minLength: number;
  maxLength: number;
  minPasswordAge: number;
  maxPasswordAge: number;
  passwordHistory: number;
  complexityEnabled: boolean;
  lockoutDuration: number;
  lockoutThreshold: number;
  lockoutObservationWindow: number;
  reversibleEncryption: boolean;
}

export interface SecurityReport {
  reportType: string;
  generatedAt: Date;
  summary: {
    totalUsers: number;
    totalGroups: number;
    privilegedUsers: number;
    staleAccounts: number;
    securityIssues: number;
  };
  findings: SecurityFinding[];
  recommendations: SecurityRecommendation[];
}

export interface SecurityFinding {
  id: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  category: string;
  title: string;
  description: string;
  affectedObjects: string[];
  evidence: Record<string, any>;
  impact: string;
  remediation: string;
}

export interface SecurityRecommendation {
  id: string;
  priority: 'low' | 'medium' | 'high';
  category: string;
  title: string;
  description: string;
  actionItems: string[];
  estimatedEffort: string;
  impact: string;
}

export interface BulkOperationRequest {
  operation: string;
  targets: string[];
  properties?: Record<string, any>;
  dryRun?: boolean;
  continueOnError?: boolean;
  batchSize?: number;
}

export interface BulkOperationResult {
  requestId: string;
  operation: string;
  totalTargets: number;
  successCount: number;
  failureCount: number;
  skippedCount: number;
  results: BulkOperationItemResult[];
  startTime: Date;
  endTime: Date;
  duration: number;
}

export interface BulkOperationItemResult {
  target: string;
  success: boolean;
  error?: string;
  details?: Record<string, any>;
  timestamp: Date;
}

export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

export interface LogEntry {
  timestamp: Date;
  level: LogLevel;
  message: string;
  meta?: Record<string, any>;
  stack?: string;
}
