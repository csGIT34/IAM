#!/usr/bin/env node
/**
 * Active Directory MCP Server
 * 
 * A Model Context Protocol server for Active Directory operations.
 * This server provides standardized interfaces for AI assistants to interact
 * with Active Directory services.
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { 
  CallToolRequestSchema, 
  ErrorCode, 
  ListToolsRequestSchema, 
  McpError 
} from '@modelcontextprotocol/sdk/types.js';

import { ADService } from './services/ad-service.js';
import { AuthService } from './services/auth-service.js';
import { AuditService } from './services/audit-service.js';
import { CacheService } from './services/cache-service.js';
import { ConfigService } from './services/config-service.js';
import { LoggerService } from './services/logger-service.js';
import { MetricsService } from './services/metrics-service.js';

import { QueryHandlers } from './handlers/query-handlers.js';
import { OperationHandlers } from './handlers/operation-handlers.js';
import { ReportHandlers } from './handlers/report-handlers.js';
import { ManagementHandlers } from './handlers/management-handlers.js';

import { 
  MCPTool, 
  ADConfig, 
  ServerContext,
  ToolRequest,
  ToolResponse 
} from './types/index.js';

class ActiveDirectoryMCPServer {
  private server: Server;
  private context: ServerContext;
  private queryHandlers: QueryHandlers;
  private operationHandlers: OperationHandlers;
  private reportHandlers: ReportHandlers;
  private managementHandlers: ManagementHandlers;

  constructor() {
    this.server = new Server(
      {
        name: 'active-directory-mcp-server',
        version: '1.0.0',
      },
      {
        capabilities: {
          tools: {},
        },
      }
    );

    this.initializeContext();
    this.initializeHandlers();
    this.setupServerHandlers();
  }

  private initializeContext(): void {
    const config = ConfigService.getInstance();
    
    this.context = {
      config: config.getConfig(),
      logger: LoggerService.getInstance(),
      adService: new ADService(config.getConfig()),
      authService: new AuthService(config.getConfig()),
      auditService: new AuditService(config.getConfig()),
      cacheService: new CacheService(config.getConfig()),
      metricsService: new MetricsService(config.getConfig())
    };
  }

  private initializeHandlers(): void {
    this.queryHandlers = new QueryHandlers(this.context);
    this.operationHandlers = new OperationHandlers(this.context);
    this.reportHandlers = new ReportHandlers(this.context);
    this.managementHandlers = new ManagementHandlers(this.context);
  }

  private setupServerHandlers(): void {
    this.server.setRequestHandler(ListToolsRequestSchema, async () => {
      const tools: MCPTool[] = [
        // Query Tools
        {
          name: 'query-user',
          description: 'Query user account information from Active Directory',
          inputSchema: {
            type: 'object',
            properties: {
              identifier: { 
                type: 'string', 
                description: 'Username, email, or distinguished name' 
              },
              properties: { 
                type: 'array', 
                items: { type: 'string' },
                description: 'Specific properties to retrieve' 
              },
              includeGroups: { 
                type: 'boolean', 
                description: 'Include group memberships' 
              }
            },
            required: ['identifier']
          }
        },
        {
          name: 'query-group',
          description: 'Query group information and membership',
          inputSchema: {
            type: 'object',
            properties: {
              identifier: { 
                type: 'string', 
                description: 'Group name or distinguished name' 
              },
              includeMembers: { 
                type: 'boolean', 
                description: 'Include group members' 
              },
              includeNestedGroups: { 
                type: 'boolean', 
                description: 'Include nested group memberships' 
              }
            },
            required: ['identifier']
          }
        },
        {
          name: 'query-computer',
          description: 'Query computer account information',
          inputSchema: {
            type: 'object',
            properties: {
              identifier: { 
                type: 'string', 
                description: 'Computer name or distinguished name' 
              },
              includeStatus: { 
                type: 'boolean', 
                description: 'Include online/offline status' 
              }
            },
            required: ['identifier']
          }
        },
        {
          name: 'query-ou',
          description: 'Query organizational unit structure',
          inputSchema: {
            type: 'object',
            properties: {
              identifier: { 
                type: 'string', 
                description: 'OU distinguished name' 
              },
              includeChildren: { 
                type: 'boolean', 
                description: 'Include child OUs' 
              },
              includeObjects: { 
                type: 'boolean', 
                description: 'Include objects in OU' 
              }
            },
            required: ['identifier']
          }
        },
        {
          name: 'search-directory',
          description: 'Perform LDAP search in Active Directory',
          inputSchema: {
            type: 'object',
            properties: {
              filter: { 
                type: 'string', 
                description: 'LDAP filter expression' 
              },
              baseDN: { 
                type: 'string', 
                description: 'Base distinguished name for search' 
              },
              scope: { 
                type: 'string', 
                enum: ['base', 'one', 'sub'],
                description: 'Search scope' 
              },
              attributes: { 
                type: 'array', 
                items: { type: 'string' },
                description: 'Attributes to retrieve' 
              },
              limit: { 
                type: 'number', 
                description: 'Maximum number of results' 
              }
            },
            required: ['filter']
          }
        },

        // Operation Tools
        {
          name: 'create-user',
          description: 'Create a new user account',
          inputSchema: {
            type: 'object',
            properties: {
              username: { type: 'string', description: 'Username' },
              displayName: { type: 'string', description: 'Display name' },
              email: { type: 'string', description: 'Email address' },
              password: { type: 'string', description: 'Initial password' },
              organizationalUnit: { type: 'string', description: 'OU DN' },
              department: { type: 'string', description: 'Department' },
              title: { type: 'string', description: 'Job title' },
              manager: { type: 'string', description: 'Manager DN' },
              enabled: { type: 'boolean', description: 'Enable account' }
            },
            required: ['username', 'displayName', 'password']
          }
        },
        {
          name: 'update-user',
          description: 'Update user account properties',
          inputSchema: {
            type: 'object',
            properties: {
              identifier: { type: 'string', description: 'User identifier' },
              properties: { 
                type: 'object', 
                description: 'Properties to update' 
              }
            },
            required: ['identifier', 'properties']
          }
        },
        {
          name: 'disable-user',
          description: 'Disable a user account',
          inputSchema: {
            type: 'object',
            properties: {
              identifier: { type: 'string', description: 'User identifier' },
              reason: { type: 'string', description: 'Reason for disabling' }
            },
            required: ['identifier']
          }
        },
        {
          name: 'enable-user',
          description: 'Enable a user account',
          inputSchema: {
            type: 'object',
            properties: {
              identifier: { type: 'string', description: 'User identifier' },
              reason: { type: 'string', description: 'Reason for enabling' }
            },
            required: ['identifier']
          }
        },
        {
          name: 'reset-password',
          description: 'Reset user password',
          inputSchema: {
            type: 'object',
            properties: {
              identifier: { type: 'string', description: 'User identifier' },
              newPassword: { type: 'string', description: 'New password' },
              forceChange: { type: 'boolean', description: 'Force password change at next logon' }
            },
            required: ['identifier', 'newPassword']
          }
        },
        {
          name: 'create-group',
          description: 'Create a new group',
          inputSchema: {
            type: 'object',
            properties: {
              name: { type: 'string', description: 'Group name' },
              description: { type: 'string', description: 'Group description' },
              organizationalUnit: { type: 'string', description: 'OU DN' },
              groupType: { 
                type: 'string', 
                enum: ['security', 'distribution'],
                description: 'Group type' 
              },
              scope: { 
                type: 'string', 
                enum: ['global', 'universal', 'domain-local'],
                description: 'Group scope' 
              }
            },
            required: ['name']
          }
        },
        {
          name: 'add-group-member',
          description: 'Add member to group',
          inputSchema: {
            type: 'object',
            properties: {
              groupIdentifier: { type: 'string', description: 'Group identifier' },
              memberIdentifier: { type: 'string', description: 'Member identifier' }
            },
            required: ['groupIdentifier', 'memberIdentifier']
          }
        },
        {
          name: 'remove-group-member',
          description: 'Remove member from group',
          inputSchema: {
            type: 'object',
            properties: {
              groupIdentifier: { type: 'string', description: 'Group identifier' },
              memberIdentifier: { type: 'string', description: 'Member identifier' }
            },
            required: ['groupIdentifier', 'memberIdentifier']
          }
        },

        // Management Tools
        {
          name: 'get-directory-health',
          description: 'Check Active Directory health status',
          inputSchema: {
            type: 'object',
            properties: {
              includeReplication: { type: 'boolean', description: 'Include replication status' },
              includeDomainControllers: { type: 'boolean', description: 'Include DC status' }
            }
          }
        },
        {
          name: 'get-replication-status',
          description: 'Get AD replication status',
          inputSchema: {
            type: 'object',
            properties: {
              domainController: { type: 'string', description: 'Specific DC to check' }
            }
          }
        },
        {
          name: 'get-password-policy',
          description: 'Get domain password policy',
          inputSchema: {
            type: 'object',
            properties: {
              domain: { type: 'string', description: 'Domain name' }
            }
          }
        },

        // Reporting Tools
        {
          name: 'generate-user-report',
          description: 'Generate user activity report',
          inputSchema: {
            type: 'object',
            properties: {
              reportType: { 
                type: 'string', 
                enum: ['inactive', 'privileged', 'recent-changes', 'password-expiry'],
                description: 'Type of report' 
              },
              timeRange: { type: 'string', description: 'Time range for report' },
              outputFormat: { 
                type: 'string', 
                enum: ['json', 'csv', 'html'],
                description: 'Output format' 
              },
              organizationalUnit: { type: 'string', description: 'Filter by OU' }
            },
            required: ['reportType']
          }
        },
        {
          name: 'generate-group-report',
          description: 'Generate group membership report',
          inputSchema: {
            type: 'object',
            properties: {
              reportType: { 
                type: 'string', 
                enum: ['membership', 'nested-groups', 'empty-groups', 'large-groups'],
                description: 'Type of report' 
              },
              includeMembers: { type: 'boolean', description: 'Include member details' },
              outputFormat: { 
                type: 'string', 
                enum: ['json', 'csv', 'html'],
                description: 'Output format' 
              }
            },
            required: ['reportType']
          }
        },
        {
          name: 'generate-security-report',
          description: 'Generate security and compliance report',
          inputSchema: {
            type: 'object',
            properties: {
              reportType: { 
                type: 'string', 
                enum: ['privileged-users', 'stale-accounts', 'password-policy', 'permissions-audit'],
                description: 'Type of report' 
              },
              includeRecommendations: { type: 'boolean', description: 'Include security recommendations' },
              outputFormat: { 
                type: 'string', 
                enum: ['json', 'csv', 'html'],
                description: 'Output format' 
              }
            },
            required: ['reportType']
          }
        }
      ];

      return { tools };
    });

    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;
      
      try {
        // Log the tool call
        this.context.logger.info(`Tool called: ${name}`, { args });
        this.context.auditService.logToolCall(name, args);
        this.context.metricsService.recordToolCall(name);

        // Route to appropriate handler
        let result: ToolResponse;
        
        switch (name) {
          // Query handlers
          case 'query-user':
            result = await this.queryHandlers.queryUser(args);
            break;
          case 'query-group':
            result = await this.queryHandlers.queryGroup(args);
            break;
          case 'query-computer':
            result = await this.queryHandlers.queryComputer(args);
            break;
          case 'query-ou':
            result = await this.queryHandlers.queryOU(args);
            break;
          case 'search-directory':
            result = await this.queryHandlers.searchDirectory(args);
            break;

          // Operation handlers
          case 'create-user':
            result = await this.operationHandlers.createUser(args);
            break;
          case 'update-user':
            result = await this.operationHandlers.updateUser(args);
            break;
          case 'disable-user':
            result = await this.operationHandlers.disableUser(args);
            break;
          case 'enable-user':
            result = await this.operationHandlers.enableUser(args);
            break;
          case 'reset-password':
            result = await this.operationHandlers.resetPassword(args);
            break;
          case 'create-group':
            result = await this.operationHandlers.createGroup(args);
            break;
          case 'add-group-member':
            result = await this.operationHandlers.addGroupMember(args);
            break;
          case 'remove-group-member':
            result = await this.operationHandlers.removeGroupMember(args);
            break;

          // Management handlers
          case 'get-directory-health':
            result = await this.managementHandlers.getDirectoryHealth(args);
            break;
          case 'get-replication-status':
            result = await this.managementHandlers.getReplicationStatus(args);
            break;
          case 'get-password-policy':
            result = await this.managementHandlers.getPasswordPolicy(args);
            break;

          // Report handlers
          case 'generate-user-report':
            result = await this.reportHandlers.generateUserReport(args);
            break;
          case 'generate-group-report':
            result = await this.reportHandlers.generateGroupReport(args);
            break;
          case 'generate-security-report':
            result = await this.reportHandlers.generateSecurityReport(args);
            break;

          default:
            throw new McpError(
              ErrorCode.MethodNotFound,
              `Unknown tool: ${name}`
            );
        }

        this.context.metricsService.recordToolSuccess(name);
        return result;

      } catch (error) {
        this.context.logger.error(`Tool execution failed: ${name}`, { error, args });
        this.context.auditService.logToolError(name, args, error);
        this.context.metricsService.recordToolError(name, error);

        if (error instanceof McpError) {
          throw error;
        }

        throw new McpError(
          ErrorCode.InternalError,
          `Tool execution failed: ${error instanceof Error ? error.message : 'Unknown error'}`
        );
      }
    });
  }

  public async start(): Promise<void> {
    try {
      // Initialize services
      await this.context.adService.initialize();
      await this.context.authService.initialize();
      await this.context.auditService.initialize();
      
      // Start the server
      const transport = new StdioServerTransport();
      await this.server.connect(transport);
      
      this.context.logger.info('Active Directory MCP Server started');
      
    } catch (error) {
      this.context.logger.error('Failed to start server', { error });
      process.exit(1);
    }
  }

  public async stop(): Promise<void> {
    try {
      // Cleanup services
      await this.context.adService.cleanup();
      await this.context.auditService.cleanup();
      
      this.context.logger.info('Active Directory MCP Server stopped');
      
    } catch (error) {
      this.context.logger.error('Error stopping server', { error });
    }
  }
}

// Handle graceful shutdown
process.on('SIGINT', async () => {
  console.log('Received SIGINT, shutting down gracefully...');
  process.exit(0);
});

process.on('SIGTERM', async () => {
  console.log('Received SIGTERM, shutting down gracefully...');
  process.exit(0);
});

// Start the server
const server = new ActiveDirectoryMCPServer();
server.start().catch((error) => {
  console.error('Failed to start server:', error);
  process.exit(1);
});
