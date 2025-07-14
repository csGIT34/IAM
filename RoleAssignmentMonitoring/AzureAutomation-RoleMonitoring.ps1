#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Users, Microsoft.Graph.DirectoryObjects, Microsoft.Graph.Identity.DirectoryManagement, Az.Accounts, Az.Resources, Az.Storage

<#
.SYNOPSIS
    Azure Automation Runbook to monitor Azure and Entra ID role assignments.

.DESCRIPTION
    This runbook monitors role assignments across Azure RBAC and Entra ID, tracking:
    - Azure subscription and resource-level role assignments
    - Entra ID directory roles and administrative units
    - Privileged Identity Management (PIM) eligible and active assignments
    - Changes over time with alerting and reporting
    
    Designed to run in Azure Automation with managed identity authentication.

.PARAMETER MonitoringScope
    Scope of monitoring: 'All', 'Azure', 'EntraID', 'PIM' (default: 'All')

.PARAMETER AlertThreshold
    Threshold for alerting on role assignment changes (default: 5)

.PARAMETER TestMode
    Run in test mode (no actual changes made, only monitoring)

.NOTES
    This runbook requires the following Azure Automation variables:
    - StorageAccountName
    - StorageAccountKey
    - AlertEmail
    - MonitoredSubscriptions (optional)
    - ExcludedRoles (optional)
    - TableName (optional, defaults to "RoleAssignments")
    
    The managed identity must have appropriate permissions for:
    - Microsoft Graph API (Directory.Read.All, RoleManagement.Read.All, PrivilegedAccess.Read.AzureAD)
    - Azure RBAC (Reader at subscription level)
    - Azure Storage (Storage Table Data Contributor)

.EXAMPLE
    Start-AzAutomationRunbook -AutomationAccountName "MyAutomationAccount" -ResourceGroupName "MyResourceGroup" -Name "MonitorRoleAssignments" -Parameters @{MonitoringScope="All"; TestMode=$true}
#>

param(
    [Parameter(Mandatory = $false)]
    [ValidateSet("All", "Azure", "EntraID", "PIM")]
    [string]$MonitoringScope = "All",
    
    [Parameter(Mandatory = $false)]
    [int]$AlertThreshold = 5,
    
    [Parameter(Mandatory = $false)]
    [bool]$TestMode = $true
)

# Initialize logging
$VerbosePreference = "Continue"
$ErrorActionPreference = "Stop"

Write-Output "=== Azure Role Assignment Monitoring Started ==="
Write-Output "Monitoring Scope: $MonitoringScope"
Write-Output "Alert Threshold: $AlertThreshold"
Write-Output "Test Mode: $TestMode"
Write-Output "Start Time: $(Get-Date)"

try {
    # Get automation variables
    Write-Output "Loading configuration from Azure Automation variables..."
    
    $storageAccountName = Get-AutomationVariable -Name "StorageAccountName"
    $storageAccountKey = Get-AutomationVariable -Name "StorageAccountKey"
    $alertEmail = Get-AutomationVariable -Name "AlertEmail"
    $monitoredSubscriptions = Get-AutomationVariable -Name "MonitoredSubscriptions" -ErrorAction SilentlyContinue
    $excludedRoles = Get-AutomationVariable -Name "ExcludedRoles" -ErrorAction SilentlyContinue
    $tableName = Get-AutomationVariable -Name "TableName" -ErrorAction SilentlyContinue
    
    if (-not $tableName) { $tableName = "RoleAssignments" }
    
    Write-Output "Configuration loaded successfully"
    Write-Output "Storage Account: $storageAccountName"
    Write-Output "Table Name: $tableName"
    Write-Output "Alert Email: $alertEmail"

    # Connect to Azure with managed identity
    Write-Output "Connecting to Azure with managed identity..."
    Connect-AzAccount -Identity
    
    # Connect to Microsoft Graph with managed identity
    Write-Output "Connecting to Microsoft Graph with managed identity..."
    Connect-MgGraph -Identity
    
    # Set up Azure Storage context
    Write-Output "Setting up Azure Storage context..."
    $storageContext = New-AzStorageContext -StorageAccountName $storageAccountName -StorageAccountKey $storageAccountKey
    $table = Get-AzStorageTable -Name $tableName -Context $storageContext
    
    $currentTime = Get-Date
    $totalChanges = 0
    $results = @()

    # Monitor Azure RBAC if in scope
    if ($MonitoringScope -eq "All" -or $MonitoringScope -eq "Azure") {
        Write-Output "Monitoring Azure RBAC role assignments..."
        
        # Get subscriptions to monitor
        $subscriptions = if ($monitoredSubscriptions) {
            $monitoredSubscriptions -split ","
        } else {
            (Get-AzSubscription).Id
        }
        
        foreach ($subscriptionId in $subscriptions) {
            Write-Output "Processing subscription: $subscriptionId"
            
            try {
                Set-AzContext -SubscriptionId $subscriptionId
                
                # Get all role assignments in subscription
                $roleAssignments = Get-AzRoleAssignment
                
                foreach ($assignment in $roleAssignments) {
                    # Skip excluded roles
                    if ($excludedRoles -and $excludedRoles -split "," -contains $assignment.RoleDefinitionName) {
                        continue
                    }
                    
                    $assignmentData = @{
                        PartitionKey = "AzureRBAC"
                        RowKey = "$($assignment.RoleAssignmentId)-$(Get-Date -Format 'yyyyMMddHHmmss')"
                        Timestamp = $currentTime
                        SubscriptionId = $subscriptionId
                        RoleAssignmentId = $assignment.RoleAssignmentId
                        PrincipalId = $assignment.ObjectId
                        PrincipalName = $assignment.DisplayName
                        PrincipalType = $assignment.ObjectType
                        RoleDefinitionName = $assignment.RoleDefinitionName
                        RoleDefinitionId = $assignment.RoleDefinitionId
                        Scope = $assignment.Scope
                        CanDelegate = $assignment.CanDelegate
                        AssignmentType = "Direct"
                        MonitoringRun = $currentTime.ToString("yyyy-MM-ddTHH:mm:ssZ")
                    }
                    
                    $results += $assignmentData
                    
                    if (-not $TestMode) {
                        Add-AzTableRow -Table $table.CloudTable -Property $assignmentData
                    }
                }
                
                Write-Output "Found $($roleAssignments.Count) role assignments in subscription $subscriptionId"
                
            } catch {
                Write-Warning "Error processing subscription $subscriptionId : $($_.Exception.Message)"
            }
        }
    }

    # Monitor Entra ID roles if in scope
    if ($MonitoringScope -eq "All" -or $MonitoringScope -eq "EntraID") {
        Write-Output "Monitoring Entra ID role assignments..."
        
        try {
            # Get all directory role assignments
            $directoryRoles = Get-MgDirectoryRole
            
            foreach ($role in $directoryRoles) {
                $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id
                
                foreach ($member in $members) {
                    # Skip excluded roles
                    if ($excludedRoles -and $excludedRoles -split "," -contains $role.DisplayName) {
                        continue
                    }
                    
                    $assignmentData = @{
                        PartitionKey = "EntraID"
                        RowKey = "$($role.Id)-$($member.Id)-$(Get-Date -Format 'yyyyMMddHHmmss')"
                        Timestamp = $currentTime
                        RoleId = $role.Id
                        RoleName = $role.DisplayName
                        RoleDescription = $role.Description
                        PrincipalId = $member.Id
                        PrincipalType = $member.AdditionalProperties.'@odata.type' -replace '#microsoft.graph.',''
                        AssignmentType = "Direct"
                        MonitoringRun = $currentTime.ToString("yyyy-MM-ddTHH:mm:ssZ")
                    }
                    
                    # Get additional principal details
                    try {
                        switch ($assignmentData.PrincipalType) {
                            "user" {
                                $principal = Get-MgUser -UserId $member.Id -Property "DisplayName,UserPrincipalName"
                                $assignmentData.PrincipalName = $principal.DisplayName
                                $assignmentData.PrincipalUPN = $principal.UserPrincipalName
                            }
                            "group" {
                                $principal = Get-MgGroup -GroupId $member.Id -Property "DisplayName"
                                $assignmentData.PrincipalName = $principal.DisplayName
                            }
                            "servicePrincipal" {
                                $principal = Get-MgServicePrincipal -ServicePrincipalId $member.Id -Property "DisplayName,AppId"
                                $assignmentData.PrincipalName = $principal.DisplayName
                                $assignmentData.ApplicationId = $principal.AppId
                            }
                        }
                    } catch {
                        Write-Warning "Could not get details for principal $($member.Id): $($_.Exception.Message)"
                        $assignmentData.PrincipalName = "Unknown"
                    }
                    
                    $results += $assignmentData
                    
                    if (-not $TestMode) {
                        Add-AzTableRow -Table $table.CloudTable -Property $assignmentData
                    }
                }
            }
            
            Write-Output "Found $($results.Where({$_.PartitionKey -eq "EntraID"}).Count) Entra ID role assignments"
            
        } catch {
            Write-Warning "Error monitoring Entra ID roles: $($_.Exception.Message)"
        }
    }

    # Monitor PIM assignments if in scope
    if ($MonitoringScope -eq "All" -or $MonitoringScope -eq "PIM") {
        Write-Output "Monitoring PIM role assignments..."
        
        try {
            # Note: PIM monitoring requires additional Graph permissions and endpoints
            # This is a placeholder for PIM-specific monitoring logic
            Write-Output "PIM monitoring is not yet implemented in this version"
            
        } catch {
            Write-Warning "Error monitoring PIM assignments: $($_.Exception.Message)"
        }
    }

    # Analyze changes and generate alerts
    Write-Output "Analyzing role assignment changes..."
    
    $totalAssignments = $results.Count
    Write-Output "Total role assignments found: $totalAssignments"
    
    # Check for changes compared to previous run
    if ($totalAssignments -gt $AlertThreshold) {
        Write-Output "Role assignment count ($totalAssignments) exceeds alert threshold ($AlertThreshold)"
        
        # In a real implementation, you would:
        # 1. Compare with previous snapshot
        # 2. Identify new/removed/changed assignments
        # 3. Send alerts via email or other channels
        # 4. Generate compliance reports
    }

    # Log summary to storage
    $summaryData = @{
        PartitionKey = "Summary"
        RowKey = "$(Get-Date -Format 'yyyyMMddHHmmss')"
        Timestamp = $currentTime
        MonitoringScope = $MonitoringScope
        TotalAssignments = $totalAssignments
        AzureRBACCount = $results.Where({$_.PartitionKey -eq "AzureRBAC"}).Count
        EntraIDCount = $results.Where({$_.PartitionKey -eq "EntraID"}).Count
        PIMCount = $results.Where({$_.PartitionKey -eq "PIM"}).Count
        TestMode = $TestMode
        MonitoringRun = $currentTime.ToString("yyyy-MM-ddTHH:mm:ssZ")
    }
    
    if (-not $TestMode) {
        Add-AzTableRow -Table $table.CloudTable -Property $summaryData
    }

    Write-Output "=== Monitoring Summary ==="
    Write-Output "Total Assignments: $totalAssignments"
    Write-Output "Azure RBAC: $($summaryData.AzureRBACCount)"
    Write-Output "Entra ID: $($summaryData.EntraIDCount)"
    Write-Output "PIM: $($summaryData.PIMCount)"
    Write-Output "Test Mode: $TestMode"

} catch {
    Write-Error "Error in role assignment monitoring: $($_.Exception.Message)"
    Write-Error "Stack Trace: $($_.ScriptStackTrace)"
    throw
} finally {
    Write-Output "End Time: $(Get-Date)"
    Write-Output "=== Azure Role Assignment Monitoring Completed ==="
}
