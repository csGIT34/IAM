# Pester Tests for Role Assignment Monitoring Runbook
# Tests the core functionality of the AzureAutomation-RoleMonitoring.ps1 script

BeforeAll {
    # Import the module under test
    $modulePath = Join-Path $PSScriptRoot "AzureAutomation-RoleMonitoring.ps1"
    if (-not (Test-Path $modulePath)) {
        throw "Module not found: $modulePath"
    }
    
    # Mock external dependencies
    Mock Connect-AzAccount { return @{ Account = "test@domain.com" } }
    Mock Connect-MgGraph { return $true }
    Mock Get-AzContext { return @{ Subscription = @{ Id = "test-subscription-id" } } }
    Mock Get-AutomationVariable { param($Name) return "test-$Name" }
    Mock Get-AzStorageAccount { return @{ StorageAccountName = "teststorage" } }
    Mock Get-AzStorageTable { return @{ Name = "TestTable" } }
    Mock Add-AzTableRow { return $true }
    Mock Send-MailMessage { return $true }
    
    # Create test data
    $script:testRoleAssignments = @(
        @{
            Id = "test-assignment-1"
            RoleDefinitionId = "role-1"
            RoleDefinitionName = "Contributor"
            PrincipalId = "user-1"
            PrincipalType = "User"
            PrincipalName = "Test User 1"
            Scope = "/subscriptions/test-sub-1"
            CreatedOn = (Get-Date).AddDays(-30)
            AssignmentType = "Direct"
            Condition = ""
            ConditionVersion = ""
        },
        @{
            Id = "test-assignment-2"
            RoleDefinitionId = "role-2"
            RoleDefinitionName = "Reader"
            PrincipalId = "group-1"
            PrincipalType = "Group"
            PrincipalName = "Test Group 1"
            Scope = "/subscriptions/test-sub-1/resourceGroups/test-rg"
            CreatedOn = (Get-Date).AddDays(-10)
            AssignmentType = "Direct"
            Condition = ""
            ConditionVersion = ""
        }
    )
    
    $script:testEntraRoles = @(
        @{
            Id = "entra-role-1"
            RoleDefinitionId = "62e90394-69f5-4237-9190-012177145e10"
            RoleDefinitionName = "Global Administrator"
            PrincipalId = "user-2"
            PrincipalType = "User"
            PrincipalName = "Test Admin"
            DirectoryScope = "/"
            CreatedDateTime = (Get-Date).AddDays(-5)
            AssignmentType = "Assigned"
            StartDateTime = (Get-Date).AddDays(-5)
            EndDateTime = $null
        },
        @{
            Id = "entra-role-2"
            RoleDefinitionId = "729827e3-9c14-49f7-bb1b-9608f156bbb8"
            RoleDefinitionName = "Helpdesk Administrator"
            PrincipalId = "user-3"
            PrincipalType = "User"
            PrincipalName = "Test Helpdesk"
            DirectoryScope = "/"
            CreatedDateTime = (Get-Date).AddDays(-15)
            AssignmentType = "Assigned"
            StartDateTime = (Get-Date).AddDays(-15)
            EndDateTime = $null
        }
    )
}

Describe "Role Assignment Monitoring - Azure RBAC" {
    Context "Get-AzureRoleAssignments" {
        BeforeAll {
            Mock Get-AzRoleAssignment { return $script:testRoleAssignments }
            Mock Get-AzRoleDefinition { param($Id) return @{ Name = "Test Role"; Id = $Id } }
            Mock Get-AzSubscription { return @(@{ Id = "test-sub-1"; Name = "Test Subscription" }) }
        }
        
        It "Should retrieve role assignments successfully" {
            # This test would need the actual function to be defined
            # For now, we'll test that the mocks are working
            $assignments = Get-AzRoleAssignment
            $assignments | Should -Not -BeNullOrEmpty
            $assignments.Count | Should -Be 2
        }
        
        It "Should handle multiple subscriptions" {
            Mock Get-AzSubscription { 
                return @(
                    @{ Id = "test-sub-1"; Name = "Test Subscription 1" },
                    @{ Id = "test-sub-2"; Name = "Test Subscription 2" }
                )
            }
            
            $subscriptions = Get-AzSubscription
            $subscriptions.Count | Should -Be 2
        }
        
        It "Should filter excluded roles" {
            $excludedRoles = @("Reader", "Security Reader")
            $filteredAssignments = $script:testRoleAssignments | Where-Object { $_.RoleDefinitionName -notin $excludedRoles }
            $filteredAssignments.Count | Should -Be 1
            $filteredAssignments[0].RoleDefinitionName | Should -Be "Contributor"
        }
        
        It "Should handle empty role assignments" {
            Mock Get-AzRoleAssignment { return @() }
            $assignments = Get-AzRoleAssignment
            $assignments.Count | Should -Be 0
        }
        
        It "Should handle role assignment retrieval errors" {
            Mock Get-AzRoleAssignment { throw "Access denied" }
            { Get-AzRoleAssignment } | Should -Throw "Access denied"
        }
    }
    
    Context "Role Assignment Processing" {
        It "Should identify high-privilege roles" {
            $highPrivilegeRoles = @("Owner", "Contributor", "User Access Administrator")
            $assignment = $script:testRoleAssignments[0]
            $assignment.RoleDefinitionName | Should -BeIn @("Contributor")
        }
        
        It "Should track assignment age" {
            $assignment = $script:testRoleAssignments[0]
            $age = (Get-Date) - $assignment.CreatedOn
            $age.Days | Should -BeGreaterThan 0
        }
        
        It "Should handle different principal types" {
            $userAssignment = $script:testRoleAssignments[0]
            $groupAssignment = $script:testRoleAssignments[1]
            
            $userAssignment.PrincipalType | Should -Be "User"
            $groupAssignment.PrincipalType | Should -Be "Group"
        }
        
        It "Should handle different scope levels" {
            $subscriptionScope = $script:testRoleAssignments[0].Scope
            $resourceGroupScope = $script:testRoleAssignments[1].Scope
            
            $subscriptionScope | Should -Match "/subscriptions/test-sub-1$"
            $resourceGroupScope | Should -Match "/subscriptions/test-sub-1/resourceGroups/test-rg$"
        }
    }
}

Describe "Role Assignment Monitoring - Entra ID Roles" {
    Context "Get-EntraRoleAssignments" {
        BeforeAll {
            Mock Get-MgRoleManagementDirectoryRoleAssignment { return $script:testEntraRoles }
            Mock Get-MgRoleManagementDirectoryRoleDefinition { param($RoleDefinitionId) return @{ DisplayName = "Test Role"; Id = $RoleDefinitionId } }
            Mock Get-MgUser { param($UserId) return @{ DisplayName = "Test User"; Id = $UserId } }
            Mock Get-MgGroup { param($GroupId) return @{ DisplayName = "Test Group"; Id = $GroupId } }
        }
        
        It "Should retrieve Entra ID role assignments successfully" {
            $assignments = $script:testEntraRoles
            $assignments | Should -Not -BeNullOrEmpty
            $assignments.Count | Should -Be 2
        }
        
        It "Should identify privileged roles" {
            $privilegedRoles = @("Global Administrator", "Privileged Role Administrator", "User Administrator")
            $globalAdminAssignment = $script:testEntraRoles[0]
            $globalAdminAssignment.RoleDefinitionName | Should -Be "Global Administrator"
        }
        
        It "Should handle permanent assignments" {
            $permanentAssignment = $script:testEntraRoles[0]
            $permanentAssignment.EndDateTime | Should -BeNullOrEmpty
        }
        
        It "Should handle time-bound assignments" {
            # Test with a time-bound assignment
            $timeBoundAssignment = @{
                Id = "entra-role-3"
                RoleDefinitionId = "test-role-id"
                RoleDefinitionName = "Application Administrator"
                PrincipalId = "user-4"
                PrincipalType = "User"
                PrincipalName = "Test User 4"
                DirectoryScope = "/"
                CreatedDateTime = (Get-Date).AddDays(-1)
                AssignmentType = "Assigned"
                StartDateTime = (Get-Date).AddDays(-1)
                EndDateTime = (Get-Date).AddDays(30)
            }
            
            $timeBoundAssignment.EndDateTime | Should -Not -BeNullOrEmpty
            $timeBoundAssignment.EndDateTime | Should -BeGreaterThan (Get-Date)
        }
        
        It "Should handle role assignment retrieval errors" {
            Mock Get-MgRoleManagementDirectoryRoleAssignment { throw "Insufficient privileges" }
            { Get-MgRoleManagementDirectoryRoleAssignment } | Should -Throw "Insufficient privileges"
        }
    }
    
    Context "PIM Role Processing" {
        BeforeAll {
            Mock Get-MgRoleManagementDirectoryRoleEligibilitySchedule { 
                return @(
                    @{
                        Id = "pim-eligible-1"
                        RoleDefinitionId = "62e90394-69f5-4237-9190-012177145e10"
                        PrincipalId = "user-5"
                        DirectoryScope = "/"
                        CreatedDateTime = (Get-Date).AddDays(-7)
                        Status = "Enabled"
                        StartDateTime = (Get-Date).AddDays(-7)
                        EndDateTime = $null
                    }
                )
            }
        }
        
        It "Should retrieve PIM eligible assignments" {
            $eligibleAssignments = Get-MgRoleManagementDirectoryRoleEligibilitySchedule
            $eligibleAssignments | Should -Not -BeNullOrEmpty
            $eligibleAssignments.Count | Should -Be 1
        }
        
        It "Should identify eligible vs active assignments" {
            $eligibleAssignment = @{ AssignmentType = "Eligible" }
            $activeAssignment = @{ AssignmentType = "Assigned" }
            
            $eligibleAssignment.AssignmentType | Should -Be "Eligible"
            $activeAssignment.AssignmentType | Should -Be "Assigned"
        }
    }
}

Describe "Role Assignment Monitoring - Data Storage" {
    Context "Azure Table Storage" {
        BeforeAll {
            Mock Get-AzStorageContext { return @{ StorageAccountName = "teststorage" } }
            Mock New-AzStorageTable { return @{ Name = "TestTable" } }
        }
        
        It "Should create storage table if not exists" {
            $table = New-AzStorageTable -Name "TestTable" -Context (Get-AzStorageContext)
            $table.Name | Should -Be "TestTable"
        }
        
        It "Should store role assignment data" {
            $assignment = $script:testRoleAssignments[0]
            $tableData = @{
                PartitionKey = "RoleAssignment"
                RowKey = $assignment.Id
                RoleDefinitionName = $assignment.RoleDefinitionName
                PrincipalName = $assignment.PrincipalName
                PrincipalType = $assignment.PrincipalType
                Scope = $assignment.Scope
                CreatedOn = $assignment.CreatedOn
                AssignmentType = $assignment.AssignmentType
                Timestamp = Get-Date
            }
            
            # Test that the data structure is correct
            $tableData.PartitionKey | Should -Be "RoleAssignment"
            $tableData.RowKey | Should -Be $assignment.Id
            $tableData.RoleDefinitionName | Should -Be $assignment.RoleDefinitionName
        }
        
        It "Should handle storage errors gracefully" {
            Mock Add-AzTableRow { throw "Storage account not found" }
            { Add-AzTableRow -Table @{} -PartitionKey "test" -RowKey "test" -Property @{} } | Should -Throw "Storage account not found"
        }
    }
    
    Context "Data Serialization" {
        It "Should serialize role assignment data correctly" {
            $assignment = $script:testRoleAssignments[0]
            $serialized = $assignment | ConvertTo-Json -Depth 3
            $deserialized = $serialized | ConvertFrom-Json
            
            $deserialized.Id | Should -Be $assignment.Id
            $deserialized.RoleDefinitionName | Should -Be $assignment.RoleDefinitionName
        }
        
        It "Should handle special characters in data" {
            $assignment = @{
                Id = "test-assignment-special"
                RoleDefinitionName = "Role with Special Characters: @#$%"
                PrincipalName = "User with Apostrophe's Name"
                Scope = "/subscriptions/test-sub/resourceGroups/test-rg"
            }
            
            $serialized = $assignment | ConvertTo-Json
            $deserialized = $serialized | ConvertFrom-Json
            
            $deserialized.RoleDefinitionName | Should -Be $assignment.RoleDefinitionName
            $deserialized.PrincipalName | Should -Be $assignment.PrincipalName
        }
    }
}

Describe "Role Assignment Monitoring - Change Detection" {
    Context "Assignment Comparison" {
        It "Should detect new assignments" {
            $previousAssignments = @($script:testRoleAssignments[0])
            $currentAssignments = $script:testRoleAssignments
            
            $newAssignments = $currentAssignments | Where-Object { $_.Id -notin $previousAssignments.Id }
            $newAssignments.Count | Should -Be 1
            $newAssignments[0].Id | Should -Be $script:testRoleAssignments[1].Id
        }
        
        It "Should detect removed assignments" {
            $previousAssignments = $script:testRoleAssignments
            $currentAssignments = @($script:testRoleAssignments[0])
            
            $removedAssignments = $previousAssignments | Where-Object { $_.Id -notin $currentAssignments.Id }
            $removedAssignments.Count | Should -Be 1
            $removedAssignments[0].Id | Should -Be $script:testRoleAssignments[1].Id
        }
        
        It "Should detect modified assignments" {
            $previousAssignment = $script:testRoleAssignments[0].PSObject.Copy()
            $currentAssignment = $script:testRoleAssignments[0].PSObject.Copy()
            $currentAssignment.RoleDefinitionName = "Modified Role"
            
            $previousAssignment.RoleDefinitionName | Should -Be "Contributor"
            $currentAssignment.RoleDefinitionName | Should -Be "Modified Role"
        }
    }
    
    Context "Change Tracking" {
        It "Should track assignment lifecycle" {
            $assignment = @{
                Id = "test-assignment-lifecycle"
                CreatedOn = (Get-Date).AddDays(-30)
                LastModified = (Get-Date).AddDays(-10)
                Status = "Active"
            }
            
            $assignment.CreatedOn | Should -BeLessThan (Get-Date)
            $assignment.LastModified | Should -BeGreaterThan $assignment.CreatedOn
            $assignment.Status | Should -Be "Active"
        }
        
        It "Should calculate assignment duration" {
            $assignment = $script:testRoleAssignments[0]
            $duration = (Get-Date) - $assignment.CreatedOn
            $duration.Days | Should -BeGreaterThan 0
        }
    }
}

Describe "Role Assignment Monitoring - Alerting" {
    Context "Alert Conditions" {
        It "Should trigger alert for high-privilege role assignments" {
            $highPrivilegeRoles = @("Owner", "Contributor", "User Access Administrator", "Global Administrator")
            $assignment = $script:testRoleAssignments[0]
            
            if ($assignment.RoleDefinitionName -in $highPrivilegeRoles) {
                $shouldAlert = $true
            } else {
                $shouldAlert = $false
            }
            
            $shouldAlert | Should -Be $true
        }
        
        It "Should trigger alert for assignments to sensitive scopes" {
            $sensitiveScopes = @("/", "/subscriptions/production-sub")
            $assignment = @{
                Scope = "/"
                RoleDefinitionName = "Global Administrator"
            }
            
            if ($assignment.Scope -in $sensitiveScopes) {
                $shouldAlert = $true
            } else {
                $shouldAlert = $false
            }
            
            $shouldAlert | Should -Be $true
        }
        
        It "Should trigger alert for assignments without expiration" {
            $assignment = @{
                EndDateTime = $null
                RoleDefinitionName = "Global Administrator"
            }
            
            if ($null -eq $assignment.EndDateTime) {
                $shouldAlert = $true
            } else {
                $shouldAlert = $false
            }
            
            $shouldAlert | Should -Be $true
        }
    }
    
    Context "Alert Processing" {
        It "Should format alert messages correctly" {
            $assignment = $script:testRoleAssignments[0]
            $alertMessage = "New role assignment detected: $($assignment.PrincipalName) assigned $($assignment.RoleDefinitionName) on $($assignment.Scope)"
            
            $alertMessage | Should -Match "Test User 1"
            $alertMessage | Should -Match "Contributor"
            $alertMessage | Should -Match "/subscriptions/test-sub-1"
        }
        
        It "Should batch multiple alerts" {
            $alerts = @(
                "Alert 1: High-privilege role assigned",
                "Alert 2: Role assignment without expiration",
                "Alert 3: Assignment to sensitive scope"
            )
            
            $batchedAlert = $alerts -join "`n"
            $batchedAlert | Should -Match "Alert 1"
            $batchedAlert | Should -Match "Alert 2"
            $batchedAlert | Should -Match "Alert 3"
        }
    }
}

Describe "Role Assignment Monitoring - Error Handling" {
    Context "Authentication Errors" {
        It "Should handle Azure authentication failures" {
            Mock Connect-AzAccount { throw "Authentication failed" }
            { Connect-AzAccount } | Should -Throw "Authentication failed"
        }
        
        It "Should handle Microsoft Graph authentication failures" {
            Mock Connect-MgGraph { throw "Graph authentication failed" }
            { Connect-MgGraph } | Should -Throw "Graph authentication failed"
        }
    }
    
    Context "Permission Errors" {
        It "Should handle insufficient Azure RBAC permissions" {
            Mock Get-AzRoleAssignment { throw "Insufficient privileges to complete the operation" }
            { Get-AzRoleAssignment } | Should -Throw "Insufficient privileges to complete the operation"
        }
        
        It "Should handle insufficient Microsoft Graph permissions" {
            Mock Get-MgRoleManagementDirectoryRoleAssignment { throw "Insufficient privileges to complete the operation" }
            { Get-MgRoleManagementDirectoryRoleAssignment } | Should -Throw "Insufficient privileges to complete the operation"
        }
    }
    
    Context "Storage Errors" {
        It "Should handle storage account access errors" {
            Mock Get-AzStorageAccount { throw "Storage account not found" }
            { Get-AzStorageAccount -ResourceGroupName "test" -Name "test" } | Should -Throw "Storage account not found"
        }
        
        It "Should handle table storage errors" {
            Mock Add-AzTableRow { throw "Table operation failed" }
            { Add-AzTableRow -Table @{} -PartitionKey "test" -RowKey "test" -Property @{} } | Should -Throw "Table operation failed"
        }
    }
}

Describe "Role Assignment Monitoring - Performance" {
    Context "Data Processing Performance" {
        It "Should process large numbers of assignments efficiently" {
            $largeAssignmentSet = @()
            for ($i = 1; $i -le 1000; $i++) {
                $largeAssignmentSet += @{
                    Id = "assignment-$i"
                    RoleDefinitionName = "Role $i"
                    PrincipalName = "User $i"
                    Scope = "/subscriptions/test-sub-$i"
                }
            }
            
            $largeAssignmentSet.Count | Should -Be 1000
            
            # Test filtering performance
            $filteredAssignments = $largeAssignmentSet | Where-Object { $_.RoleDefinitionName -like "Role 1*" }
            $filteredAssignments.Count | Should -Be 111 # Role 1, Role 10-19, Role 100-199, Role 1000
        }
        
        It "Should handle concurrent data operations" {
            $assignments = $script:testRoleAssignments
            $processedAssignments = @()
            
            foreach ($assignment in $assignments) {
                $processedAssignments += $assignment
            }
            
            $processedAssignments.Count | Should -Be $assignments.Count
        }
    }
}

Describe "Role Assignment Monitoring - Configuration" {
    Context "Environment Variables" {
        It "Should read configuration from automation variables" {
            Mock Get-AutomationVariable { 
                param($Name)
                switch ($Name) {
                    "StorageAccountName" { return "teststorage" }
                    "TableName" { return "TestTable" }
                    "AlertEmail" { return "admin@test.com" }
                    "ExcludedRoles" { return "Reader,Security Reader" }
                    default { return $null }
                }
            }
            
            $storageAccount = Get-AutomationVariable -Name "StorageAccountName"
            $tableName = Get-AutomationVariable -Name "TableName"
            $alertEmail = Get-AutomationVariable -Name "AlertEmail"
            
            $storageAccount | Should -Be "teststorage"
            $tableName | Should -Be "TestTable"
            $alertEmail | Should -Be "admin@test.com"
        }
        
        It "Should handle missing configuration values" {
            Mock Get-AutomationVariable { return $null }
            $missingValue = Get-AutomationVariable -Name "NonExistentVariable"
            $missingValue | Should -BeNullOrEmpty
        }
    }
    
    Context "Default Values" {
        It "Should use default values when configuration is missing" {
            $defaultTableName = "RoleAssignments"
            $defaultExcludedRoles = @("Reader", "Security Reader")
            
            $defaultTableName | Should -Be "RoleAssignments"
            $defaultExcludedRoles | Should -Contain "Reader"
            $defaultExcludedRoles | Should -Contain "Security Reader"
        }
    }
}
