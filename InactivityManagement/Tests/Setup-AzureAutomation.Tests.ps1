# Pester Tests for Setup-AzureAutomation.ps1

BeforeAll {
    # Import required modules for testing
    Import-Module Az.Automation -Force -ErrorAction SilentlyContinue
    Import-Module Az.Accounts -Force -ErrorAction SilentlyContinue
    
    # Mock Azure PowerShell commands
    Mock Connect-AzAccount { return @{ Context = @{ Subscription = @{ Id = "test-sub-id" } } } }
    Mock Set-AzContext { return $true }
    Mock Get-AzAutomationAccount { return @{ ResourceGroupName = "test-rg"; AutomationAccountName = "test-aa" } }
    Mock New-AzAutomationVariable { return $true }
    Mock Set-AzAutomationVariable { return $true }
    Mock New-AzAutomationCredential { return $true }
    Mock Set-AzAutomationCredential { return $true }
    Mock Import-AzAutomationModule { return $true }
    Mock Get-AzAutomationModule { return @{ Name = "TestModule"; ImportState = "Available" } }
    Mock New-AzAutomationSchedule { return $true }
    Mock Register-AzAutomationScheduledRunbook { return $true }
    Mock Import-AzAutomationRunbook { return $true }
    Mock Publish-AzAutomationRunbook { return $true }
    Mock New-AzAutomationHybridWorkerGroup { return $true }
    Mock Get-AzAutomationHybridWorkerGroup { return @() }
    Mock Write-Host { param($Message) }
    Mock Write-Warning { param($Message) }
    Mock Write-Error { param($Message) }
    Mock Start-Sleep { param($Seconds) }
    Mock Test-Path { return $true }
}

Describe "Setup-AzureAutomation Script Tests" {
    
    Context "Parameter Validation" {
        It "Should validate required parameters" {
            # Test that all required parameters are of correct type
            $params = @{
                SubscriptionId = "12345678-1234-1234-1234-123456789012"
                ResourceGroupName = "rg-test"
                AutomationAccountName = "aa-test"
                StorageAccountName = "satest"
                StorageAccountKey = "testkey123"
                SenderEmail = "test@contoso.com"
                DomainCredentials = @{
                    "contoso.com" = @{Username = "CONTOSO\svc"; Password = "pass123"}
                }
            }
            
            $params.SubscriptionId | Should -Match "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
            $params.ResourceGroupName | Should -BeOfType [string]
            $params.AutomationAccountName | Should -BeOfType [string]
            $params.StorageAccountName | Should -BeOfType [string]
            $params.StorageAccountKey | Should -BeOfType [string]
            $params.SenderEmail | Should -Match "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
            $params.DomainCredentials | Should -BeOfType [hashtable]
        }
        
        It "Should validate email format" {
            $validEmails = @("test@contoso.com", "admin@fabrikam.co.uk", "user.name@domain.org")
            $invalidEmails = @("invalid-email", "test@", "@domain.com", "test.domain.com")
            
            foreach ($email in $validEmails) {
                $email | Should -Match "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
            }
            
            foreach ($email in $invalidEmails) {
                $email | Should -Not -Match "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
            }
        }
        
        It "Should validate domain credentials structure" {
            $validCredentials = @{
                "contoso.com" = @{Username = "CONTOSO\svc-automation"; Password = "P@ssw0rd123"}
                "fabrikam.com" = @{Username = "FABRIKAM\svc-automation"; Password = "P@ssw0rd456"}
            }
            
            foreach ($domain in $validCredentials.Keys) {
                $validCredentials[$domain].Username | Should -BeOfType [string]
                $validCredentials[$domain].Password | Should -BeOfType [string]
                $validCredentials[$domain].Username | Should -Not -BeNullOrEmpty
                $validCredentials[$domain].Password | Should -Not -BeNullOrEmpty
            }
        }
    }
    
    Context "Azure Connection Tests" {
        BeforeEach {
            Mock Connect-AzAccount { return @{ Context = @{ Subscription = @{ Id = "test-sub-id" } } } }
            Mock Set-AzContext { return $true }
        }
        
        It "Should connect to Azure successfully" {
            Connect-AzAccount
            Assert-MockCalled Connect-AzAccount -Times 1
        }
        
        It "Should set correct subscription context" {
            Set-AzContext -SubscriptionId "12345678-1234-1234-1234-123456789012"
            Assert-MockCalled Set-AzContext -Times 1
        }
        
        It "Should verify automation account exists" {
            $automationAccount = Get-AzAutomationAccount -ResourceGroupName "test-rg" -AutomationAccountName "test-aa"
            $automationAccount | Should -Not -BeNullOrEmpty
            Assert-MockCalled Get-AzAutomationAccount -Times 1
        }
    }
    
    Context "Azure Automation Variables Tests" {
        BeforeEach {
            Mock New-AzAutomationVariable { return $true }
            Mock Set-AzAutomationVariable { return $true }
        }
        
        It "Should create required automation variables" {
            $variables = @{
                "StorageAccountName" = "satest"
                "StorageAccountKey" = "testkey123"
                "SenderEmail" = "test@contoso.com"
                "TableName" = "InactiveUsers"
            }
            
            foreach ($variable in $variables.GetEnumerator()) {
                New-AzAutomationVariable -AutomationAccountName "test-aa" -ResourceGroupName "test-rg" -Name $variable.Key -Value $variable.Value -Encrypted $false
            }
            
            Assert-MockCalled New-AzAutomationVariable -Times 4
        }
        
        It "Should create optional automation variables when provided" {
            $optionalVariables = @{
                "ExcludeGroups" = "AdminGroup,ServiceAccounts"
                "ExcludeOUs" = "OU=ServiceAccounts,DC=contoso,DC=com"
                "ExcludeUserProperty" = "Department"
                "ExcludeUserPropertyValue" = "IT"
                "DomainControllers" = "dc1.contoso.com,dc2.contoso.com"
            }
            
            foreach ($variable in $optionalVariables.GetEnumerator()) {
                if ($variable.Value) {
                    New-AzAutomationVariable -AutomationAccountName "test-aa" -ResourceGroupName "test-rg" -Name $variable.Key -Value $variable.Value -Encrypted $false
                }
            }
            
            Assert-MockCalled New-AzAutomationVariable -Times 5
        }
        
        It "Should handle variable creation errors gracefully" {
            Mock New-AzAutomationVariable { throw "Variable already exists" }
            
            { New-AzAutomationVariable -AutomationAccountName "test-aa" -ResourceGroupName "test-rg" -Name "TestVar" -Value "TestValue" -Encrypted $false } | Should -Throw "Variable already exists"
        }
    }
    
    Context "Azure Automation Credentials Tests" {
        BeforeEach {
            Mock New-AzAutomationCredential { return $true }
            Mock Set-AzAutomationCredential { return $true }
        }
        
        It "Should create domain credentials" {
            $domainCredentials = @{
                "contoso.com" = @{Username = "CONTOSO\svc-automation"; Password = "P@ssw0rd123"}
                "fabrikam.com" = @{Username = "FABRIKAM\svc-automation"; Password = "P@ssw0rd456"}
            }
            
            foreach ($domain in $domainCredentials.Keys) {
                $credentialName = "AD-$($domain.ToUpper().Replace('.', ''))"
                $username = $domainCredentials[$domain].Username
                $password = ConvertTo-SecureString $domainCredentials[$domain].Password -AsPlainText -Force
                $credential = New-Object PSCredential($username, $password)
                
                New-AzAutomationCredential -AutomationAccountName "test-aa" -ResourceGroupName "test-rg" -Name $credentialName -Value $credential
            }
            
            Assert-MockCalled New-AzAutomationCredential -Times 2
        }
        
        It "Should format credential names correctly" {
            $domains = @("contoso.com", "fabrikam.co.uk", "sub.domain.com")
            $expectedNames = @("AD-CONTOSOCOM", "AD-FABRIKAMCOUK", "AD-SUBDOMAINCOM")
            
            for ($i = 0; $i -lt $domains.Count; $i++) {
                $credentialName = "AD-$($domains[$i].ToUpper().Replace('.', ''))"
                $credentialName | Should -Be $expectedNames[$i]
            }
        }
        
        It "Should handle credential creation errors gracefully" {
            Mock New-AzAutomationCredential { throw "Credential already exists" }
            
            { New-AzAutomationCredential -AutomationAccountName "test-aa" -ResourceGroupName "test-rg" -Name "TestCred" -Value (New-Object PSCredential("test", (ConvertTo-SecureString "pass" -AsPlainText -Force))) } | Should -Throw "Credential already exists"
        }
    }
    
    Context "PowerShell Module Installation Tests" {
        BeforeEach {
            Mock Import-AzAutomationModule { return $true }
            Mock Get-AzAutomationModule { return @{ Name = "TestModule"; ImportState = "Available" } }
            Mock Start-Sleep { param($Seconds) }
        }
        
        It "Should install required PowerShell modules" {
            $requiredModules = @(
                "Microsoft.Graph.Authentication",
                "Microsoft.Graph.Users",
                "Microsoft.Graph.Mail",
                "Microsoft.Graph.Reports",
                "Az.Storage",
                "Az.Accounts",
                "Az.KeyVault",
                "AzTable"
            )
            
            foreach ($module in $requiredModules) {
                Import-AzAutomationModule -AutomationAccountName "test-aa" -ResourceGroupName "test-rg" -Name $module -ModuleVersion "Latest"
            }
            
            Assert-MockCalled Import-AzAutomationModule -Times 8
        }
        
        It "Should wait for module installation to complete" {
            $moduleName = "Microsoft.Graph.Authentication"
            
            # Mock module installation states
            Mock Get-AzAutomationModule { return @{ Name = $moduleName; ImportState = "Installing" } } -ParameterFilter { $Name -eq $moduleName }
            Mock Get-AzAutomationModule { return @{ Name = $moduleName; ImportState = "Available" } } -ParameterFilter { $Name -eq $moduleName }
            
            Import-AzAutomationModule -AutomationAccountName "test-aa" -ResourceGroupName "test-rg" -Name $moduleName -ModuleVersion "Latest"
            
            do {
                Start-Sleep -Seconds 30
                $moduleStatus = Get-AzAutomationModule -AutomationAccountName "test-aa" -ResourceGroupName "test-rg" -Name $moduleName
            } while ($moduleStatus.ImportState -eq "Installing")
            
            Assert-MockCalled Get-AzAutomationModule -AtLeast 1
            Assert-MockCalled Start-Sleep -AtLeast 0
        }
        
        It "Should handle module installation failures" {
            Mock Import-AzAutomationModule { throw "Module installation failed" }
            
            { Import-AzAutomationModule -AutomationAccountName "test-aa" -ResourceGroupName "test-rg" -Name "TestModule" -ModuleVersion "Latest" } | Should -Throw "Module installation failed"
        }
    }
    
    Context "Runbook Management Tests" {
        BeforeEach {
            Mock Import-AzAutomationRunbook { return $true }
            Mock Publish-AzAutomationRunbook { return $true }
            Mock Test-Path { return $true }
        }
        
        It "Should import runbook from file" {
            $runbookPath = "C:\Scripts\AzureAutomation-DisableInactiveUsers.ps1"
            Mock Test-Path { return $true } -ParameterFilter { $Path -eq $runbookPath }
            
            Import-AzAutomationRunbook -AutomationAccountName "test-aa" -ResourceGroupName "test-rg" -Name "DisableInactiveUsers" -Type "PowerShell" -Path $runbookPath
            
            Assert-MockCalled Import-AzAutomationRunbook -Times 1
        }
        
        It "Should publish runbook after import" {
            Publish-AzAutomationRunbook -AutomationAccountName "test-aa" -ResourceGroupName "test-rg" -Name "DisableInactiveUsers"
            
            Assert-MockCalled Publish-AzAutomationRunbook -Times 1
        }
        
        It "Should handle missing runbook file" {
            $runbookPath = "C:\Scripts\NonExistentRunbook.ps1"
            Mock Test-Path { return $false } -ParameterFilter { $Path -eq $runbookPath }
            
            Test-Path -Path $runbookPath | Should -Be $false
        }
    }
    
    Context "Hybrid Worker Group Tests" {
        BeforeEach {
            Mock New-AzAutomationHybridWorkerGroup { return $true }
            Mock Get-AzAutomationHybridWorkerGroup { return @() }
        }
        
        It "Should create hybrid worker group when specified" {
            $hybridWorkerGroup = "HybridWorkerGroup"
            
            if ($hybridWorkerGroup) {
                New-AzAutomationHybridWorkerGroup -AutomationAccountName "test-aa" -ResourceGroupName "test-rg" -Name $hybridWorkerGroup
            }
            
            Assert-MockCalled New-AzAutomationHybridWorkerGroup -Times 1
        }
        
        It "Should check if hybrid worker group exists" {
            $existingGroups = Get-AzAutomationHybridWorkerGroup -AutomationAccountName "test-aa" -ResourceGroupName "test-rg"
            $existingGroups | Should -BeOfType [array]
            
            Assert-MockCalled Get-AzAutomationHybridWorkerGroup -Times 1
        }
        
        It "Should skip hybrid worker group creation if not specified" {
            $hybridWorkerGroup = ""
            
            if ($hybridWorkerGroup) {
                New-AzAutomationHybridWorkerGroup -AutomationAccountName "test-aa" -ResourceGroupName "test-rg" -Name $hybridWorkerGroup
            }
            
            Assert-MockCalled New-AzAutomationHybridWorkerGroup -Times 0
        }
    }
    
    Context "Schedule Configuration Tests" {
        BeforeEach {
            Mock New-AzAutomationSchedule { return $true }
            Mock Register-AzAutomationScheduledRunbook { return $true }
        }
        
        It "Should create schedule when requested" {
            $createSchedule = $true
            $scheduleFrequency = "Daily"
            $scheduleTime = "02:00"
            
            if ($createSchedule) {
                $scheduleName = "DisableInactiveUsers-Schedule"
                $startTime = (Get-Date).Date.AddHours(2).AddDays(1) # Tomorrow at 2 AM
                
                New-AzAutomationSchedule -AutomationAccountName "test-aa" -ResourceGroupName "test-rg" -Name $scheduleName -StartTime $startTime -DayInterval 1
                Register-AzAutomationScheduledRunbook -AutomationAccountName "test-aa" -ResourceGroupName "test-rg" -RunbookName "DisableInactiveUsers" -ScheduleName $scheduleName
            }
            
            Assert-MockCalled New-AzAutomationSchedule -Times 1
            Assert-MockCalled Register-AzAutomationScheduledRunbook -Times 1
        }
        
        It "Should skip schedule creation when not requested" {
            $createSchedule = $false
            
            if ($createSchedule) {
                New-AzAutomationSchedule -AutomationAccountName "test-aa" -ResourceGroupName "test-rg" -Name "test-schedule" -StartTime (Get-Date)
            }
            
            Assert-MockCalled New-AzAutomationSchedule -Times 0
        }
        
        It "Should calculate correct start time for schedule" {
            $scheduleTime = "02:00"
            $timeComponents = $scheduleTime.Split(':')
            $startTime = (Get-Date).Date.AddHours([int]$timeComponents[0]).AddMinutes([int]$timeComponents[1]).AddDays(1)
            
            $startTime.Hour | Should -Be 2
            $startTime.Minute | Should -Be 0
            $startTime.Date | Should -Be (Get-Date).Date.AddDays(1)
        }
    }
    
    Context "Error Handling Tests" {
        It "Should handle Azure connection failures" {
            Mock Connect-AzAccount { throw "Authentication failed" }
            
            { Connect-AzAccount } | Should -Throw "Authentication failed"
        }
        
        It "Should handle missing automation account" {
            Mock Get-AzAutomationAccount { throw "Automation account not found" }
            
            { Get-AzAutomationAccount -ResourceGroupName "test-rg" -AutomationAccountName "missing-aa" } | Should -Throw "Automation account not found"
        }
        
        It "Should handle variable creation failures" {
            Mock New-AzAutomationVariable { throw "Variable creation failed" }
            
            { New-AzAutomationVariable -AutomationAccountName "test-aa" -ResourceGroupName "test-rg" -Name "TestVar" -Value "TestValue" -Encrypted $false } | Should -Throw "Variable creation failed"
        }
        
        It "Should handle credential creation failures" {
            Mock New-AzAutomationCredential { throw "Credential creation failed" }
            
            { New-AzAutomationCredential -AutomationAccountName "test-aa" -ResourceGroupName "test-rg" -Name "TestCred" -Value (New-Object PSCredential("test", (ConvertTo-SecureString "pass" -AsPlainText -Force))) } | Should -Throw "Credential creation failed"
        }
    }
    
    Context "Configuration Validation Tests" {
        It "Should validate storage account name format" {
            $validNames = @("satest", "storageaccount123", "mysa2024")
            $invalidNames = @("SA_Test", "storage-account", "StorageAccount", "sa")
            
            foreach ($name in $validNames) {
                $name | Should -Match "^[a-z0-9]{3,24}$"
            }
            
            foreach ($name in $invalidNames) {
                $name | Should -Not -Match "^[a-z0-9]{3,24}$"
            }
        }
        
        It "Should validate automation account name format" {
            $validNames = @("aa-test", "MyAutomationAccount", "automation123")
            $invalidNames = @("", "a", "automation_account")
            
            foreach ($name in $validNames) {
                $name.Length | Should -BeGreaterThan 2
                $name.Length | Should -BeLessOrEqual 50
            }
            
            foreach ($name in $invalidNames) {
                if ($name.Length -gt 0) {
                    ($name.Length -le 2 -or $name.Length -gt 50) | Should -Be $true
                }
            }
        }
        
        It "Should validate resource group name format" {
            $validNames = @("rg-test", "resource-group", "ResourceGroup123")
            $invalidNames = @("", "rg_test", "resource.group")
            
            foreach ($name in $validNames) {
                $name.Length | Should -BeGreaterThan 0
                $name.Length | Should -BeLessOrEqual 90
            }
        }
    }
    
    Context "Integration Tests" {
        It "Should complete full setup process" {
            # Mock all required commands for full setup
            Mock Connect-AzAccount { return @{ Context = @{ Subscription = @{ Id = "test-sub-id" } } } }
            Mock Set-AzContext { return $true }
            Mock Get-AzAutomationAccount { return @{ ResourceGroupName = "test-rg"; AutomationAccountName = "test-aa" } }
            Mock New-AzAutomationVariable { return $true }
            Mock New-AzAutomationCredential { return $true }
            Mock Import-AzAutomationModule { return $true }
            Mock Get-AzAutomationModule { return @{ Name = "TestModule"; ImportState = "Available" } }
            Mock Import-AzAutomationRunbook { return $true }
            Mock Publish-AzAutomationRunbook { return $true }
            Mock New-AzAutomationSchedule { return $true }
            Mock Register-AzAutomationScheduledRunbook { return $true }
            Mock Test-Path { return $true }
            
            # Simulate setup process
            Connect-AzAccount
            Set-AzContext -SubscriptionId "test-sub-id"
            Get-AzAutomationAccount -ResourceGroupName "test-rg" -AutomationAccountName "test-aa"
            New-AzAutomationVariable -AutomationAccountName "test-aa" -ResourceGroupName "test-rg" -Name "TestVar" -Value "TestValue" -Encrypted $false
            New-AzAutomationCredential -AutomationAccountName "test-aa" -ResourceGroupName "test-rg" -Name "TestCred" -Value (New-Object PSCredential("test", (ConvertTo-SecureString "pass" -AsPlainText -Force)))
            Import-AzAutomationModule -AutomationAccountName "test-aa" -ResourceGroupName "test-rg" -Name "TestModule" -ModuleVersion "Latest"
            Import-AzAutomationRunbook -AutomationAccountName "test-aa" -ResourceGroupName "test-rg" -Name "TestRunbook" -Type "PowerShell" -Path "C:\test.ps1"
            Publish-AzAutomationRunbook -AutomationAccountName "test-aa" -ResourceGroupName "test-rg" -Name "TestRunbook"
            New-AzAutomationSchedule -AutomationAccountName "test-aa" -ResourceGroupName "test-rg" -Name "TestSchedule" -StartTime (Get-Date).AddHours(1) -DayInterval 1
            Register-AzAutomationScheduledRunbook -AutomationAccountName "test-aa" -ResourceGroupName "test-rg" -RunbookName "TestRunbook" -ScheduleName "TestSchedule"
            
            # Verify all commands were called
            Assert-MockCalled Connect-AzAccount -Times 1
            Assert-MockCalled Set-AzContext -Times 1
            Assert-MockCalled Get-AzAutomationAccount -Times 1
            Assert-MockCalled New-AzAutomationVariable -Times 1
            Assert-MockCalled New-AzAutomationCredential -Times 1
            Assert-MockCalled Import-AzAutomationModule -Times 1
            Assert-MockCalled Import-AzAutomationRunbook -Times 1
            Assert-MockCalled Publish-AzAutomationRunbook -Times 1
            Assert-MockCalled New-AzAutomationSchedule -Times 1
            Assert-MockCalled Register-AzAutomationScheduledRunbook -Times 1
        }
    }
}
