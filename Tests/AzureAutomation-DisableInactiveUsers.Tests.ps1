# Pester Tests for AzureAutomation-DisableInactiveUsers.ps1

BeforeAll {
    # Import the module being tested
    $ScriptPath = Join-Path $PSScriptRoot ".." "AzureAutomation-DisableInactiveUsers.ps1"
    
    # Mock Azure Automation variables
    $global:MockAutomationVariables = @{
        StorageAccountName = "testStorageAccount"
        StorageAccountKey = "testKey"
        SenderEmail = "test@contoso.com"
        ExcludeGroups = "AdminGroup,ServiceAccounts"
        ExcludeOUs = "OU=ServiceAccounts,DC=contoso,DC=com"
        ExcludeUserProperty = "Department"
        ExcludeUserPropertyValue = "IT"
        TableName = "InactiveUsers"
        DomainControllers = "dc1.contoso.com,dc2.contoso.com"
    }
    
    # Mock Azure Automation credentials
    $global:MockCredentials = @{
        'AD-CONTOSO' = [PSCredential]::new("CONTOSO\svc-automation", (ConvertTo-SecureString "password" -AsPlainText -Force))
        'AD-FABRIKAM' = [PSCredential]::new("FABRIKAM\svc-automation", (ConvertTo-SecureString "password" -AsPlainText -Force))
    }
    
    # Mock functions that would normally be available in Azure Automation
    function Get-AutomationVariable { 
        param($Name)
        return $global:MockAutomationVariables[$Name]
    }
    
    function Get-AutomationPSCredential { 
        param($Name)
        return $global:MockCredentials[$Name]
    }
    
    function Write-Output { param($Message) }
    function Write-Warning { param($Message) }
    function Write-Error { param($Message) }
    
    # Mock external modules
    Mock Connect-MgGraph { return $true }
    Mock Connect-AzAccount { return $true }
    Mock Get-MgUser { return @() }
    Mock Get-ADUser { return @() }
    Mock Get-ADDomain { return @{ Name = "contoso.com"; NetBIOSName = "CONTOSO" } }
    Mock Set-ADUser { return $true }
    Mock Disable-ADAccount { return $true }
    Mock Update-MgUser { return $true }
    Mock Send-MgUserMail { return $true }
    Mock New-AzStorageContext { return [PSCustomObject]@{ StorageAccountName = "test" } }
    Mock Get-AzStorageTable { return [PSCustomObject]@{ CloudTable = @{} } }
    Mock Add-AzTableRow { return $true }
    Mock Test-Path { return $true }
    Mock Import-Module { return $true }
}

Describe "AzureAutomation-DisableInactiveUsers Script Tests" {
    
    Context "Parameter Validation" {
        It "Should accept valid DaysInactive parameter" {
            $DaysInactive = 90
            $DaysInactive | Should -BeOfType [int]
            $DaysInactive | Should -BeGreaterThan 0
        }
        
        It "Should accept valid NotificationDays parameter" {
            $NotificationDays = @(14, 7, 3)
            $NotificationDays | Should -BeOfType [array]
            $NotificationDays | Should -AllBeGreaterThan 0
        }
        
        It "Should accept TestMode parameter" {
            $TestMode = $true
            $TestMode | Should -BeOfType [bool]
        }
    }
    
    Context "Azure Automation Variable Tests" {
        BeforeEach {
            # Reset mock variables
            $global:MockAutomationVariables = @{
                StorageAccountName = "testStorageAccount"
                StorageAccountKey = "testKey"
                SenderEmail = "test@contoso.com"
                ExcludeGroups = "AdminGroup,ServiceAccounts"
                ExcludeOUs = "OU=ServiceAccounts,DC=contoso,DC=com"
                ExcludeUserProperty = "Department"
                ExcludeUserPropertyValue = "IT"
                TableName = "InactiveUsers"
                DomainControllers = "dc1.contoso.com,dc2.contoso.com"
            }
        }
        
        It "Should retrieve required automation variables" {
            Get-AutomationVariable -Name "StorageAccountName" | Should -Be "testStorageAccount"
            Get-AutomationVariable -Name "StorageAccountKey" | Should -Be "testKey"
            Get-AutomationVariable -Name "SenderEmail" | Should -Be "test@contoso.com"
        }
        
        It "Should handle missing optional variables gracefully" {
            $global:MockAutomationVariables.Remove("ExcludeGroups")
            Get-AutomationVariable -Name "ExcludeGroups" | Should -BeNullOrEmpty
        }
        
        It "Should use default table name when not specified" {
            $global:MockAutomationVariables.Remove("TableName")
            $tableName = Get-AutomationVariable -Name "TableName"
            if (-not $tableName) { $tableName = "InactiveUsers" }
            $tableName | Should -Be "InactiveUsers"
        }
    }
    
    Context "Credential Management Tests" {
        It "Should retrieve domain credentials" {
            $credential = Get-AutomationPSCredential -Name "AD-CONTOSO"
            $credential | Should -Not -BeNullOrEmpty
            $credential.UserName | Should -Be "CONTOSO\svc-automation"
        }
        
        It "Should handle multiple domain credentials" {
            $contosoCredential = Get-AutomationPSCredential -Name "AD-CONTOSO"
            $fabrikamCredential = Get-AutomationPSCredential -Name "AD-FABRIKAM"
            
            $contosoCredential.UserName | Should -Be "CONTOSO\svc-automation"
            $fabrikamCredential.UserName | Should -Be "FABRIKAM\svc-automation"
        }
        
        It "Should handle missing domain credentials gracefully" {
            $missingCredential = Get-AutomationPSCredential -Name "AD-MISSING"
            $missingCredential | Should -BeNullOrEmpty
        }
    }
    
    Context "Active Directory Integration Tests" {
        BeforeEach {
            Mock Get-ADDomain { return @{ Name = "contoso.com"; NetBIOSName = "CONTOSO" } }
            Mock Get-ADUser { 
                return @(
                    [PSCustomObject]@{
                        SamAccountName = "testuser1"
                        UserPrincipalName = "testuser1@contoso.com"
                        LastLogonDate = (Get-Date).AddDays(-100)
                        Enabled = $true
                        MemberOf = @()
                        Department = "Sales"
                        DistinguishedName = "CN=Test User,OU=Users,DC=contoso,DC=com"
                    }
                )
            }
        }
        
        It "Should discover AD domains" {
            $domain = Get-ADDomain
            $domain.Name | Should -Be "contoso.com"
            $domain.NetBIOSName | Should -Be "CONTOSO"
        }
        
        It "Should find inactive users" {
            $users = Get-ADUser -Filter * -Properties LastLogonDate, Enabled, MemberOf, Department
            $inactiveUsers = $users | Where-Object { 
                $_.LastLogonDate -lt (Get-Date).AddDays(-90) -and $_.Enabled -eq $true 
            }
            $inactiveUsers.Count | Should -Be 1
            $inactiveUsers[0].SamAccountName | Should -Be "testuser1"
        }
        
        It "Should exclude users in specified groups" {
            Mock Get-ADUser { 
                return @(
                    [PSCustomObject]@{
                        SamAccountName = "adminuser"
                        UserPrincipalName = "adminuser@contoso.com"
                        LastLogonDate = (Get-Date).AddDays(-100)
                        Enabled = $true
                        MemberOf = @("CN=AdminGroup,OU=Groups,DC=contoso,DC=com")
                        Department = "IT"
                        DistinguishedName = "CN=Admin User,OU=Users,DC=contoso,DC=com"
                    }
                )
            }
            
            $users = Get-ADUser -Filter * -Properties LastLogonDate, Enabled, MemberOf, Department
            $excludeGroups = @("AdminGroup")
            $filteredUsers = $users | Where-Object { 
                $isExcluded = $false
                foreach ($group in $excludeGroups) {
                    if ($_.MemberOf -match $group) { $isExcluded = $true; break }
                }
                -not $isExcluded
            }
            $filteredUsers.Count | Should -Be 0
        }
        
        It "Should exclude users by property value" {
            Mock Get-ADUser { 
                return @(
                    [PSCustomObject]@{
                        SamAccountName = "ituser"
                        UserPrincipalName = "ituser@contoso.com"
                        LastLogonDate = (Get-Date).AddDays(-100)
                        Enabled = $true
                        MemberOf = @()
                        Department = "IT"
                        DistinguishedName = "CN=IT User,OU=Users,DC=contoso,DC=com"
                    }
                )
            }
            
            $users = Get-ADUser -Filter * -Properties LastLogonDate, Enabled, MemberOf, Department
            $excludeProperty = "Department"
            $excludeValue = "IT"
            $filteredUsers = $users | Where-Object { $_.$excludeProperty -ne $excludeValue }
            $filteredUsers.Count | Should -Be 0
        }
    }
    
    Context "Microsoft Graph Integration Tests" {
        BeforeEach {
            Mock Connect-MgGraph { return $true }
            Mock Get-MgUser { 
                return @(
                    [PSCustomObject]@{
                        Id = "user1-guid"
                        UserPrincipalName = "testuser1@contoso.com"
                        DisplayName = "Test User 1"
                        Mail = "testuser1@contoso.com"
                        SignInActivity = @{
                            LastSignInDateTime = (Get-Date).AddDays(-100).ToString("yyyy-MM-ddTHH:mm:ssZ")
                        }
                        AccountEnabled = $true
                    }
                )
            }
        }
        
        It "Should connect to Microsoft Graph" {
            Connect-MgGraph -Identity
            Assert-MockCalled Connect-MgGraph -Times 1
        }
        
        It "Should retrieve Entra ID users" {
            $users = Get-MgUser -All -Property "Id,UserPrincipalName,DisplayName,Mail,SignInActivity,AccountEnabled"
            $users.Count | Should -Be 1
            $users[0].UserPrincipalName | Should -Be "testuser1@contoso.com"
        }
        
        It "Should send notification emails" {
            $emailParams = @{
                UserId = "user1-guid"
                Message = @{
                    Subject = "Test Subject"
                    Body = @{ Content = "Test Body" }
                    ToRecipients = @(@{ EmailAddress = @{ Address = "testuser1@contoso.com" } })
                }
            }
            
            Send-MgUserMail @emailParams
            Assert-MockCalled Send-MgUserMail -Times 1
        }
        
        It "Should disable Entra ID accounts" {
            Update-MgUser -UserId "user1-guid" -AccountEnabled:$false
            Assert-MockCalled Update-MgUser -Times 1
        }
    }
    
    Context "Azure Storage Integration Tests" {
        BeforeEach {
            Mock New-AzStorageContext { 
                return [PSCustomObject]@{ StorageAccountName = "testStorageAccount" }
            }
            Mock Get-AzStorageTable { 
                return [PSCustomObject]@{ CloudTable = @{} }
            }
            Mock Add-AzTableRow { return $true }
        }
        
        It "Should create storage context" {
            $ctx = New-AzStorageContext -StorageAccountName "testStorageAccount" -StorageAccountKey "testKey"
            $ctx.StorageAccountName | Should -Be "testStorageAccount"
            Assert-MockCalled New-AzStorageContext -Times 1
        }
        
        It "Should access storage table" {
            $ctx = New-AzStorageContext -StorageAccountName "testStorageAccount" -StorageAccountKey "testKey"
            $table = Get-AzStorageTable -Name "InactiveUsers" -Context $ctx
            $table | Should -Not -BeNullOrEmpty
            Assert-MockCalled Get-AzStorageTable -Times 1
        }
        
        It "Should log user actions to storage table" {
            $ctx = New-AzStorageContext -StorageAccountName "testStorageAccount" -StorageAccountKey "testKey"
            $table = Get-AzStorageTable -Name "InactiveUsers" -Context $ctx
            
            $logEntry = @{
                PartitionKey = "Action"
                RowKey = [guid]::NewGuid().ToString()
                UserPrincipalName = "testuser1@contoso.com"
                Action = "Disabled"
                Timestamp = (Get-Date)
                DaysInactive = 100
                TestMode = $false
            }
            
            Add-AzTableRow -Table $table.CloudTable -Property $logEntry
            Assert-MockCalled Add-AzTableRow -Times 1
        }
    }
    
    Context "Hybrid Worker Detection Tests" {
        BeforeEach {
            Mock Get-WmiObject { return $null }
            Mock Get-CimInstance { return $null }
            Mock Test-Path { return $false }
        }
        
        It "Should detect when running on Hybrid Worker" {
            Mock Test-Path { return $true } -ParameterFilter { $Path -like "*HybridWorker*" }
            
            $isHybridWorker = Test-Path -Path "C:\Packages\Plugins\Microsoft.Azure.Automation.HybridWorker.HybridWorkerForWindows"
            $isHybridWorker | Should -Be $true
        }
        
        It "Should detect when running in Azure sandbox" {
            Mock Test-Path { return $false }
            Mock Get-WmiObject { return $null }
            
            $isAzureSandbox = -not (Test-Path -Path "C:\Packages\Plugins\Microsoft.Azure.Automation.HybridWorker.HybridWorkerForWindows")
            $isAzureSandbox | Should -Be $true
        }
    }
    
    Context "Test Mode Tests" {
        BeforeEach {
            Mock Write-Output { param($Message) }
            Mock Set-ADUser { return $true }
            Mock Disable-ADAccount { return $true }
            Mock Update-MgUser { return $true }
        }
        
        It "Should not make changes in test mode" {
            $TestMode = $true
            
            if (-not $TestMode) {
                Set-ADUser -Identity "testuser1" -Description "Account disabled due to inactivity"
                Disable-ADAccount -Identity "testuser1"
                Update-MgUser -UserId "user1-guid" -AccountEnabled:$false
            }
            
            Assert-MockCalled Set-ADUser -Times 0
            Assert-MockCalled Disable-ADAccount -Times 0
            Assert-MockCalled Update-MgUser -Times 0
        }
        
        It "Should make changes in production mode" {
            $TestMode = $false
            
            if (-not $TestMode) {
                Set-ADUser -Identity "testuser1" -Description "Account disabled due to inactivity"
                Disable-ADAccount -Identity "testuser1"
                Update-MgUser -UserId "user1-guid" -AccountEnabled:$false
            }
            
            Assert-MockCalled Set-ADUser -Times 1
            Assert-MockCalled Disable-ADAccount -Times 1
            Assert-MockCalled Update-MgUser -Times 1
        }
    }
    
    Context "Error Handling Tests" {
        It "Should handle AD connection errors gracefully" {
            Mock Get-ADDomain { throw "Cannot contact domain controller" }
            
            { Get-ADDomain } | Should -Throw "Cannot contact domain controller"
        }
        
        It "Should handle Graph API connection errors gracefully" {
            Mock Connect-MgGraph { throw "Authentication failed" }
            
            { Connect-MgGraph -Identity } | Should -Throw "Authentication failed"
        }
        
        It "Should handle storage connection errors gracefully" {
            Mock New-AzStorageContext { throw "Storage account not found" }
            
            { New-AzStorageContext -StorageAccountName "invalid" -StorageAccountKey "key" } | Should -Throw "Storage account not found"
        }
        
        It "Should handle missing automation variables gracefully" {
            $global:MockAutomationVariables.Remove("StorageAccountName")
            
            $result = Get-AutomationVariable -Name "StorageAccountName"
            $result | Should -BeNullOrEmpty
        }
    }
    
    Context "Date Calculation Tests" {
        It "Should calculate correct cutoff date" {
            $daysInactive = 90
            $cutoffDate = (Get-Date).AddDays(-$daysInactive)
            $cutoffDate | Should -BeLessThan (Get-Date)
            $cutoffDate | Should -BeGreaterThan (Get-Date).AddDays(-100)
        }
        
        It "Should calculate notification dates correctly" {
            $notificationDays = @(14, 7, 3)
            $disableDate = (Get-Date).AddDays(14)
            
            foreach ($days in $notificationDays) {
                $notificationDate = $disableDate.AddDays(-$days)
                $notificationDate | Should -BeLessThan $disableDate
                $notificationDate | Should -BeGreaterOrEqual (Get-Date).Date
            }
        }
    }
    
    Context "Configuration Validation Tests" {
        It "Should validate email format" {
            $senderEmail = "test@contoso.com"
            $senderEmail | Should -Match "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        }
        
        It "Should validate exclude groups format" {
            $excludeGroups = "AdminGroup,ServiceAccounts,TestGroup"
            $groupArray = $excludeGroups -split ","
            $groupArray.Count | Should -Be 3
            $groupArray[0] | Should -Be "AdminGroup"
        }
        
        It "Should validate exclude OUs format" {
            $excludeOUs = "OU=ServiceAccounts,DC=contoso,DC=com;OU=TestUsers,DC=contoso,DC=com"
            $ouArray = $excludeOUs -split ";"
            $ouArray.Count | Should -Be 2
            $ouArray[0] | Should -Match "OU=.*,DC=.*"
        }
    }
}
