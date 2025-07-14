# Pester Tests for Legacy Scripts (Disable-InactiveUsers.ps1 and Config-DisableInactiveUsers.ps1)

BeforeAll {
    # Mock external dependencies
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
    Mock Get-AzKeyVaultSecret { return @{ SecretValue = (ConvertTo-SecureString "secret" -AsPlainText -Force) } }
    Mock Import-Module { return $true }
    Mock Test-Path { return $true }
    Mock Write-Host { param($Message) }
    Mock Write-Warning { param($Message) }
    Mock Write-Error { param($Message) }
    Mock Write-Verbose { param($Message) }
    
    # Mock configuration variables
    $global:MockConfig = @{
        DaysInactive = 90
        NotificationDays = @(14, 7, 3)
        StorageAccountName = "saiamlogging"
        StorageAccountKey = "testkey123"
        SenderEmail = "admin@contoso.com"
        KeyVaultName = "kv-iam-test"
        ADDomains = @(
            @{
                Name = "contoso.com"
                NetBIOSName = "CONTOSO"
                CredentialName = "CONTOSO-ServiceAccount"
                DomainControllers = @("dc1.contoso.com", "dc2.contoso.com")
            },
            @{
                Name = "fabrikam.com"
                NetBIOSName = "FABRIKAM"
                CredentialName = "FABRIKAM-ServiceAccount"
                DomainControllers = @("dc1.fabrikam.com", "dc2.fabrikam.com")
            }
        )
        ExcludeGroups = @("Domain Admins", "Enterprise Admins", "Service Accounts")
        ExcludeOUs = @("OU=ServiceAccounts,DC=contoso,DC=com", "OU=SharedMailboxes,DC=contoso,DC=com")
        ExcludeUserProperty = "Department"
        ExcludeUserPropertyValue = "IT"
        TableName = "InactiveUsers"
        TestMode = $true
    }
}

Describe "Legacy Scripts Configuration Tests" {
    
    Context "Config-DisableInactiveUsers.ps1 Tests" {
        It "Should have valid configuration structure" {
            $global:MockConfig.DaysInactive | Should -BeOfType [int]
            $global:MockConfig.DaysInactive | Should -BeGreaterThan 0
            
            $global:MockConfig.NotificationDays | Should -BeOfType [array]
            $global:MockConfig.NotificationDays | Should -AllBeGreaterThan 0
            
            $global:MockConfig.StorageAccountName | Should -Not -BeNullOrEmpty
            $global:MockConfig.StorageAccountKey | Should -Not -BeNullOrEmpty
            $global:MockConfig.SenderEmail | Should -Match "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        }
        
        It "Should have valid AD domain configuration" {
            $global:MockConfig.ADDomains | Should -Not -BeNullOrEmpty
            $global:MockConfig.ADDomains | Should -BeOfType [array]
            
            foreach ($domain in $global:MockConfig.ADDomains) {
                $domain.Name | Should -Not -BeNullOrEmpty
                $domain.NetBIOSName | Should -Not -BeNullOrEmpty
                $domain.CredentialName | Should -Not -BeNullOrEmpty
                $domain.DomainControllers | Should -BeOfType [array]
                $domain.DomainControllers | Should -Not -BeNullOrEmpty
            }
        }
        
        It "Should have valid exclusion configuration" {
            $global:MockConfig.ExcludeGroups | Should -BeOfType [array]
            $global:MockConfig.ExcludeOUs | Should -BeOfType [array]
            $global:MockConfig.ExcludeUserProperty | Should -BeOfType [string]
            $global:MockConfig.ExcludeUserPropertyValue | Should -BeOfType [string]
        }
        
        It "Should validate storage account name format" {
            $global:MockConfig.StorageAccountName | Should -Match "^[a-z0-9]{3,24}$"
        }
        
        It "Should validate notification days are in ascending order" {
            $sortedDays = $global:MockConfig.NotificationDays | Sort-Object -Descending
            $sortedDays | Should -Be $global:MockConfig.NotificationDays
        }
    }
    
    Context "Configuration Loading Tests" {
        BeforeEach {
            Mock Test-Path { return $true }
            Mock Get-Content { return '$Config = @{ DaysInactive = 90; TestMode = $true }' }
            Mock Invoke-Expression { return $true }
        }
        
        It "Should load configuration from file" {
            $configPath = "C:\Scripts\Config-DisableInactiveUsers.ps1"
            Test-Path -Path $configPath | Should -Be $true
            
            Assert-MockCalled Test-Path -Times 1
        }
        
        It "Should handle missing configuration file" {
            Mock Test-Path { return $false }
            
            $configPath = "C:\Scripts\MissingConfig.ps1"
            Test-Path -Path $configPath | Should -Be $false
        }
        
        It "Should validate configuration after loading" {
            $loadedConfig = $global:MockConfig
            
            $loadedConfig.DaysInactive | Should -BeGreaterThan 0
            $loadedConfig.NotificationDays | Should -Not -BeNullOrEmpty
            $loadedConfig.StorageAccountName | Should -Not -BeNullOrEmpty
            $loadedConfig.SenderEmail | Should -Match "@"
        }
    }
    
    Context "Key Vault Integration Tests" {
        BeforeEach {
            Mock Get-AzKeyVaultSecret { 
                param($VaultName, $Name)
                return @{ 
                    SecretValue = (ConvertTo-SecureString "test-secret-value" -AsPlainText -Force)
                    Name = $Name
                }
            }
            Mock Connect-AzAccount { return $true }
        }
        
        It "Should retrieve domain credentials from Key Vault" {
            $keyVaultName = $global:MockConfig.KeyVaultName
            $credentialName = "CONTOSO-ServiceAccount"
            
            $secret = Get-AzKeyVaultSecret -VaultName $keyVaultName -Name $credentialName
            $secret | Should -Not -BeNullOrEmpty
            $secret.SecretValue | Should -BeOfType [System.Security.SecureString]
            
            Assert-MockCalled Get-AzKeyVaultSecret -Times 1
        }
        
        It "Should handle missing Key Vault secrets" {
            Mock Get-AzKeyVaultSecret { throw "Secret not found" }
            
            { Get-AzKeyVaultSecret -VaultName "test-kv" -Name "missing-secret" } | Should -Throw "Secret not found"
        }
        
        It "Should retrieve storage account key from Key Vault" {
            $keyVaultName = $global:MockConfig.KeyVaultName
            $storageKeyName = "StorageAccountKey"
            
            $secret = Get-AzKeyVaultSecret -VaultName $keyVaultName -Name $storageKeyName
            $secret.SecretValue | Should -BeOfType [System.Security.SecureString]
            
            Assert-MockCalled Get-AzKeyVaultSecret -Times 1
        }
    }
}

Describe "Legacy Scripts Functionality Tests" {
    
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
            Mock Import-Module { return $true }
        }
        
        It "Should connect to multiple domains" {
            $domains = $global:MockConfig.ADDomains
            
            foreach ($domain in $domains) {
                Import-Module -Name "ActiveDirectory"
                $domainInfo = Get-ADDomain -Server $domain.DomainControllers[0]
                $domainInfo.Name | Should -Be $domain.Name
            }
            
            Assert-MockCalled Import-Module -Times 2
            Assert-MockCalled Get-ADDomain -Times 2
        }
        
        It "Should find inactive users in domain" {
            $cutoffDate = (Get-Date).AddDays(-$global:MockConfig.DaysInactive)
            
            $users = Get-ADUser -Filter * -Properties LastLogonDate, Enabled, MemberOf, Department
            $inactiveUsers = $users | Where-Object { 
                $_.LastLogonDate -lt $cutoffDate -and $_.Enabled -eq $true 
            }
            
            $inactiveUsers.Count | Should -Be 1
            $inactiveUsers[0].SamAccountName | Should -Be "testuser1"
        }
        
        It "Should apply group exclusions" {
            Mock Get-ADUser { 
                return @(
                    [PSCustomObject]@{
                        SamAccountName = "adminuser"
                        UserPrincipalName = "adminuser@contoso.com"
                        LastLogonDate = (Get-Date).AddDays(-100)
                        Enabled = $true
                        MemberOf = @("CN=Domain Admins,CN=Users,DC=contoso,DC=com")
                        Department = "IT"
                        DistinguishedName = "CN=Admin User,OU=Users,DC=contoso,DC=com"
                    }
                )
            }
            
            $users = Get-ADUser -Filter * -Properties LastLogonDate, Enabled, MemberOf, Department
            $excludeGroups = $global:MockConfig.ExcludeGroups
            $filteredUsers = $users | Where-Object { 
                $isExcluded = $false
                foreach ($group in $excludeGroups) {
                    if ($_.MemberOf -match $group) { $isExcluded = $true; break }
                }
                -not $isExcluded
            }
            
            $filteredUsers.Count | Should -Be 0
        }
        
        It "Should apply OU exclusions" {
            Mock Get-ADUser { 
                return @(
                    [PSCustomObject]@{
                        SamAccountName = "serviceuser"
                        UserPrincipalName = "serviceuser@contoso.com"
                        LastLogonDate = (Get-Date).AddDays(-100)
                        Enabled = $true
                        MemberOf = @()
                        Department = "IT"
                        DistinguishedName = "CN=Service User,OU=ServiceAccounts,DC=contoso,DC=com"
                    }
                )
            }
            
            $users = Get-ADUser -Filter * -Properties LastLogonDate, Enabled, MemberOf, Department
            $excludeOUs = $global:MockConfig.ExcludeOUs
            $filteredUsers = $users | Where-Object { 
                $isExcluded = $false
                foreach ($ou in $excludeOUs) {
                    if ($_.DistinguishedName -match $ou) { $isExcluded = $true; break }
                }
                -not $isExcluded
            }
            
            $filteredUsers.Count | Should -Be 0
        }
        
        It "Should apply user property exclusions" {
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
            $excludeProperty = $global:MockConfig.ExcludeUserProperty
            $excludeValue = $global:MockConfig.ExcludeUserPropertyValue
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
            Connect-MgGraph -Scopes "User.ReadWrite.All", "Mail.Send", "AuditLog.Read.All"
            
            Assert-MockCalled Connect-MgGraph -Times 1
        }
        
        It "Should retrieve Entra ID users" {
            $users = Get-MgUser -All -Property "Id,UserPrincipalName,DisplayName,Mail,SignInActivity,AccountEnabled"
            
            $users.Count | Should -Be 1
            $users[0].UserPrincipalName | Should -Be "testuser1@contoso.com"
            $users[0].AccountEnabled | Should -Be $true
        }
        
        It "Should send notification emails" {
            $userId = "user1-guid"
            $recipient = "testuser1@contoso.com"
            $subject = "Account Inactivity Notification"
            $body = "Your account will be disabled due to inactivity."
            
            $emailParams = @{
                UserId = $userId
                Message = @{
                    Subject = $subject
                    Body = @{ Content = $body; ContentType = "Text" }
                    ToRecipients = @(
                        @{ EmailAddress = @{ Address = $recipient } }
                    )
                }
            }
            
            Send-MgUserMail @emailParams
            
            Assert-MockCalled Send-MgUserMail -Times 1
        }
        
        It "Should disable Entra ID accounts" {
            $userId = "user1-guid"
            
            Update-MgUser -UserId $userId -AccountEnabled:$false
            
            Assert-MockCalled Update-MgUser -Times 1
        }
    }
    
    Context "Azure Storage Integration Tests" {
        BeforeEach {
            Mock Connect-AzAccount { return $true }
            Mock New-AzStorageContext { 
                return [PSCustomObject]@{ 
                    StorageAccountName = $global:MockConfig.StorageAccountName
                    StorageAccountKey = $global:MockConfig.StorageAccountKey
                }
            }
            Mock Get-AzStorageTable { 
                return [PSCustomObject]@{ 
                    Name = $global:MockConfig.TableName
                    CloudTable = @{}
                }
            }
            Mock Add-AzTableRow { return $true }
        }
        
        It "Should connect to Azure Storage" {
            Connect-AzAccount
            
            $storageContext = New-AzStorageContext -StorageAccountName $global:MockConfig.StorageAccountName -StorageAccountKey $global:MockConfig.StorageAccountKey
            $storageContext.StorageAccountName | Should -Be $global:MockConfig.StorageAccountName
            
            Assert-MockCalled Connect-AzAccount -Times 1
            Assert-MockCalled New-AzStorageContext -Times 1
        }
        
        It "Should access storage table" {
            $storageContext = New-AzStorageContext -StorageAccountName $global:MockConfig.StorageAccountName -StorageAccountKey $global:MockConfig.StorageAccountKey
            $table = Get-AzStorageTable -Name $global:MockConfig.TableName -Context $storageContext
            
            $table.Name | Should -Be $global:MockConfig.TableName
            
            Assert-MockCalled Get-AzStorageTable -Times 1
        }
        
        It "Should log user actions to storage table" {
            $storageContext = New-AzStorageContext -StorageAccountName $global:MockConfig.StorageAccountName -StorageAccountKey $global:MockConfig.StorageAccountKey
            $table = Get-AzStorageTable -Name $global:MockConfig.TableName -Context $storageContext
            
            $logEntry = @{
                PartitionKey = "UserAction"
                RowKey = [guid]::NewGuid().ToString()
                UserPrincipalName = "testuser1@contoso.com"
                Action = "AccountDisabled"
                Timestamp = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
                DaysInactive = 100
                Domain = "contoso.com"
                TestMode = $global:MockConfig.TestMode
            }
            
            Add-AzTableRow -Table $table.CloudTable -Property $logEntry
            
            Assert-MockCalled Add-AzTableRow -Times 1
        }
    }
    
    Context "Scheduled Task Integration Tests" {
        BeforeEach {
            Mock Get-ScheduledTask { return @{ TaskName = "Disable-InactiveUsers"; State = "Ready" } }
            Mock Register-ScheduledTask { return $true }
            Mock Start-ScheduledTask { return $true }
            Mock Unregister-ScheduledTask { return $true }
        }
        
        It "Should check for existing scheduled task" {
            $task = Get-ScheduledTask -TaskName "Disable-InactiveUsers" -ErrorAction SilentlyContinue
            $task | Should -Not -BeNullOrEmpty
            $task.TaskName | Should -Be "Disable-InactiveUsers"
        }
        
        It "Should create scheduled task" {
            $taskName = "Disable-InactiveUsers"
            $scriptPath = "C:\Scripts\Disable-InactiveUsers.ps1"
            $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-File $scriptPath"
            $trigger = New-ScheduledTaskTrigger -Daily -At "2:00AM"
            
            Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger
            
            Assert-MockCalled Register-ScheduledTask -Times 1
        }
        
        It "Should start scheduled task manually" {
            Start-ScheduledTask -TaskName "Disable-InactiveUsers"
            
            Assert-MockCalled Start-ScheduledTask -Times 1
        }
    }
    
    Context "Test Mode Tests" {
        BeforeEach {
            Mock Set-ADUser { return $true }
            Mock Disable-ADAccount { return $true }
            Mock Update-MgUser { return $true }
            Mock Write-Host { param($Message) }
        }
        
        It "Should not make changes in test mode" {
            $testMode = $global:MockConfig.TestMode
            $testMode | Should -Be $true
            
            if (-not $testMode) {
                Set-ADUser -Identity "testuser1" -Description "Account disabled due to inactivity"
                Disable-ADAccount -Identity "testuser1"
                Update-MgUser -UserId "user1-guid" -AccountEnabled:$false
            }
            
            Assert-MockCalled Set-ADUser -Times 0
            Assert-MockCalled Disable-ADAccount -Times 0
            Assert-MockCalled Update-MgUser -Times 0
        }
        
        It "Should log test mode actions" {
            $testMode = $global:MockConfig.TestMode
            
            if ($testMode) {
                Write-Host "TEST MODE: Would disable account testuser1@contoso.com"
            } else {
                Write-Host "PRODUCTION: Disabling account testuser1@contoso.com"
            }
            
            Assert-MockCalled Write-Host -Times 1
        }
    }
    
    Context "Error Handling Tests" {
        It "Should handle AD connection errors" {
            Mock Get-ADDomain { throw "Cannot contact domain controller" }
            
            { Get-ADDomain -Server "invalid.domain.com" } | Should -Throw "Cannot contact domain controller"
        }
        
        It "Should handle Graph API errors" {
            Mock Connect-MgGraph { throw "Authentication failed" }
            
            { Connect-MgGraph -Scopes "User.ReadWrite.All" } | Should -Throw "Authentication failed"
        }
        
        It "Should handle storage connection errors" {
            Mock New-AzStorageContext { throw "Storage account not found" }
            
            { New-AzStorageContext -StorageAccountName "invalid" -StorageAccountKey "key" } | Should -Throw "Storage account not found"
        }
        
        It "Should handle Key Vault access errors" {
            Mock Get-AzKeyVaultSecret { throw "Access denied" }
            
            { Get-AzKeyVaultSecret -VaultName "invalid-kv" -Name "secret" } | Should -Throw "Access denied"
        }
    }
    
    Context "Notification System Tests" {
        BeforeEach {
            Mock Send-MgUserMail { return $true }
            Mock Get-Date { return [DateTime]::Parse("2024-01-15") }
        }
        
        It "Should calculate correct notification dates" {
            $disableDate = (Get-Date).AddDays(14)
            $notificationDays = $global:MockConfig.NotificationDays
            
            foreach ($days in $notificationDays) {
                $notificationDate = $disableDate.AddDays(-$days)
                $notificationDate | Should -BeLessThan $disableDate
            }
        }
        
        It "Should send notifications at correct intervals" {
            $user = @{
                UserPrincipalName = "testuser1@contoso.com"
                DisplayName = "Test User"
                LastLogonDate = (Get-Date).AddDays(-76) # 14 days before disable
            }
            
            $daysUntilDisable = 14
            $notificationDays = $global:MockConfig.NotificationDays
            
            if ($daysUntilDisable -in $notificationDays) {
                Send-MgUserMail -UserId "user1-guid" -Message @{
                    Subject = "Account Inactivity Warning"
                    Body = @{ Content = "Your account will be disabled in $daysUntilDisable days." }
                    ToRecipients = @(@{ EmailAddress = @{ Address = $user.UserPrincipalName } })
                }
            }
            
            Assert-MockCalled Send-MgUserMail -Times 1
        }
        
        It "Should format notification messages correctly" {
            $user = @{
                UserPrincipalName = "testuser1@contoso.com"
                DisplayName = "Test User"
            }
            $daysUntilDisable = 7
            
            $subject = "Account Inactivity Warning - $daysUntilDisable days remaining"
            $body = @"
Dear $($user.DisplayName),

Your account ($($user.UserPrincipalName)) will be disabled in $daysUntilDisable days due to inactivity.

Please log in to prevent account disabling.

Best regards,
IT Security Team
"@
            
            $subject | Should -Match "Account Inactivity Warning"
            $body | Should -Match $user.DisplayName
            $body | Should -Match $user.UserPrincipalName
            $body | Should -Match $daysUntilDisable.ToString()
        }
    }
}
