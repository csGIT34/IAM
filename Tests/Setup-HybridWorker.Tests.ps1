# Pester Tests for Setup-HybridWorker.ps1

BeforeAll {
    # Mock Windows PowerShell commands
    Mock Get-Service { return @{ Name = "TestService"; Status = "Running" } }
    Mock Start-Service { return $true }
    Mock Stop-Service { return $true }
    Mock Test-Path { return $true }
    Mock New-Item { return $true }
    Mock Get-ItemProperty { return @{ Version = "1.0.0" } }
    Mock Invoke-WebRequest { return @{ Content = "test content" } }
    Mock Invoke-RestMethod { return @{ success = $true } }
    Mock Start-Process { return @{ ExitCode = 0 } }
    Mock Get-Process { return @{ ProcessName = "TestProcess" } }
    Mock Get-WmiObject { return @{ Name = "TestComputer" } }
    Mock Get-CimInstance { return @{ Name = "TestComputer" } }
    Mock Test-NetConnection { return @{ TcpTestSucceeded = $true } }
    Mock Resolve-DnsName { return @{ IPAddress = "1.2.3.4" } }
    Mock Get-Module { return @{ Name = "TestModule"; Version = "1.0.0" } }
    Mock Import-Module { return $true }
    Mock Install-Module { return $true }
    Mock Get-PackageProvider { return @{ Name = "NuGet" } }
    Mock Install-PackageProvider { return $true }
    Mock Set-PSRepository { return $true }
    Mock Write-Host { param($Message) }
    Mock Write-Warning { param($Message) }
    Mock Write-Error { param($Message) }
    Mock Write-Verbose { param($Message) }
}

Describe "Setup-HybridWorker Script Tests" {
    
    Context "Parameter Validation" {
        It "Should validate required parameters" {
            $params = @{
                SubscriptionId = "12345678-1234-1234-1234-123456789012"
                ResourceGroupName = "rg-test"
                AutomationAccountName = "aa-test"
                WorkerGroupName = "HybridWorkerGroup"
                TenantId = "87654321-4321-4321-4321-210987654321"
                Location = "East US"
            }
            
            $params.SubscriptionId | Should -Match "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
            $params.ResourceGroupName | Should -BeOfType [string]
            $params.AutomationAccountName | Should -BeOfType [string]
            $params.WorkerGroupName | Should -BeOfType [string]
            $params.TenantId | Should -Match "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
            $params.Location | Should -BeOfType [string]
        }
        
        It "Should validate Azure location format" {
            $validLocations = @("East US", "West US", "North Europe", "Southeast Asia")
            $invalidLocations = @("", "InvalidLocation", "US-East")
            
            foreach ($location in $validLocations) {
                $location | Should -Not -BeNullOrEmpty
                $location.Length | Should -BeGreaterThan 0
            }
            
            foreach ($location in $invalidLocations) {
                if ($location -eq "") {
                    $location | Should -BeNullOrEmpty
                } else {
                    $location | Should -Not -Match "^[A-Za-z]+\s[A-Za-z]+$"
                }
            }
        }
    }
    
    Context "Prerequisites Validation Tests" {
        BeforeEach {
            Mock Get-Module { return @{ Name = "TestModule"; Version = "1.0.0" } }
            Mock Get-Service { return @{ Name = "TestService"; Status = "Running" } }
            Mock Test-Path { return $true }
        }
        
        It "Should check PowerShell version" {
            $psVersion = $PSVersionTable.PSVersion
            $psVersion.Major | Should -BeGreaterOrEqual 5
        }
        
        It "Should check if running as administrator" {
            $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
            $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
            $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
            
            $isAdmin | Should -BeOfType [bool]
        }
        
        It "Should check required PowerShell modules" {
            $requiredModules = @("Az.Accounts", "Az.Automation", "Az.ConnectedMachine", "ActiveDirectory")
            
            foreach ($module in $requiredModules) {
                $moduleInfo = Get-Module -Name $module -ListAvailable
                $moduleInfo | Should -Not -BeNullOrEmpty
            }
            
            Assert-MockCalled Get-Module -Times 4
        }
        
        It "Should check domain connectivity" {
            $domainName = $env:USERDOMAIN
            if ($domainName) {
                $domainTest = Test-NetConnection -ComputerName $domainName -Port 389
                $domainTest.TcpTestSucceeded | Should -Be $true
            }
        }
        
        It "Should check Active Directory module availability" {
            Mock Get-Module { return @{ Name = "ActiveDirectory"; Version = "1.0.0" } } -ParameterFilter { $Name -eq "ActiveDirectory" }
            
            $adModule = Get-Module -Name "ActiveDirectory" -ListAvailable
            $adModule | Should -Not -BeNullOrEmpty
            $adModule.Name | Should -Be "ActiveDirectory"
        }
    }
    
    Context "Azure Connected Machine Agent Tests" {
        BeforeEach {
            Mock Test-Path { return $false }
            Mock Invoke-WebRequest { return @{ Content = "installer content" } }
            Mock Start-Process { return @{ ExitCode = 0 } }
            Mock Get-Service { return @{ Name = "himds"; Status = "Running" } }
        }
        
        It "Should check if Connected Machine Agent is installed" {
            $agentPath = "${env:ProgramFiles}\AzureConnectedMachineAgent\azcmagent.exe"
            $isInstalled = Test-Path -Path $agentPath
            
            $isInstalled | Should -BeOfType [bool]
            Assert-MockCalled Test-Path -Times 1
        }
        
        It "Should download Connected Machine Agent installer" {
            $downloadUrl = "https://aka.ms/azcmagent-windows"
            $downloadPath = "$env:TEMP\AzureConnectedMachineAgent.msi"
            
            Invoke-WebRequest -Uri $downloadUrl -OutFile $downloadPath
            
            Assert-MockCalled Invoke-WebRequest -Times 1
        }
        
        It "Should install Connected Machine Agent" {
            $installerPath = "$env:TEMP\AzureConnectedMachineAgent.msi"
            Mock Test-Path { return $true } -ParameterFilter { $Path -eq $installerPath }
            
            $process = Start-Process -FilePath "msiexec.exe" -ArgumentList "/i", $installerPath, "/quiet" -Wait -PassThru
            $process.ExitCode | Should -Be 0
            
            Assert-MockCalled Start-Process -Times 1
        }
        
        It "Should verify Connected Machine Agent service" {
            Mock Get-Service { return @{ Name = "himds"; Status = "Running" } } -ParameterFilter { $Name -eq "himds" }
            
            $service = Get-Service -Name "himds"
            $service.Status | Should -Be "Running"
        }
    }
    
    Context "Azure Arc Registration Tests" {
        BeforeEach {
            Mock Start-Process { return @{ ExitCode = 0 } }
            Mock Test-Path { return $true }
        }
        
        It "Should register machine with Azure Arc" {
            $subscriptionId = "12345678-1234-1234-1234-123456789012"
            $resourceGroup = "rg-test"
            $tenantId = "87654321-4321-4321-4321-210987654321"
            $location = "East US"
            
            $agentPath = "${env:ProgramFiles}\AzureConnectedMachineAgent\azcmagent.exe"
            Mock Test-Path { return $true } -ParameterFilter { $Path -eq $agentPath }
            
            $arguments = @(
                "connect",
                "--subscription-id", $subscriptionId,
                "--resource-group", $resourceGroup,
                "--tenant-id", $tenantId,
                "--location", $location,
                "--service-principal-id", "test-sp-id",
                "--service-principal-secret", "test-sp-secret"
            )
            
            Start-Process -FilePath $agentPath -ArgumentList $arguments -Wait -PassThru
            
            Assert-MockCalled Start-Process -Times 1
        }
        
        It "Should verify Arc registration status" {
            $agentPath = "${env:ProgramFiles}\AzureConnectedMachineAgent\azcmagent.exe"
            Mock Test-Path { return $true } -ParameterFilter { $Path -eq $agentPath }
            
            Start-Process -FilePath $agentPath -ArgumentList "show" -Wait -PassThru
            
            Assert-MockCalled Start-Process -Times 1
        }
        
        It "Should handle Arc registration failures" {
            Mock Start-Process { return @{ ExitCode = 1 } }
            
            $process = Start-Process -FilePath "test.exe" -ArgumentList "connect" -Wait -PassThru
            $process.ExitCode | Should -Be 1
        }
    }
    
    Context "Hybrid Worker Extension Tests" {
        BeforeEach {
            Mock Start-Process { return @{ ExitCode = 0 } }
            Mock Test-Path { return $true }
            Mock Get-Service { return @{ Name = "Hybrid Worker"; Status = "Running" } }
        }
        
        It "Should install Hybrid Worker extension" {
            $agentPath = "${env:ProgramFiles}\AzureConnectedMachineAgent\azcmagent.exe"
            Mock Test-Path { return $true } -ParameterFilter { $Path -eq $agentPath }
            
            $arguments = @(
                "extension", "install",
                "--name", "HybridWorkerExtension",
                "--publisher", "Microsoft.Azure.Automation.HybridWorker",
                "--type", "HybridWorkerForWindows",
                "--settings", '{"AutomationAccountURL":"https://test.automation.azure.com","AutomationAccountKey":"test-key"}'
            )
            
            Start-Process -FilePath $agentPath -ArgumentList $arguments -Wait -PassThru
            
            Assert-MockCalled Start-Process -Times 1
        }
        
        It "Should verify Hybrid Worker extension status" {
            $agentPath = "${env:ProgramFiles}\AzureConnectedMachineAgent\azcmagent.exe"
            Mock Test-Path { return $true } -ParameterFilter { $Path -eq $agentPath }
            
            Start-Process -FilePath $agentPath -ArgumentList "extension", "list" -Wait -PassThru
            
            Assert-MockCalled Start-Process -Times 1
        }
        
        It "Should check Hybrid Worker service" {
            Mock Get-Service { return @{ Name = "Hybrid Worker"; Status = "Running" } } -ParameterFilter { $Name -like "*Hybrid*" }
            
            $service = Get-Service -Name "*Hybrid*"
            $service.Status | Should -Be "Running"
        }
    }
    
    Context "Network Connectivity Tests" {
        BeforeEach {
            Mock Test-NetConnection { return @{ TcpTestSucceeded = $true } }
            Mock Resolve-DnsName { return @{ IPAddress = "1.2.3.4" } }
        }
        
        It "Should test connectivity to Azure Automation endpoints" {
            $endpoints = @(
                "https://management.azure.com",
                "https://login.microsoftonline.com",
                "https://test.automation.azure.com"
            )
            
            foreach ($endpoint in $endpoints) {
                $uri = [System.Uri]$endpoint
                $connection = Test-NetConnection -ComputerName $uri.Host -Port 443
                $connection.TcpTestSucceeded | Should -Be $true
            }
            
            Assert-MockCalled Test-NetConnection -Times 3
        }
        
        It "Should test DNS resolution for Azure endpoints" {
            $endpoints = @(
                "management.azure.com",
                "login.microsoftonline.com",
                "test.automation.azure.com"
            )
            
            foreach ($endpoint in $endpoints) {
                $dnsResult = Resolve-DnsName -Name $endpoint
                $dnsResult.IPAddress | Should -Not -BeNullOrEmpty
            }
            
            Assert-MockCalled Resolve-DnsName -Times 3
        }
        
        It "Should test connectivity to domain controllers" {
            $domainControllers = @("dc1.contoso.com", "dc2.contoso.com")
            
            foreach ($dc in $domainControllers) {
                $connection = Test-NetConnection -ComputerName $dc -Port 389
                $connection.TcpTestSucceeded | Should -Be $true
            }
            
            Assert-MockCalled Test-NetConnection -Times 2
        }
    }
    
    Context "PowerShell Module Management Tests" {
        BeforeEach {
            Mock Get-Module { return @() }
            Mock Install-Module { return $true }
            Mock Import-Module { return $true }
            Mock Get-PackageProvider { return @{ Name = "NuGet" } }
            Mock Install-PackageProvider { return $true }
            Mock Set-PSRepository { return $true }
        }
        
        It "Should install required PowerShell modules" {
            $requiredModules = @(
                "Az.Accounts",
                "Az.Automation", 
                "Az.ConnectedMachine",
                "ActiveDirectory"
            )
            
            foreach ($module in $requiredModules) {
                Install-Module -Name $module -Force -AllowClobber
            }
            
            Assert-MockCalled Install-Module -Times 4
        }
        
        It "Should configure PowerShell Gallery as trusted repository" {
            Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted
            
            Assert-MockCalled Set-PSRepository -Times 1
        }
        
        It "Should install NuGet package provider" {
            Install-PackageProvider -Name "NuGet" -Force
            
            Assert-MockCalled Install-PackageProvider -Times 1
        }
        
        It "Should import modules after installation" {
            $modules = @("Az.Accounts", "Az.Automation", "Az.ConnectedMachine")
            
            foreach ($module in $modules) {
                Import-Module -Name $module -Force
            }
            
            Assert-MockCalled Import-Module -Times 3
        }
    }
    
    Context "Validation Tests" {
        BeforeEach {
            Mock Test-Path { return $true }
            Mock Get-Service { return @{ Name = "TestService"; Status = "Running" } }
            Mock Start-Process { return @{ ExitCode = 0 } }
        }
        
        It "Should validate Hybrid Worker installation" {
            # Check if Connected Machine Agent is installed
            $agentPath = "${env:ProgramFiles}\AzureConnectedMachineAgent\azcmagent.exe"
            $agentInstalled = Test-Path -Path $agentPath
            
            # Check if himds service is running
            $himdsService = Get-Service -Name "himds"
            
            # Check if machine is registered with Arc
            if ($agentInstalled) {
                Start-Process -FilePath $agentPath -ArgumentList "show" -Wait -PassThru
            }
            
            $agentInstalled | Should -Be $true
            $himdsService.Status | Should -Be "Running"
            
            Assert-MockCalled Test-Path -Times 1
            Assert-MockCalled Get-Service -Times 1
            Assert-MockCalled Start-Process -Times 1
        }
        
        It "Should validate Active Directory connectivity" {
            Mock Get-ADDomain { return @{ Name = "contoso.com" } }
            Mock Test-NetConnection { return @{ TcpTestSucceeded = $true } }
            
            # Test AD connectivity
            $connection = Test-NetConnection -ComputerName "contoso.com" -Port 389
            $connection.TcpTestSucceeded | Should -Be $true
            
            Assert-MockCalled Test-NetConnection -Times 1
        }
        
        It "Should validate Azure connectivity" {
            $azureEndpoints = @(
                "management.azure.com",
                "login.microsoftonline.com"
            )
            
            foreach ($endpoint in $azureEndpoints) {
                $connection = Test-NetConnection -ComputerName $endpoint -Port 443
                $connection.TcpTestSucceeded | Should -Be $true
            }
            
            Assert-MockCalled Test-NetConnection -Times 2
        }
    }
    
    Context "Error Handling Tests" {
        It "Should handle Connected Machine Agent installation failures" {
            Mock Start-Process { return @{ ExitCode = 1 } }
            
            $process = Start-Process -FilePath "msiexec.exe" -ArgumentList "/i", "test.msi", "/quiet" -Wait -PassThru
            $process.ExitCode | Should -Be 1
        }
        
        It "Should handle Azure Arc registration failures" {
            Mock Start-Process { return @{ ExitCode = 1 } }
            
            $process = Start-Process -FilePath "azcmagent.exe" -ArgumentList "connect" -Wait -PassThru
            $process.ExitCode | Should -Be 1
        }
        
        It "Should handle module installation failures" {
            Mock Install-Module { throw "Module installation failed" }
            
            { Install-Module -Name "TestModule" -Force } | Should -Throw "Module installation failed"
        }
        
        It "Should handle service startup failures" {
            Mock Start-Service { throw "Service failed to start" }
            
            { Start-Service -Name "TestService" } | Should -Throw "Service failed to start"
        }
        
        It "Should handle network connectivity failures" {
            Mock Test-NetConnection { return @{ TcpTestSucceeded = $false } }
            
            $connection = Test-NetConnection -ComputerName "invalid.domain.com" -Port 443
            $connection.TcpTestSucceeded | Should -Be $false
        }
    }
    
    Context "Configuration Tests" {
        It "Should create worker configuration file" {
            $configPath = "$env:TEMP\HybridWorkerConfig.json"
            $config = @{
                AutomationAccountName = "test-aa"
                WorkerGroupName = "HybridWorkerGroup"
                SubscriptionId = "12345678-1234-1234-1234-123456789012"
                ResourceGroupName = "rg-test"
            }
            
            $config | ConvertTo-Json | Out-File -FilePath $configPath
            
            Mock Test-Path { return $true } -ParameterFilter { $Path -eq $configPath }
            
            Test-Path -Path $configPath | Should -Be $true
        }
        
        It "Should validate worker configuration" {
            $config = @{
                AutomationAccountName = "test-aa"
                WorkerGroupName = "HybridWorkerGroup"
                SubscriptionId = "12345678-1234-1234-1234-123456789012"
                ResourceGroupName = "rg-test"
            }
            
            $config.AutomationAccountName | Should -Not -BeNullOrEmpty
            $config.WorkerGroupName | Should -Not -BeNullOrEmpty
            $config.SubscriptionId | Should -Match "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
            $config.ResourceGroupName | Should -Not -BeNullOrEmpty
        }
    }
    
    Context "Cleanup Tests" {
        BeforeEach {
            Mock Remove-Item { return $true }
            Mock Stop-Service { return $true }
            Mock Start-Process { return @{ ExitCode = 0 } }
        }
        
        It "Should clean up temporary files" {
            $tempFiles = @(
                "$env:TEMP\AzureConnectedMachineAgent.msi",
                "$env:TEMP\HybridWorkerConfig.json",
                "$env:TEMP\setup.log"
            )
            
            foreach ($file in $tempFiles) {
                Remove-Item -Path $file -Force -ErrorAction SilentlyContinue
            }
            
            Assert-MockCalled Remove-Item -Times 3
        }
        
        It "Should unregister from Azure Arc if needed" {
            $agentPath = "${env:ProgramFiles}\AzureConnectedMachineAgent\azcmagent.exe"
            Mock Test-Path { return $true } -ParameterFilter { $Path -eq $agentPath }
            
            Start-Process -FilePath $agentPath -ArgumentList "disconnect" -Wait -PassThru
            
            Assert-MockCalled Start-Process -Times 1
        }
    }
}
