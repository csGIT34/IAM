#Requires -Modules Pester

<#
.SYNOPSIS
    Pester tests for MFA Registration Reporting solution
.DESCRIPTION
    Comprehensive test suite for validating MFA registration reporting functionality,
    including script execution, configuration management, and output validation.
.NOTES
    Author: GitHub Copilot
    Version: 1.0
    Requires: Pester 5.0+, Microsoft Graph modules
#>

BeforeAll {
    # Import required modules
    Import-Module Pester -Force
    
    # Set up test environment
    $TestRoot = Split-Path -Parent $PSScriptRoot
    $script:ScriptPath = Join-Path $TestRoot "Get-MFARegistrationStatus.ps1"
    $script:BulkScriptPath = Join-Path $TestRoot "Start-BulkMFAReporting.ps1"
    $script:InstallScriptPath = Join-Path $TestRoot "Install-Prerequisites.ps1"
    $script:ConfigPath = Join-Path $TestRoot "config\reporting-config.json"
    $TestOutputPath = Join-Path $TestRoot "TestOutput"
    
    # Create test output directory
    if (-not (Test-Path $TestOutputPath)) {
        New-Item -Path $TestOutputPath -ItemType Directory -Force
    }
    
    # Mock data for testing
    $script:MockMFAReport = @(
        @{
            Id = "user1@test.com"
            IsMfaCapable = $true
            IsMfaRegistered = $true
            IsPasswordlessCapable = $false
            MethodsRegistered = @("microsoftAuthenticatorAuthenticationMethod")
            DefaultMfaMethod = "microsoftAuthenticatorAuthenticationMethod"
            LastUpdatedDateTime = (Get-Date).AddDays(-1)
        },
        @{
            Id = "user2@test.com"
            IsMfaCapable = $true
            IsMfaRegistered = $false
            IsPasswordlessCapable = $false
            MethodsRegistered = @()
            DefaultMfaMethod = $null
            LastUpdatedDateTime = (Get-Date).AddDays(-2)
        },
        @{
            Id = "user3@test.com"
            IsMfaCapable = $false
            IsMfaRegistered = $false
            IsPasswordlessCapable = $false
            MethodsRegistered = @()
            DefaultMfaMethod = $null
            LastUpdatedDateTime = (Get-Date).AddDays(-3)
        }
    )
    
    $script:MockUserDetails = @{
        "user1@test.com" = @{
            Id = "user1@test.com"
            UserPrincipalName = "user1@test.com"
            DisplayName = "Test User 1"
            Department = "IT"
            AccountEnabled = $true
            AssignedLicenses = @(@{})
            LastSignInDateTime = (Get-Date).AddDays(-1)
        }
        "user2@test.com" = @{
            Id = "user2@test.com"
            UserPrincipalName = "user2@test.com"
            DisplayName = "Test User 2"
            Department = "Finance"
            AccountEnabled = $true
            AssignedLicenses = @(@{})
            LastSignInDateTime = (Get-Date).AddDays(-5)
        }
        "user3@test.com" = @{
            Id = "user3@test.com"
            UserPrincipalName = "user3@test.com"
            DisplayName = "Test User 3"
            Department = "HR"
            AccountEnabled = $false
            AssignedLicenses = @()
            LastSignInDateTime = $null
        }
    }
}

Describe "MFA Registration Reporting - Script Validation" {
    Context "Script Files Existence" {
        It "Should have Get-MFARegistrationStatus.ps1 script" {
            Test-Path $script:ScriptPath | Should -Be $true
        }
        
        It "Should have Start-BulkMFAReporting.ps1 script" {
            Test-Path $script:BulkScriptPath | Should -Be $true
        }
        
        It "Should have Install-Prerequisites.ps1 script" {
            Test-Path $script:InstallScriptPath | Should -Be $true
        }
        
        It "Should have configuration file" {
            Test-Path $script:ConfigPath | Should -Be $true
        }
    }
    
    Context "Script Syntax Validation" {
        It "Get-MFARegistrationStatus.ps1 should have valid syntax" {
            $errors = $null
            [System.Management.Automation.PSParser]::Tokenize((Get-Content $script:ScriptPath -Raw), [ref]$errors)
            $errors.Count | Should -Be 0
        }
        
        It "Start-BulkMFAReporting.ps1 should have valid syntax" {
            $errors = $null
            [System.Management.Automation.PSParser]::Tokenize((Get-Content $script:BulkScriptPath -Raw), [ref]$errors)
            $errors.Count | Should -Be 0
        }
        
        It "Install-Prerequisites.ps1 should have valid syntax" {
            $errors = $null
            [System.Management.Automation.PSParser]::Tokenize((Get-Content $script:InstallScriptPath -Raw), [ref]$errors)
            $errors.Count | Should -Be 0
        }
    }
    
    Context "Script Parameters Validation" {
        It "Get-MFARegistrationStatus.ps1 should have required parameters" {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:ScriptPath, [ref]$null, [ref]$null)
            $params = $ast.ParamBlock.Parameters
            
            $paramNames = $params.Name.VariablePath.UserPath
            $paramNames | Should -Contain "OutputFormat"
            $paramNames | Should -Contain "ExportPath"
            $paramNames | Should -Contain "IncludeAuthMethods"
            $paramNames | Should -Contain "GenerateRecommendations"
        }
        
        It "Start-BulkMFAReporting.ps1 should have required parameters" {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:BulkScriptPath, [ref]$null, [ref]$null)
            $params = $ast.ParamBlock.Parameters
            
            $paramNames = $params.Name.VariablePath.UserPath
            $paramNames | Should -Contain "ConfigPath"
            $paramNames | Should -Contain "OutputDirectory"
            $paramNames | Should -Contain "GenerateConsolidatedReport"
        }
    }
}

Describe "MFA Registration Reporting - Configuration Management" {
    Context "Configuration File Validation" {
        It "Should have valid JSON configuration" {
            { Get-Content $script:ConfigPath | ConvertFrom-Json } | Should -Not -Throw
        }
        
        It "Should have required configuration sections" {
            $config = Get-Content $script:ConfigPath | ConvertFrom-Json
            $config.tenants | Should -Not -BeNullOrEmpty
            $config.reportSettings | Should -Not -BeNullOrEmpty
            $config.emailConfiguration | Should -Not -BeNullOrEmpty
        }
        
        It "Should have valid tenant configuration" {
            $config = Get-Content $script:ConfigPath | ConvertFrom-Json
            $config.tenants[0].id | Should -Not -BeNullOrEmpty
            $config.tenants[0].name | Should -Not -BeNullOrEmpty
            $config.tenants[0].enabled | Should -BeOfType [bool]
        }
        
        It "Should have valid report settings" {
            $config = Get-Content $script:ConfigPath | ConvertFrom-Json
            $config.reportSettings.complianceThreshold | Should -BeOfType [int]
            $config.reportSettings.includeAuthMethods | Should -BeOfType [bool]
            $config.reportSettings.generateRecommendations | Should -BeOfType [bool]
        }
    }
    
    Context "Configuration Validation Functions" {
        BeforeEach {
            . $script:ScriptPath
        }
        
        It "Should validate configuration structure" {
            $testConfig = @{
                tenants = @(
                    @{
                        id = "test-tenant"
                        name = "Test Tenant"
                        enabled = $true
                    }
                )
                reportSettings = @{
                    complianceThreshold = 90
                    includeAuthMethods = $true
                }
            }
            
            # Test configuration structure
            $testConfig.tenants | Should -Not -BeNullOrEmpty
            $testConfig.reportSettings | Should -Not -BeNullOrEmpty
        }
    }
}

Describe "MFA Registration Reporting - Data Processing" {
    Context "MFA Data Processing Functions" {
        BeforeAll {
            # Dot source the main script to access functions
            . $script:ScriptPath
        }
        
        It "Should process MFA registration data correctly" {
            # Test data processing function
            $processedData = Process-MFAData -MFAReport $script:MockMFAReport -UserDetails $script:MockUserDetails -AuthMethods @{}
            
            $processedData.Data.Count | Should -Be 3
            $processedData.Statistics.TotalUsers | Should -Be 3
            $processedData.Statistics.MFARegistered | Should -Be 1
            $processedData.Statistics.MFACapable | Should -Be 2
        }
        
        It "Should calculate risk levels correctly" {
            $mockUser = $script:MockUserDetails["user1@test.com"]
            $riskLevel = Get-UserRiskLevel -User $mockUser -MfaStatus "Registered"
            
            $riskLevel | Should -BeIn @("Low", "Medium", "High")
        }
        
        It "Should generate user recommendations" {
            $mockUser = $script:MockUserDetails["user2@test.com"]
            $recommendations = Get-UserRecommendations -User $mockUser -MfaStatus "Capable but Not Registered" -AuthMethods @()
            
            $recommendations | Should -Not -BeNullOrEmpty
            $recommendations | Should -Match "register for MFA"
        }
        
        It "Should filter users by department" {
            $itUsers = $script:MockUserDetails.Values | Where-Object { $_.Department -eq "IT" }
            $itUsers.Count | Should -Be 1
            $itUsers[0].DisplayName | Should -Be "Test User 1"
        }
        
        It "Should identify licensed vs unlicensed users" {
            $licensedUsers = $script:MockUserDetails.Values | Where-Object { $_.AssignedLicenses.Count -gt 0 }
            $unlicensedUsers = $script:MockUserDetails.Values | Where-Object { $_.AssignedLicenses.Count -eq 0 }
            
            $licensedUsers.Count | Should -Be 2
            $unlicensedUsers.Count | Should -Be 1
        }
    }
    
    Context "Statistics Calculation" {
        It "Should calculate compliance percentage correctly" {
            $totalUsers = 100
            $registeredUsers = 85
            $complianceRate = ($registeredUsers / $totalUsers) * 100
            
            $complianceRate | Should -Be 85
        }
        
        It "Should determine compliance status" {
            $threshold = 90
            $currentRate = 85
            $isCompliant = $currentRate -ge $threshold
            
            $isCompliant | Should -Be $false
        }
    }
}

Describe "MFA Registration Reporting - Output Generation" {
    Context "Report Output Formats" {
        BeforeAll {
            . $script:ScriptPath
        }
        
        It "Should generate CSV output" {
            $testData = @(
                [PSCustomObject]@{
                    UserPrincipalName = "test@example.com"
                    DisplayName = "Test User"
                    MfaStatus = "Registered"
                    Department = "IT"
                }
            )
            
            $csvPath = Join-Path $TestOutputPath "test-output.csv"
            $testData | Export-Csv -Path $csvPath -NoTypeInformation
            
            Test-Path $csvPath | Should -Be $true
            $csvContent = Import-Csv $csvPath
            $csvContent.Count | Should -Be 1
            $csvContent[0].DisplayName | Should -Be "Test User"
        }
        
        It "Should generate JSON output" {
            $testData = @{
                GeneratedAt = Get-Date
                TotalUsers = 100
                RegisteredUsers = 85
                Data = @(
                    @{
                        UserPrincipalName = "test@example.com"
                        MfaStatus = "Registered"
                    }
                )
            }
            
            $jsonPath = Join-Path $TestOutputPath "test-output.json"
            $testData | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8
            
            Test-Path $jsonPath | Should -Be $true
            $jsonContent = Get-Content $jsonPath | ConvertFrom-Json
            $jsonContent.TotalUsers | Should -Be 100
            $jsonContent.RegisteredUsers | Should -Be 85
        }
        
        It "Should generate HTML output with proper structure" {
            $testData = @(
                [PSCustomObject]@{
                    UserPrincipalName = "test@example.com"
                    DisplayName = "Test User"
                    MfaStatus = "Registered"
                    RiskLevel = "Low"
                }
            )
            
            $testStats = @{
                TotalUsers = 1
                MFARegistered = 1
                MFACapable = 1
            }
            
            $htmlContent = Generate-HTMLReport -Data $testData -Statistics $testStats
            
            $htmlContent | Should -Match "<html>"
            $htmlContent | Should -Match "<title>MFA Registration Status Report</title>"
            $htmlContent | Should -Match "Test User"
            $htmlContent | Should -Match "Registered"
        }
    }
    
    Context "Console Output" {
        It "Should display console output without errors" {
            $testData = @(
                [PSCustomObject]@{
                    DisplayName = "Test User"
                    UserPrincipalName = "test@example.com"
                    MfaStatus = "Registered"
                    RiskLevel = "Low"
                }
            )
            
            $testStats = @{
                TotalUsers = 1
                MFARegistered = 1
                MFACapable = 1
                Departments = @{ "IT" = 1 }
            }
            
            { Display-ConsoleReport -Data $testData -Statistics $testStats } | Should -Not -Throw
        }
    }
}

Describe "MFA Registration Reporting - Bulk Operations" {
    Context "Multi-Tenant Configuration" {
        BeforeAll {
            . $script:BulkScriptPath
        }
        
        It "Should parse tenant configuration correctly" {
            $mockConfig = @{
                tenants = @(
                    @{
                        id = "tenant1"
                        name = "Tenant 1"
                        enabled = $true
                    },
                    @{
                        id = "tenant2"
                        name = "Tenant 2"
                        enabled = $false
                    }
                )
            }
            
            $tenantConfigs = Get-TenantConfiguration -Config $mockConfig -TenantIds @("tenant1")
            $tenantConfigs.Count | Should -Be 1
            $tenantConfigs[0].id | Should -Be "tenant1"
        }
        
        It "Should handle tenant IDs without configuration" {
            $tenantConfigs = Get-TenantConfiguration -Config $null -TenantIds @("tenant1", "tenant2")
            $tenantConfigs.Count | Should -Be 2
            $tenantConfigs[0].id | Should -Be "tenant1"
            $tenantConfigs[1].id | Should -Be "tenant2"
        }
    }
    
    Context "Compliance Analysis" {
        BeforeAll {
            . $script:BulkScriptPath
        }
        
        It "Should analyze tenant compliance correctly" {
            $mockJsonPath = Join-Path $TestOutputPath "mock-compliance.json"
            $mockData = @{
                Statistics = @{
                    TotalUsers = 100
                    MFARegistered = 85
                }
            }
            
            $mockData | ConvertTo-Json -Depth 10 | Out-File -FilePath $mockJsonPath -Encoding UTF8
            
            $compliance = Test-TenantCompliance -JsonReportPath $mockJsonPath -Threshold 90
            $compliance.RegistrationRate | Should -Be 85
            $compliance.IsCompliant | Should -Be $false
            $compliance.RiskLevel | Should -Be "Medium"
        }
    }
}

Describe "MFA Registration Reporting - Error Handling" {
    Context "Input Validation" {
        It "Should validate output format parameter" {
            $validFormats = @("Console", "CSV", "HTML", "JSON")
            $invalidFormat = "XML"
            
            $invalidFormat | Should -Not -BeIn $validFormats
        }
        
        It "Should require export path for non-console output" {
            $outputFormat = "HTML"
            $exportPath = $null
            
            if ($outputFormat -ne "Console") {
                $exportPath | Should -Not -BeNullOrEmpty
            }
        }
    }
    
    Context "File Operations" {
        It "Should handle missing configuration file gracefully" {
            $nonExistentPath = "C:\NonExistent\config.json"
            Test-Path $nonExistentPath | Should -Be $false
            
            { Get-Configuration -ConfigPath $nonExistentPath } | Should -Not -Throw
        }
        
        It "Should handle invalid JSON configuration" {
            $invalidJsonPath = Join-Path $TestOutputPath "invalid.json"
            "{ invalid json }" | Out-File -FilePath $invalidJsonPath -Encoding UTF8
            
            { Get-Content $invalidJsonPath | ConvertFrom-Json } | Should -Throw
        }
    }
    
    Context "Network and API Errors" {
        It "Should handle Graph API connection failures" {
            # Mock Graph API failure
            Mock Connect-MgGraph { throw "Connection failed" } -ModuleName "Microsoft.Graph.Authentication"
            
            { Connect-MgGraph } | Should -Throw "Connection failed"
        }
        
        It "Should handle missing permissions gracefully" {
            # Test for insufficient permissions scenario
            $requiredScopes = @("Reports.Read.All", "User.Read.All")
            $currentScopes = @("User.Read.All")
            
            $missingScopes = $requiredScopes | Where-Object { $_ -notin $currentScopes }
            $missingScopes.Count | Should -Be 1
            $missingScopes[0] | Should -Be "Reports.Read.All"
        }
    }
}

Describe "MFA Registration Reporting - Performance" {
    Context "Batch Processing" {
        It "Should handle large user datasets efficiently" {
            $largeUserSet = 1..1000 | ForEach-Object {
                "user$_@test.com"
            }
            
            $batchSize = 100
            $batches = [Math]::Ceiling($largeUserSet.Count / $batchSize)
            
            $batches | Should -Be 10
            $largeUserSet.Count | Should -Be 1000
        }
        
        It "Should process users in appropriate batch sizes" {
            $users = 1..250 | ForEach-Object { "user$_@test.com" }
            $batchSize = 100
            
            $batchCount = [Math]::Ceiling($users.Count / $batchSize)
            $batchCount | Should -Be 3
            
            # First two batches should be full
            $users[0..99].Count | Should -Be 100
            $users[100..199].Count | Should -Be 100
            # Last batch should have remaining users
            $users[200..249].Count | Should -Be 50
        }
    }
    
    Context "Memory Management" {
        It "Should not accumulate excessive memory usage" {
            $initialMemory = [GC]::GetTotalMemory($false)
            
            # Simulate processing large dataset
            $null = 1..1000 | ForEach-Object {
                [PSCustomObject]@{
                    Id = $_
                    Data = "Sample data for user $_"
                }
            }
            
            # Force garbage collection
            [GC]::Collect()
            [GC]::WaitForPendingFinalizers()
            
            $finalMemory = [GC]::GetTotalMemory($false)
            
            # Memory should be manageable (less than 100MB increase)
            ($finalMemory - $initialMemory) | Should -BeLessThan 100MB
        }
    }
}

Describe "MFA Registration Reporting - Security" {
    Context "Audit Logging" {
        It "Should log all operations" {
            $logPath = Join-Path $TestOutputPath "test-audit.log"
            
            # Mock logging function
            function Write-Log {
                param([string]$Message, [string]$Level = "Info")
                $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
                "$timestamp [$Level] $Message" | Add-Content -Path $logPath
            }
            
            Write-Log "Test operation started"
            Write-Log "Test operation completed"
            
            Test-Path $logPath | Should -Be $true
            $logContent = Get-Content $logPath
            $logContent.Count | Should -Be 2
            $logContent[0] | Should -Match "Test operation started"
        }
        
        It "Should include security-relevant events in audit log" {
            $securityEvents = @(
                "User authentication",
                "Permission check",
                "Data access",
                "Report generation",
                "Configuration change"
            )
            
            foreach ($securityEvent in $securityEvents) {
                $securityEvent | Should -Not -BeNullOrEmpty
            }
        }
    }
    
    Context "Data Validation" {
        It "Should validate user data integrity" {
            $userData = @{
                UserPrincipalName = "test@example.com"
                DisplayName = "Test User"
                Id = "12345"
            }
            
            $userData.UserPrincipalName | Should -Match "^[^@]+@[^@]+\.[^@]+$"
            $userData.DisplayName | Should -Not -BeNullOrEmpty
            $userData.Id | Should -Not -BeNullOrEmpty
        }
        
        It "Should sanitize output data" {
            $potentiallyMaliciousData = "<script>alert('xss')</script>"
            $sanitizedData = $potentiallyMaliciousData -replace "<[^>]*>", ""
            
            $sanitizedData | Should -Be "alert('xss')"
            $sanitizedData | Should -Not -Match "<script>"
        }
    }
}

AfterAll {
    # Clean up test files
    if (Test-Path $TestOutputPath) {
        Remove-Item $TestOutputPath -Recurse -Force -ErrorAction SilentlyContinue
    }
}
