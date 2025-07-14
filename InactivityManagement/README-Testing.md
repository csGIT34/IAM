# PowerShell Testing README

## Overview

This directory contains comprehensive Pester tests for the IAM (Identity and Access Management) solution. The tests cover all major components including Azure Automation runbooks, setup scripts, and legacy on-premises scripts.

## Test Structure

### Test Files

- **`AzureAutomation-DisableInactiveUsers.Tests.ps1`** - Tests for the main Azure Automation runbook
- **`Setup-AzureAutomation.Tests.ps1`** - Tests for Azure Automation setup script
- **`Setup-HybridWorker.Tests.ps1`** - Tests for Hybrid Worker configuration script
- **`Legacy-Scripts.Tests.ps1`** - Tests for on-premises scripts (Disable-InactiveUsers.ps1 and Config-DisableInactiveUsers.ps1)

### Test Categories

Each test file contains the following test categories:

1. **Parameter Validation** - Tests for input parameter validation
2. **Configuration Tests** - Tests for configuration loading and validation
3. **Integration Tests** - Tests for external service integration (Azure, AD, Graph)
4. **Error Handling** - Tests for error scenarios and exception handling
5. **Functionality Tests** - Tests for core business logic
6. **Security Tests** - Tests for security-related functionality

## Setup Instructions

### Prerequisites

- PowerShell 5.1 or later
- Administrator privileges (for module installation)
- Internet connection for downloading modules

### Quick Setup

1. **Install Test Dependencies:**
   ```powershell
   .\Install-TestDependencies.ps1
   ```

2. **Run All Tests:**
   ```powershell
   .\Test-Runner.ps1
   Invoke-AllTests
   ```

### Manual Setup

If you prefer to install dependencies manually:

```powershell
# Install required modules
Install-Module -Name Pester -MinimumVersion 5.5.0 -Force -AllowClobber
Install-Module -Name PSScriptAnalyzer -Force -AllowClobber
Install-Module -Name Az.Accounts -Force -AllowClobber
Install-Module -Name Az.Automation -Force -AllowClobber
Install-Module -Name Microsoft.Graph.Authentication -Force -AllowClobber
```

## Running Tests

### Using Test Runner (Recommended)

The `Test-Runner.ps1` script provides a convenient way to run tests:

```powershell
# Load the test runner
.\Test-Runner.ps1

# Run all tests
Invoke-AllTests

# Run tests with code coverage
Invoke-AllTests -Coverage

# Run specific test file
Invoke-TestFile -TestFile "AzureAutomation-DisableInactiveUsers"

# Run tests by tag
Invoke-TestsByTag -Tags "Integration", "Security"

# Generate HTML report
New-TestReport

# Clean old test results
Clear-TestResults
```

### Direct Pester Commands

You can also run tests directly with Pester:

```powershell
# Run all tests
Invoke-Pester -Path .\Tests\

# Run specific test file
Invoke-Pester -Path .\Tests\AzureAutomation-DisableInactiveUsers.Tests.ps1

# Run with coverage
Invoke-Pester -Path .\Tests\ -CodeCoverage .\*.ps1
```

## Test Configuration

### Mock Dependencies

The tests use extensive mocking to isolate functionality:

- **Azure PowerShell cmdlets** - Mocked to avoid actual Azure calls
- **Microsoft Graph cmdlets** - Mocked to simulate Graph API responses
- **Active Directory cmdlets** - Mocked to simulate AD operations
- **File system operations** - Mocked to avoid file dependencies
- **Network operations** - Mocked to simulate connectivity tests

### Test Data

Test data is defined in `BeforeAll` blocks and includes:

- Mock configuration objects
- Sample user data
- Test credentials
- Mock service responses

## Understanding Test Results

### Test Output

Tests provide detailed output including:

- **Test execution summary** - Pass/fail counts and duration
- **Code coverage metrics** - Percentage of code tested
- **Failed test details** - Error messages and stack traces
- **Performance metrics** - Test execution times

### Test Reports

The test runner generates:

- **XML reports** - NUnit format for CI/CD integration
- **HTML reports** - Human-readable test results
- **Coverage reports** - JaCoCo format for code coverage

## Test Categories and Tags

Tests are organized by functionality:

### Core Functionality
- User discovery and filtering
- Account disabling logic
- Notification system
- Logging and auditing

### Integration Testing
- Azure Automation integration
- Microsoft Graph API calls
- Active Directory operations
- Azure Storage operations

### Security Testing
- Authentication mechanisms
- Permission validation
- Credential handling
- Data encryption

### Error Handling
- Network failures
- Authentication errors
- Permission issues
- Invalid configurations

## Continuous Integration

### GitHub Actions

Example workflow configuration:

```yaml
name: PowerShell Tests

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  test:
    runs-on: windows-latest
    
    steps:
    - uses: actions/checkout@v2
    
    - name: Install Dependencies
      run: .\Install-TestDependencies.ps1
      shell: powershell
    
    - name: Run Tests
      run: |
        .\Test-Runner.ps1
        Invoke-AllTests -Coverage
      shell: powershell
    
    - name: Upload Test Results
      uses: actions/upload-artifact@v2
      with:
        name: test-results
        path: TestResults/
```

### Azure DevOps

Example pipeline configuration:

```yaml
trigger:
- main

pool:
  vmImage: 'windows-latest'

steps:
- task: PowerShell@2
  displayName: 'Install Test Dependencies'
  inputs:
    filePath: 'Install-TestDependencies.ps1'

- task: PowerShell@2
  displayName: 'Run Tests'
  inputs:
    targetType: 'inline'
    script: |
      .\Test-Runner.ps1
      Invoke-AllTests -Coverage

- task: PublishTestResults@2
  inputs:
    testResultsFormat: 'NUnit'
    testResultsFiles: 'TestResults/*.xml'
```

## Best Practices

### Writing Tests

1. **Use descriptive test names** - Clearly describe what is being tested
2. **Test one thing at a time** - Each test should focus on a single behavior
3. **Use appropriate assertions** - Choose the right Should assertion for the scenario
4. **Mock external dependencies** - Isolate the code under test
5. **Clean up after tests** - Reset state between tests

### Test Organization

1. **Group related tests** - Use Describe and Context blocks effectively
2. **Use BeforeAll/BeforeEach** - Set up test data consistently
3. **Tag tests appropriately** - Enable selective test execution
4. **Document test purpose** - Add comments for complex test scenarios

### Performance Considerations

1. **Mock heavy operations** - Avoid actual network calls or file operations
2. **Use parallel execution** - When tests are independent
3. **Optimize test data** - Use minimal datasets for testing
4. **Cache expensive operations** - Reuse setup where possible

## Troubleshooting

### Common Issues

1. **Module Import Errors**
   - Solution: Run `Install-TestDependencies.ps1` as Administrator

2. **Permission Errors**
   - Solution: Ensure running as Administrator for system-wide module installation

3. **Network Connectivity Issues**
   - Solution: All external calls should be mocked in tests

4. **Test Timeout Issues**
   - Solution: Reduce test data size or increase timeout values

### Debug Mode

To run tests in debug mode:

```powershell
# Enable verbose output
$VerbosePreference = 'Continue'
Invoke-AllTests

# Run with debug output
$DebugPreference = 'Continue'
Invoke-Pester -Path .\Tests\ -Output Detailed
```

## Contributing

When adding new tests:

1. Follow the existing test structure and naming conventions
2. Add appropriate mocks for external dependencies
3. Include both positive and negative test cases
4. Update this README if adding new test categories
5. Ensure tests pass before submitting changes

## Test Coverage Goals

Target coverage metrics:

- **Overall Coverage**: 80%+ 
- **Critical Functions**: 95%+
- **Error Handling**: 90%+
- **Configuration Logic**: 85%+

## Support

For issues with tests:

1. Check the troubleshooting section above
2. Review test output for detailed error messages
3. Verify all dependencies are installed correctly
4. Check that mock configurations match actual usage

## File Structure

```
IAM/
├── Tests/
│   ├── AzureAutomation-DisableInactiveUsers.Tests.ps1
│   ├── Setup-AzureAutomation.Tests.ps1
│   ├── Setup-HybridWorker.Tests.ps1
│   └── Legacy-Scripts.Tests.ps1
├── TestResults/
│   ├── TestResults-*.xml
│   ├── CodeCoverage-*.xml
│   └── TestReport.html
├── Test-Runner.ps1
├── Install-TestDependencies.ps1
└── README-Testing.md
```

This comprehensive test suite ensures the reliability and maintainability of the IAM solution across all deployment scenarios.
