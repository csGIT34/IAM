# Pester Test Runner and Configuration

# Test configuration
$TestConfig = @{
    TestPath = Join-Path $PSScriptRoot "Tests"
    OutputPath = Join-Path $PSScriptRoot "TestResults"
    CoverageEnabled = $true
    ParallelTests = $false
    MinimumCoverage = 80
}

# Ensure output directory exists
if (-not (Test-Path $TestConfig.OutputPath)) {
    New-Item -ItemType Directory -Path $TestConfig.OutputPath -Force | Out-Null
}

# Pester configuration
$PesterConfig = @{
    Run = @{
        Path = $TestConfig.TestPath
        Exit = $true
        PassThru = $true
    }
    Output = @{
        Verbosity = 'Detailed'
        StackTraceVerbosity = 'Filtered'
        CIFormat = 'Auto'
    }
    TestResult = @{
        Enabled = $true
        OutputFormat = 'NUnitXml'
        OutputPath = Join-Path $TestConfig.OutputPath "TestResults.xml"
    }
    CodeCoverage = @{
        Enabled = $TestConfig.CoverageEnabled
        Path = @(
            Join-Path $PSScriptRoot "AzureAutomation-DisableInactiveUsers.ps1"
            Join-Path $PSScriptRoot "Setup-AzureAutomation.ps1"
            Join-Path $PSScriptRoot "Setup-HybridWorker.ps1"
            Join-Path $PSScriptRoot "Disable-InactiveUsers.ps1"
            Join-Path $PSScriptRoot "Config-DisableInactiveUsers.ps1"
        )
        OutputFormat = 'JaCoCo'
        OutputPath = Join-Path $TestConfig.OutputPath "CodeCoverage.xml"
    }
}

# Function to run all tests
function Invoke-AllTests {
    param(
        [switch]$Coverage,
        [switch]$Parallel,
        [string]$TestName = "*",
        [string]$OutputPath = $TestConfig.OutputPath
    )
    
    Write-Host "Starting IAM Solution Test Suite..." -ForegroundColor Green
    Write-Host "Test Path: $($TestConfig.TestPath)" -ForegroundColor Cyan
    Write-Host "Output Path: $OutputPath" -ForegroundColor Cyan
    
    # Update configuration based on parameters
    $config = $PesterConfig.Clone()
    $config.CodeCoverage.Enabled = $Coverage.IsPresent
    $config.Run.Path = Join-Path $TestConfig.TestPath "*$TestName*.Tests.ps1"
    $config.TestResult.OutputPath = Join-Path $OutputPath "TestResults-$(Get-Date -Format 'yyyyMMdd-HHmmss').xml"
    $config.CodeCoverage.OutputPath = Join-Path $OutputPath "CodeCoverage-$(Get-Date -Format 'yyyyMMdd-HHmmss').xml"
    
    # Run tests
    $result = Invoke-Pester -Configuration $config
    
    # Display results
    Write-Host "`n=================== TEST RESULTS ===================" -ForegroundColor Yellow
    Write-Host "Tests Run: $($result.TotalCount)" -ForegroundColor White
    Write-Host "Passed: $($result.PassedCount)" -ForegroundColor Green
    Write-Host "Failed: $($result.FailedCount)" -ForegroundColor Red
    Write-Host "Skipped: $($result.SkippedCount)" -ForegroundColor Yellow
    Write-Host "Duration: $($result.Duration)" -ForegroundColor White
    
    if ($Coverage.IsPresent -and $result.CodeCoverage) {
        $coveragePercent = [Math]::Round(($result.CodeCoverage.CoveragePercent), 2)
        Write-Host "Code Coverage: $coveragePercent%" -ForegroundColor $(if ($coveragePercent -ge $TestConfig.MinimumCoverage) { "Green" } else { "Red" })
    }
    
    Write-Host "=====================================================" -ForegroundColor Yellow
    
    if ($result.FailedCount -gt 0) {
        Write-Host "`nFailed Tests:" -ForegroundColor Red
        foreach ($test in $result.Failed) {
            Write-Host "  - $($test.FullName)" -ForegroundColor Red
            Write-Host "    Error: $($test.ErrorRecord.Exception.Message)" -ForegroundColor Red
        }
    }
    
    return $result
}

# Function to run specific test file
function Invoke-TestFile {
    param(
        [Parameter(Mandatory)]
        [string]$TestFile,
        [switch]$Coverage
    )
    
    $testPath = Join-Path $TestConfig.TestPath "$TestFile.Tests.ps1"
    
    if (-not (Test-Path $testPath)) {
        Write-Error "Test file not found: $testPath"
        return
    }
    
    Write-Host "Running test file: $TestFile" -ForegroundColor Green
    
    $config = $PesterConfig.Clone()
    $config.Run.Path = $testPath
    $config.CodeCoverage.Enabled = $Coverage.IsPresent
    $config.TestResult.OutputPath = Join-Path $TestConfig.OutputPath "TestResults-$TestFile-$(Get-Date -Format 'yyyyMMdd-HHmmss').xml"
    
    return Invoke-Pester -Configuration $config
}

# Function to run tests with specific tags
function Invoke-TestsByTag {
    param(
        [Parameter(Mandatory)]
        [string[]]$Tags,
        [switch]$Coverage
    )
    
    Write-Host "Running tests with tags: $($Tags -join ', ')" -ForegroundColor Green
    
    $config = $PesterConfig.Clone()
    $config.Filter = @{ Tag = $Tags }
    $config.CodeCoverage.Enabled = $Coverage.IsPresent
    $config.TestResult.OutputPath = Join-Path $TestConfig.OutputPath "TestResults-Tagged-$(Get-Date -Format 'yyyyMMdd-HHmmss').xml"
    
    return Invoke-Pester -Configuration $config
}

# Function to generate test report
function New-TestReport {
    param(
        [string]$TestResultsPath = $TestConfig.OutputPath,
        [string]$ReportPath = (Join-Path $TestConfig.OutputPath "TestReport.html")
    )
    
    $testFiles = Get-ChildItem -Path $TestResultsPath -Filter "TestResults-*.xml" | Sort-Object LastWriteTime -Descending
    
    if ($testFiles.Count -eq 0) {
        Write-Warning "No test results found in $TestResultsPath"
        return
    }
    
    $latestResult = $testFiles[0]
    Write-Host "Generating test report from: $($latestResult.Name)" -ForegroundColor Green
    
    [xml]$testXml = Get-Content $latestResult.FullName
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>IAM Solution Test Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #f0f0f0; padding: 20px; border-radius: 5px; }
        .summary { display: flex; gap: 20px; margin: 20px 0; }
        .metric { background-color: #e9ecef; padding: 15px; border-radius: 5px; text-align: center; }
        .metric.passed { background-color: #d4edda; color: #155724; }
        .metric.failed { background-color: #f8d7da; color: #721c24; }
        .metric.skipped { background-color: #fff3cd; color: #856404; }
        .test-suite { margin: 20px 0; border: 1px solid #ddd; border-radius: 5px; }
        .test-suite-header { background-color: #f8f9fa; padding: 15px; font-weight: bold; }
        .test-case { padding: 10px 15px; border-bottom: 1px solid #eee; }
        .test-case:last-child { border-bottom: none; }
        .test-case.passed { background-color: #f8fff8; }
        .test-case.failed { background-color: #fff8f8; }
        .test-case.skipped { background-color: #fffef8; }
        .error-message { color: #dc3545; font-style: italic; margin-top: 5px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>IAM Solution Test Report</h1>
        <p>Generated: $(Get-Date)</p>
        <p>Test File: $($latestResult.Name)</p>
    </div>
    
    <div class="summary">
        <div class="metric">
            <h3>Total Tests</h3>
            <p>$($testXml.'test-results'.total)</p>
        </div>
        <div class="metric passed">
            <h3>Passed</h3>
            <p>$($testXml.'test-results'.passed)</p>
        </div>
        <div class="metric failed">
            <h3>Failed</h3>
            <p>$($testXml.'test-results'.failures)</p>
        </div>
        <div class="metric skipped">
            <h3>Skipped</h3>
            <p>$($testXml.'test-results'.skipped)</p>
        </div>
    </div>
    
    <h2>Test Results</h2>
"@
    
    foreach ($testSuite in $testXml.'test-results'.'test-suite') {
        $html += @"
    <div class="test-suite">
        <div class="test-suite-header">$($testSuite.name)</div>
"@
        
        foreach ($testCase in $testSuite.'test-case') {
            $status = if ($testCase.success -eq 'True') { 'passed' } elseif ($testCase.executed -eq 'False') { 'skipped' } else { 'failed' }
            $html += @"
        <div class="test-case $status">
            <strong>$($testCase.name)</strong>
            <span style="float: right;">$($testCase.time)s</span>
"@
            
            if ($testCase.failure) {
                $html += @"
            <div class="error-message">$($testCase.failure.message)</div>
"@
            }
            
            $html += "</div>"
        }
        
        $html += "</div>"
    }
    
    $html += @"
</body>
</html>
"@
    
    $html | Out-File -FilePath $ReportPath -Encoding UTF8
    Write-Host "Test report generated: $ReportPath" -ForegroundColor Green
    
    # Try to open the report in default browser
    try {
        Start-Process $ReportPath
    } catch {
        Write-Warning "Could not open report in browser. Please open manually: $ReportPath"
    }
}

# Function to clean test results
function Clear-TestResults {
    param(
        [int]$KeepLatest = 5
    )
    
    Write-Host "Cleaning test results..." -ForegroundColor Yellow
    
    $testFiles = Get-ChildItem -Path $TestConfig.OutputPath -Filter "TestResults-*.xml" | Sort-Object LastWriteTime -Descending
    $coverageFiles = Get-ChildItem -Path $TestConfig.OutputPath -Filter "CodeCoverage-*.xml" | Sort-Object LastWriteTime -Descending
    
    if ($testFiles.Count -gt $KeepLatest) {
        $toDelete = $testFiles | Select-Object -Skip $KeepLatest
        $toDelete | Remove-Item -Force
        Write-Host "Deleted $($toDelete.Count) old test result files" -ForegroundColor Green
    }
    
    if ($coverageFiles.Count -gt $KeepLatest) {
        $toDelete = $coverageFiles | Select-Object -Skip $KeepLatest
        $toDelete | Remove-Item -Force
        Write-Host "Deleted $($toDelete.Count) old coverage files" -ForegroundColor Green
    }
}

# Export functions for use in other scripts
Export-ModuleMember -Function Invoke-AllTests, Invoke-TestFile, Invoke-TestsByTag, New-TestReport, Clear-TestResults

# If script is run directly, run all tests
if ($MyInvocation.InvocationName -eq $MyInvocation.MyCommand.Name) {
    Write-Host "IAM Solution Test Runner" -ForegroundColor Green
    Write-Host "Available commands:" -ForegroundColor Yellow
    Write-Host "  Invoke-AllTests [-Coverage] [-Parallel] [-TestName <pattern>]" -ForegroundColor Cyan
    Write-Host "  Invoke-TestFile -TestFile <name> [-Coverage]" -ForegroundColor Cyan
    Write-Host "  Invoke-TestsByTag -Tags <tag1,tag2> [-Coverage]" -ForegroundColor Cyan
    Write-Host "  New-TestReport [-TestResultsPath <path>] [-ReportPath <path>]" -ForegroundColor Cyan
    Write-Host "  Clear-TestResults [-KeepLatest <number>]" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Example usage:" -ForegroundColor Yellow
    Write-Host "  .\Test-Runner.ps1; Invoke-AllTests -Coverage" -ForegroundColor Cyan
    Write-Host "  .\Test-Runner.ps1; Invoke-TestFile -TestFile 'AzureAutomation-DisableInactiveUsers'" -ForegroundColor Cyan
    Write-Host "  .\Test-Runner.ps1; New-TestReport" -ForegroundColor Cyan
}
