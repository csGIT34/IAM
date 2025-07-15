#Requires -Modules Pester

<#
.SYNOPSIS
    Test runner for SAP SuccessFactors Integration solution
.DESCRIPTION
    This script executes all Pester tests for the SAP SuccessFactors Integration solution
    and generates comprehensive test reports.
.PARAMETER TestPath
    Path to the test files directory
.PARAMETER OutputPath
    Path to store test results
.PARAMETER GenerateHtmlReport
    Generate HTML test report
.PARAMETER GenerateXmlReport
    Generate XML test report for CI/CD
.PARAMETER TestTag
    Specific test tags to run
.PARAMETER Detailed
    Show detailed test output
.PARAMETER PassThru
    Return test results object
.EXAMPLE
    .\Start-Tests.ps1
.EXAMPLE
    .\Start-Tests.ps1 -GenerateHtmlReport -GenerateXmlReport
.EXAMPLE
    .\Start-Tests.ps1 -TestTag "Unit" -Detailed
.NOTES
    Author: GitHub Copilot
    Version: 1.0
    Requires: Pester 5.0+
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$TestPath = ".\tests\",
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = ".\test-results\",
    
    [Parameter(Mandatory = $false)]
    [switch]$GenerateHtmlReport,
    
    [Parameter(Mandatory = $false)]
    [switch]$GenerateXmlReport,
    
    [Parameter(Mandatory = $false)]
    [string[]]$TestTag,
    
    [Parameter(Mandatory = $false)]
    [switch]$Detailed,
    
    [Parameter(Mandatory = $false)]
    [switch]$PassThru
)

# Initialize test environment
$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$null = New-Item -Path $OutputPath -ItemType Directory -Force -ErrorAction SilentlyContinue

Write-Host "=== SAP SuccessFactors Integration Test Suite ===" -ForegroundColor Cyan
Write-Host "Start Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Green
Write-Host "Test Path: $TestPath" -ForegroundColor Yellow
Write-Host "Output Path: $OutputPath" -ForegroundColor Yellow
Write-Host ""

# Check prerequisites
try {
    $pesterVersion = (Get-Module -ListAvailable Pester | Sort-Object Version -Descending | Select-Object -First 1).Version
    Write-Host "Pester Version: $pesterVersion" -ForegroundColor Green
    
    if ($pesterVersion -lt [Version]'5.0.0') {
        Write-Warning "Pester 5.0+ is recommended for best results"
    }
} catch {
    Write-Error "Pester module not found. Please install: Install-Module Pester -Force"
    exit 1
}

# Configure Pester
$pesterConfig = New-PesterConfiguration

# Set basic configuration
$pesterConfig.Run.Path = $TestPath
$pesterConfig.Run.PassThru = $PassThru

# Configure output
if ($Detailed) {
    $pesterConfig.Output.Verbosity = 'Detailed'
} else {
    $pesterConfig.Output.Verbosity = 'Normal'
}

# Configure test discovery
if ($TestTag) {
    $pesterConfig.Filter.Tag = $TestTag
}

# Configure test results
$pesterConfig.TestResult.Enabled = $true
$pesterConfig.TestResult.OutputFormat = 'NUnitXml'
$pesterConfig.TestResult.OutputPath = Join-Path $OutputPath "TestResults_$timestamp.xml"

# Configure code coverage (if available)
$pesterConfig.CodeCoverage.Enabled = $true
$pesterConfig.CodeCoverage.Path = @(
    ".\*.ps1",
    ".\config\*.json"
)
$pesterConfig.CodeCoverage.OutputFormat = 'CoverageGutters'
$pesterConfig.CodeCoverage.OutputPath = Join-Path $OutputPath "CodeCoverage_$timestamp.xml"

# Run tests
Write-Host "Running tests..." -ForegroundColor Cyan
$testResults = Invoke-Pester -Configuration $pesterConfig

# Generate reports
if ($GenerateHtmlReport) {
    Write-Host "Generating HTML report..." -ForegroundColor Cyan
    $htmlReportPath = Join-Path $OutputPath "TestReport_$timestamp.html"
    
    $htmlReport = @"
<!DOCTYPE html>
<html>
<head>
    <title>SAP SuccessFactors Integration Test Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .header { background-color: #0078d4; color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
        .summary { background-color: white; padding: 20px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; }
        .passed { color: #28a745; }
        .failed { color: #dc3545; }
        .skipped { color: #ffc107; }
        .test-details { background-color: white; padding: 20px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; }
        .test-item { margin: 10px 0; padding: 10px; border-left: 4px solid #e9ecef; }
        .test-passed { border-left-color: #28a745; }
        .test-failed { border-left-color: #dc3545; }
        .test-skipped { border-left-color: #ffc107; }
        .stats { display: flex; gap: 20px; margin: 20px 0; }
        .stat-box { background-color: #e9ecef; padding: 15px; border-radius: 5px; text-align: center; min-width: 100px; }
        .stat-value { font-size: 24px; font-weight: bold; }
        .stat-label { font-size: 12px; color: #666; }
    </style>
</head>
<body>
    <div class="header">
        <h1>SAP SuccessFactors Integration Test Report</h1>
        <p>Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
        <p>Test Suite: SAP SuccessFactors Integration</p>
    </div>
    
    <div class="summary">
        <h2>Test Summary</h2>
        <div class="stats">
            <div class="stat-box">
                <div class="stat-value passed">$($testResults.PassedCount)</div>
                <div class="stat-label">Passed</div>
            </div>
            <div class="stat-box">
                <div class="stat-value failed">$($testResults.FailedCount)</div>
                <div class="stat-label">Failed</div>
            </div>
            <div class="stat-box">
                <div class="stat-value skipped">$($testResults.SkippedCount)</div>
                <div class="stat-label">Skipped</div>
            </div>
            <div class="stat-box">
                <div class="stat-value">$($testResults.TotalCount)</div>
                <div class="stat-label">Total</div>
            </div>
        </div>
        <p><strong>Duration:</strong> $([math]::Round($testResults.Duration.TotalSeconds, 2)) seconds</p>
        <p><strong>Result:</strong> $(if ($testResults.Result -eq 'Passed') { '<span class="passed">PASSED</span>' } else { '<span class="failed">FAILED</span>' })</p>
    </div>
    
    <div class="test-details">
        <h2>Test Details</h2>
"@
    
    foreach ($test in $testResults.Tests) {
        $testClass = switch ($test.Result) {
            'Passed' { 'test-passed' }
            'Failed' { 'test-failed' }
            'Skipped' { 'test-skipped' }
            default { 'test-item' }
        }
        
        $resultClass = switch ($test.Result) {
            'Passed' { 'passed' }
            'Failed' { 'failed' }
            'Skipped' { 'skipped' }
            default { '' }
        }
        
        $htmlReport += @"
        <div class="test-item $testClass">
            <h4>$($test.Name)</h4>
            <p><strong>Result:</strong> <span class="$resultClass">$($test.Result)</span></p>
            <p><strong>Duration:</strong> $([math]::Round($test.Duration.TotalMilliseconds, 2)) ms</p>
            $(if ($test.ErrorRecord) { "<p><strong>Error:</strong> $($test.ErrorRecord.Exception.Message)</p>" })
        </div>
"@
    }
    
    $htmlReport += @"
    </div>
    
    <div class="test-details">
        <h2>Code Coverage</h2>
        <p>Code coverage analysis: $(if ($testResults.CodeCoverage) { 'Enabled' } else { 'Disabled' })</p>
        $(if ($testResults.CodeCoverage) {
            $coverage = $testResults.CodeCoverage
            "<p><strong>Coverage:</strong> $([math]::Round($coverage.CoveragePercent, 2))%</p>"
        })
    </div>
    
    <div class="test-details">
        <h2>Environment Information</h2>
        <p><strong>PowerShell Version:</strong> $($PSVersionTable.PSVersion)</p>
        <p><strong>OS:</strong> $($PSVersionTable.OS)</p>
        <p><strong>Pester Version:</strong> $pesterVersion</p>
        <p><strong>Test Path:</strong> $TestPath</p>
        <p><strong>Output Path:</strong> $OutputPath</p>
    </div>
</body>
</html>
"@
    
    $htmlReport | Out-File -FilePath $htmlReportPath -Encoding UTF8
    Write-Host "HTML report saved: $htmlReportPath" -ForegroundColor Green
}

if ($GenerateXmlReport) {
    Write-Host "XML report saved: $($pesterConfig.TestResult.OutputPath)" -ForegroundColor Green
}

# Display results summary
Write-Host ""
Write-Host "=== Test Results Summary ===" -ForegroundColor Cyan
Write-Host "Total Tests: $($testResults.TotalCount)" -ForegroundColor White
Write-Host "Passed: $($testResults.PassedCount)" -ForegroundColor Green
Write-Host "Failed: $($testResults.FailedCount)" -ForegroundColor Red
Write-Host "Skipped: $($testResults.SkippedCount)" -ForegroundColor Yellow
Write-Host "Duration: $([math]::Round($testResults.Duration.TotalSeconds, 2)) seconds" -ForegroundColor White
Write-Host "Result: $($testResults.Result)" -ForegroundColor $(if ($testResults.Result -eq 'Passed') { 'Green' } else { 'Red' })

# Show failed tests if any
if ($testResults.FailedCount -gt 0) {
    Write-Host ""
    Write-Host "=== Failed Tests ===" -ForegroundColor Red
    foreach ($failedTest in $testResults.Tests | Where-Object { $_.Result -eq 'Failed' }) {
        Write-Host "❌ $($failedTest.Name)" -ForegroundColor Red
        if ($failedTest.ErrorRecord) {
            Write-Host "   Error: $($failedTest.ErrorRecord.Exception.Message)" -ForegroundColor Red
        }
    }
}

Write-Host ""
Write-Host "End Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Green
Write-Host "Test execution completed." -ForegroundColor Cyan

# Return test results if PassThru is specified
if ($PassThru) {
    return $testResults
}

# Exit with appropriate code
exit $(if ($testResults.Result -eq 'Passed') { 0 } else { 1 })
