# Test Runner for Role Assignment Monitoring Solution
# This script runs all Pester tests for the Role Assignment Monitoring solution

<#
.SYNOPSIS
    Runs all Pester tests for the Role Assignment Monitoring solution.

.DESCRIPTION
    This script discovers and runs all Pester tests for the Role Assignment Monitoring solution.
    It generates detailed test reports and provides coverage information.

.PARAMETER TestPath
    Path to the directory containing the tests (defaults to current directory)

.PARAMETER OutputPath
    Path to save test results (defaults to TestResults directory)

.PARAMETER CodeCoverageEnabled
    Whether to enable code coverage analysis

.PARAMETER PassThru
    Returns the test results object

.EXAMPLE
    .\Test-RoleMonitoring.ps1 -CodeCoverageEnabled -OutputPath "C:\Reports"
#>

param(
    [string]$TestPath = $PSScriptRoot,
    [string]$OutputPath = (Join-Path $PSScriptRoot "TestResults"),
    [switch]$CodeCoverageEnabled,
    [switch]$PassThru
)

# Ensure output directory exists
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

Write-Host "=== Role Assignment Monitoring Test Runner ===" -ForegroundColor Green
Write-Host "Test Path: $TestPath" -ForegroundColor Cyan
Write-Host "Output Path: $OutputPath" -ForegroundColor Cyan
Write-Host "Code Coverage: $CodeCoverageEnabled" -ForegroundColor Cyan

# Check if Pester is available
try {
    $pesterModule = Get-Module -Name Pester -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1
    if (-not $pesterModule) {
        throw "Pester module not found"
    }
    
    if ($pesterModule.Version -lt [version]"5.0.0") {
        throw "Pester 5.0.0 or higher is required. Current version: $($pesterModule.Version)"
    }
    
    Write-Host "✓ Pester version $($pesterModule.Version) found" -ForegroundColor Green
    Import-Module Pester -Force
} catch {
    Write-Error "Pester setup failed: $($_.Exception.Message)"
    Write-Host "To install Pester 5.x, run: Install-Module Pester -Force -SkipPublisherCheck" -ForegroundColor Yellow
    exit 1
}

# Discover test files
Write-Host "Discovering test files..." -ForegroundColor Yellow
$testFiles = Get-ChildItem -Path $TestPath -Filter "*.Tests.ps1" -Recurse

if ($testFiles.Count -eq 0) {
    Write-Warning "No test files found in $TestPath"
    exit 0
}

Write-Host "Found $($testFiles.Count) test files:" -ForegroundColor Cyan
foreach ($file in $testFiles) {
    Write-Host "  - $($file.Name)" -ForegroundColor Cyan
}

# Prepare test configuration
$testConfig = @{
    Run = @{
        Path = $testFiles.FullName
        PassThru = $true
    }
    Output = @{
        Verbosity = 'Detailed'
    }
    TestResult = @{
        Enabled = $true
        OutputPath = Join-Path $OutputPath "TestResults.xml"
        OutputFormat = 'NUnitXml'
    }
}

# Add code coverage if enabled
if ($CodeCoverageEnabled) {
    $sourceFiles = Get-ChildItem -Path $TestPath -Filter "*.ps1" -Recurse | Where-Object { $_.Name -notlike "*.Tests.ps1" -and $_.Name -notlike "Test-*" }
    
    if ($sourceFiles.Count -gt 0) {
        $testConfig.CodeCoverage = @{
            Enabled = $true
            Path = $sourceFiles.FullName
            OutputPath = Join-Path $OutputPath "CodeCoverage.xml"
            OutputFormat = 'JaCoCo'
        }
        
        Write-Host "Code coverage enabled for $($sourceFiles.Count) source files" -ForegroundColor Green
    } else {
        Write-Warning "No source files found for code coverage"
    }
}

# Run tests
Write-Host "`nRunning tests..." -ForegroundColor Yellow
$testResults = Invoke-Pester -Configuration $testConfig

# Generate summary
Write-Host "`n=== Test Summary ===" -ForegroundColor Green
Write-Host "Total Tests: $($testResults.TotalCount)" -ForegroundColor Cyan
Write-Host "Passed: $($testResults.PassedCount)" -ForegroundColor Green
Write-Host "Failed: $($testResults.FailedCount)" -ForegroundColor Red
Write-Host "Skipped: $($testResults.SkippedCount)" -ForegroundColor Yellow
Write-Host "Duration: $($testResults.Duration)" -ForegroundColor Cyan

if ($testResults.FailedCount -gt 0) {
    Write-Host "`nFailed Tests:" -ForegroundColor Red
    foreach ($failedTest in $testResults.Failed) {
        Write-Host "  - $($failedTest.FullName)" -ForegroundColor Red
        Write-Host "    $($failedTest.ErrorRecord.Exception.Message)" -ForegroundColor Red
    }
}

# Show code coverage summary
if ($CodeCoverageEnabled -and $testResults.CodeCoverage) {
    Write-Host "`n=== Code Coverage Summary ===" -ForegroundColor Green
    $coverage = $testResults.CodeCoverage
    $coveragePercent = [math]::Round(($coverage.CommandsExecuted / $coverage.CommandsAnalyzed) * 100, 2)
    
    Write-Host "Commands Analyzed: $($coverage.CommandsAnalyzed)" -ForegroundColor Cyan
    Write-Host "Commands Executed: $($coverage.CommandsExecuted)" -ForegroundColor Cyan
    Write-Host "Coverage Percentage: $coveragePercent%" -ForegroundColor Cyan
    
    if ($coveragePercent -lt 70) {
        Write-Host "Warning: Code coverage is below 70%" -ForegroundColor Yellow
    } elseif ($coveragePercent -ge 80) {
        Write-Host "Excellent: Code coverage is above 80%" -ForegroundColor Green
    }
}

# Generate HTML report
Write-Host "`nGenerating HTML report..." -ForegroundColor Yellow
$htmlReportPath = Join-Path $OutputPath "TestReport.html"

$htmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>Role Assignment Monitoring - Test Results</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #f0f0f0; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
        .summary { background-color: #e8f5e8; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .failed { background-color: #ffe8e8; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .coverage { background-color: #e8f0ff; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .test-file { margin-bottom: 20px; border: 1px solid #ddd; border-radius: 5px; }
        .test-file-header { background-color: #f5f5f5; padding: 10px; font-weight: bold; }
        .test-case { padding: 10px; border-bottom: 1px solid #eee; }
        .test-case:last-child { border-bottom: none; }
        .passed { color: green; }
        .failed { color: red; }
        .skipped { color: orange; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Role Assignment Monitoring - Test Results</h1>
        <p>Generated on: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
    </div>
    
    <div class="summary">
        <h2>Test Summary</h2>
        <p><strong>Total Tests:</strong> $($testResults.TotalCount)</p>
        <p><strong>Passed:</strong> <span class="passed">$($testResults.PassedCount)</span></p>
        <p><strong>Failed:</strong> <span class="failed">$($testResults.FailedCount)</span></p>
        <p><strong>Skipped:</strong> <span class="skipped">$($testResults.SkippedCount)</span></p>
        <p><strong>Duration:</strong> $($testResults.Duration)</p>
    </div>
"@

if ($CodeCoverageEnabled -and $testResults.CodeCoverage) {
    $coverage = $testResults.CodeCoverage
    $coveragePercent = [math]::Round(($coverage.CommandsExecuted / $coverage.CommandsAnalyzed) * 100, 2)
    
    $htmlContent += @"
    <div class="coverage">
        <h2>Code Coverage</h2>
        <p><strong>Commands Analyzed:</strong> $($coverage.CommandsAnalyzed)</p>
        <p><strong>Commands Executed:</strong> $($coverage.CommandsExecuted)</p>
        <p><strong>Coverage Percentage:</strong> $coveragePercent%</p>
    </div>
"@
}

if ($testResults.FailedCount -gt 0) {
    $htmlContent += @"
    <div class="failed">
        <h2>Failed Tests</h2>
        <ul>
"@
    
    foreach ($failedTest in $testResults.Failed) {
        $htmlContent += "<li><strong>$($failedTest.FullName)</strong><br/>$($failedTest.ErrorRecord.Exception.Message)</li>"
    }
    
    $htmlContent += @"
        </ul>
    </div>
"@
}

$htmlContent += @"
    <div class="test-files">
        <h2>Test Details</h2>
"@

# Group tests by file
$testsByFile = $testResults.Tests | Group-Object -Property { $_.ScriptBlock.File }

foreach ($fileGroup in $testsByFile) {
    $fileName = Split-Path $fileGroup.Name -Leaf
    $htmlContent += @"
        <div class="test-file">
            <div class="test-file-header">$fileName</div>
"@
    
    foreach ($test in $fileGroup.Group) {
        $statusClass = switch ($test.Result) {
            'Passed' { 'passed' }
            'Failed' { 'failed' }
            'Skipped' { 'skipped' }
            default { '' }
        }
        
        $htmlContent += @"
            <div class="test-case">
                <span class="$statusClass">[$($test.Result)]</span> $($test.Name)
"@
        
        if ($test.Result -eq 'Failed') {
            $htmlContent += "<br/><small>$($test.ErrorRecord.Exception.Message)</small>"
        }
        
        $htmlContent += "</div>"
    }
    
    $htmlContent += "</div>"
}

$htmlContent += @"
    </div>
</body>
</html>
"@

$htmlContent | Out-File -FilePath $htmlReportPath -Encoding UTF8
Write-Host "✓ HTML report generated: $htmlReportPath" -ForegroundColor Green

# Show file locations
Write-Host "`nTest artifacts generated:" -ForegroundColor Yellow
Write-Host "  - XML Results: $(Join-Path $OutputPath "TestResults.xml")" -ForegroundColor Cyan
Write-Host "  - HTML Report: $htmlReportPath" -ForegroundColor Cyan

if ($CodeCoverageEnabled) {
    Write-Host "  - Code Coverage: $(Join-Path $OutputPath "CodeCoverage.xml")" -ForegroundColor Cyan
}

# Return results if requested
if ($PassThru) {
    return $testResults
}

# Exit with appropriate code
if ($testResults.FailedCount -gt 0) {
    Write-Host "`nTests failed. Exiting with code 1." -ForegroundColor Red
    exit 1
} else {
    Write-Host "`nAll tests passed!" -ForegroundColor Green
    exit 0
}
