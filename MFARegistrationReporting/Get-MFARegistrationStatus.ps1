#Requires -Modules Microsoft.Graph.Reports, Microsoft.Graph.Users

<#
.SYNOPSIS
    Generates comprehensive MFA registration status reports for Entra ID users
.DESCRIPTION
    This script provides detailed analysis of MFA registration status across your organization,
    including authentication methods, compliance status, and security recommendations.
.PARAMETER OutputFormat
    Output format for the report (Console, CSV, HTML, JSON)
.PARAMETER ExportPath
    Path to export the report (required for CSV, HTML, JSON formats)
.PARAMETER IncludeDisabledUsers
    Include disabled users in the report
.PARAMETER FilterByDepartment
    Filter users by specific department
.PARAMETER FilterByLicenseStatus
    Filter users by license status (Licensed, Unlicensed, All)
.PARAMETER IncludeAuthMethods
    Include detailed authentication methods in the report
.PARAMETER GenerateRecommendations
    Generate security recommendations based on MFA status
.PARAMETER SendEmailReport
    Send the report via email
.PARAMETER EmailRecipients
    Email recipients for the report
.PARAMETER ScheduleReport
    Schedule the report to run automatically
.PARAMETER TenantId
    Tenant ID for authentication (optional)
.EXAMPLE
    .\Get-MFARegistrationStatus.ps1 -OutputFormat HTML -ExportPath "C:\Reports\MFA-Status.html" -IncludeAuthMethods
.EXAMPLE
    .\Get-MFARegistrationStatus.ps1 -OutputFormat CSV -ExportPath ".\mfa-report.csv" -FilterByDepartment "IT" -GenerateRecommendations
.EXAMPLE
    .\Get-MFARegistrationStatus.ps1 -OutputFormat JSON -ExportPath ".\mfa-status.json" -SendEmailReport -EmailRecipients @("admin@company.com", "security@company.com")
.NOTES
    Author: GitHub Copilot
    Version: 1.0
    Requires: Microsoft.Graph.Reports, Microsoft.Graph.Users modules
    Permissions: Reports.Read.All, User.Read.All, UserAuthenticationMethod.Read.All
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet('Console', 'CSV', 'HTML', 'JSON')]
    [string]$OutputFormat = 'Console',
    
    [Parameter(Mandatory = $false)]
    [string]$ExportPath,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeDisabledUsers,
    
    [Parameter(Mandatory = $false)]
    [string]$FilterByDepartment,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet('Licensed', 'Unlicensed', 'All')]
    [string]$FilterByLicenseStatus = 'All',
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeAuthMethods,
    
    [Parameter(Mandatory = $false)]
    [switch]$GenerateRecommendations,
    
    [Parameter(Mandatory = $false)]
    [switch]$SendEmailReport,
    
    [Parameter(Mandatory = $false)]
    [string[]]$EmailRecipients,
    
    [Parameter(Mandatory = $false)]
    [switch]$ScheduleReport,
    
    [Parameter(Mandatory = $false)]
    [string]$TenantId
)

# Initialize logging
$LogPath = ".\logs\MFARegistrationReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$null = New-Item -Path (Split-Path $LogPath -Parent) -ItemType Directory -Force -ErrorAction SilentlyContinue

function Write-Log {
    param([string]$Message, [string]$Level = 'Info')
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logEntry = "[$timestamp] [$Level] $Message"
    Add-Content -Path $LogPath -Value $logEntry
    
    switch ($Level) {
        'Error' { Write-Error $Message }
        'Warning' { Write-Warning $Message }
        'Info' { Write-Host $Message -ForegroundColor Green }
        'Debug' { Write-Debug $Message }
    }
}

function Connect-ToMicrosoftGraph {
    param([string]$TenantId)
    
    try {
        Write-Log "Connecting to Microsoft Graph..."
        
        $requiredScopes = @(
            'Reports.Read.All',
            'User.Read.All',
            'UserAuthenticationMethod.Read.All'
        )
        
        $connectParams = @{
            Scopes = $requiredScopes
            NoWelcome = $true
        }
        
        if ($TenantId) {
            $connectParams.TenantId = $TenantId
        }
        
        Connect-MgGraph @connectParams
        Write-Log "Successfully connected to Microsoft Graph"
        
        # Get current context
        $context = Get-MgContext
        Write-Log "Connected to tenant: $($context.TenantId)"
        Write-Log "Using account: $($context.Account)"
        
    } catch {
        Write-Log "Failed to connect to Microsoft Graph: $($_.Exception.Message)" -Level Error
        throw
    }
}

function Get-MFARegistrationReport {
    try {
        Write-Log "Retrieving MFA registration status from Microsoft Graph..."
        
        # Get the authentication methods registration campaign report
        $report = Get-MgReportAuthenticationMethodUserRegistrationDetail -All
        
        Write-Log "Retrieved $($report.Count) user records"
        return $report
        
    } catch {
        Write-Log "Failed to retrieve MFA registration report: $($_.Exception.Message)" -Level Error
        throw
    }
}

function Get-UserDetails {
    param([string[]]$UserIds)
    
    try {
        Write-Log "Retrieving detailed user information..."
        
        $users = @{}
        $batchSize = 100
        
        for ($i = 0; $i -lt $UserIds.Count; $i += $batchSize) {
            $batch = $UserIds[$i..([Math]::Min($i + $batchSize - 1, $UserIds.Count - 1))]
            
            foreach ($userId in $batch) {
                try {
                    $user = Get-MgUser -UserId $userId -Property @(
                        'id', 'userPrincipalName', 'displayName', 'givenName', 'surname',
                        'department', 'jobTitle', 'companyName', 'accountEnabled',
                        'createdDateTime', 'lastSignInDateTime', 'mail', 'mobilePhone',
                        'assignedLicenses', 'usageLocation', 'userType'
                    ) -ErrorAction SilentlyContinue
                    
                    if ($user) {
                        $users[$userId] = $user
                    }
                } catch {
                    Write-Log "Failed to retrieve user details for $userId: $($_.Exception.Message)" -Level Warning
                }
            }
            
            Write-Progress -Activity "Retrieving user details" -Status "Processed $($i + $batch.Count) of $($UserIds.Count) users" -PercentComplete (($i + $batch.Count) / $UserIds.Count * 100)
        }
        
        Write-Progress -Activity "Retrieving user details" -Completed
        Write-Log "Retrieved details for $($users.Count) users"
        
        return $users
        
    } catch {
        Write-Log "Failed to retrieve user details: $($_.Exception.Message)" -Level Error
        throw
    }
}

function Get-UserAuthenticationMethods {
    param([string[]]$UserIds)
    
    if (-not $IncludeAuthMethods) {
        return @{}
    }
    
    try {
        Write-Log "Retrieving authentication methods for users..."
        
        $authMethods = @{}
        $batchSize = 50
        
        for ($i = 0; $i -lt $UserIds.Count; $i += $batchSize) {
            $batch = $UserIds[$i..([Math]::Min($i + $batchSize - 1, $UserIds.Count - 1))]
            
            foreach ($userId in $batch) {
                try {
                    $methods = Get-MgUserAuthenticationMethod -UserId $userId -ErrorAction SilentlyContinue
                    if ($methods) {
                        $authMethods[$userId] = $methods
                    }
                } catch {
                    Write-Log "Failed to retrieve auth methods for $userId: $($_.Exception.Message)" -Level Warning
                }
            }
            
            Write-Progress -Activity "Retrieving authentication methods" -Status "Processed $($i + $batch.Count) of $($UserIds.Count) users" -PercentComplete (($i + $batch.Count) / $UserIds.Count * 100)
        }
        
        Write-Progress -Activity "Retrieving authentication methods" -Completed
        Write-Log "Retrieved authentication methods for $($authMethods.Count) users"
        
        return $authMethods
        
    } catch {
        Write-Log "Failed to retrieve authentication methods: $($_.Exception.Message)" -Level Error
        throw
    }
}

function Process-MFAData {
    param(
        [object[]]$MFAReport,
        [hashtable]$UserDetails,
        [hashtable]$AuthMethods
    )
    
    try {
        Write-Log "Processing MFA registration data..."
        
        $processedData = @()
        $stats = @{
            TotalUsers = 0
            MFACapable = 0
            MFAEnabled = 0
            MFARegistered = 0
            PasswordOnly = 0
            DisabledUsers = 0
            LicensedUsers = 0
            UnlicensedUsers = 0
            Departments = @{}
            AuthMethods = @{}
        }
        
        foreach ($record in $MFAReport) {
            $user = $UserDetails[$record.Id]
            
            if (-not $user) {
                continue
            }
            
            # Apply filters
            if (-not $IncludeDisabledUsers -and -not $user.AccountEnabled) {
                continue
            }
            
            if ($FilterByDepartment -and $user.Department -ne $FilterByDepartment) {
                continue
            }
            
            $isLicensed = $user.AssignedLicenses -and $user.AssignedLicenses.Count -gt 0
            
            if ($FilterByLicenseStatus -eq 'Licensed' -and -not $isLicensed) {
                continue
            }
            
            if ($FilterByLicenseStatus -eq 'Unlicensed' -and $isLicensed) {
                continue
            }
            
            # Process authentication methods
            $userAuthMethods = @()
            if ($AuthMethods.ContainsKey($record.Id)) {
                $userAuthMethods = $AuthMethods[$record.Id] | ForEach-Object {
                    $_.AdditionalProperties['@odata.type'] -replace '#microsoft.graph.', ''
                }
            }
            
            # Calculate MFA status
            $mfaStatus = 'Unknown'
            if ($record.IsMfaCapable) {
                if ($record.IsMfaRegistered) {
                    $mfaStatus = 'Registered'
                } else {
                    $mfaStatus = 'Capable but Not Registered'
                }
            } else {
                $mfaStatus = 'Not Capable'
            }
            
            # Build processed record
            $processedRecord = [PSCustomObject]@{
                UserId = $record.Id
                UserPrincipalName = $user.UserPrincipalName
                DisplayName = $user.DisplayName
                GivenName = $user.GivenName
                Surname = $user.Surname
                Department = $user.Department
                JobTitle = $user.JobTitle
                CompanyName = $user.CompanyName
                AccountEnabled = $user.AccountEnabled
                IsLicensed = $isLicensed
                UserType = $user.UserType
                CreatedDateTime = $user.CreatedDateTime
                LastSignInDateTime = $user.LastSignInDateTime
                Mail = $user.Mail
                MobilePhone = $user.MobilePhone
                UsageLocation = $user.UsageLocation
                IsMfaCapable = $record.IsMfaCapable
                IsMfaRegistered = $record.IsMfaRegistered
                MfaStatus = $mfaStatus
                IsPasswordlessCapable = $record.IsPasswordlessCapable
                MethodsRegistered = $record.MethodsRegistered -join ', '
                DefaultMfaMethod = $record.DefaultMfaMethod
                AuthenticationMethods = $userAuthMethods -join ', '
                LastUpdatedDateTime = $record.LastUpdatedDateTime
                RiskLevel = Get-UserRiskLevel -User $user -MfaStatus $mfaStatus
                Recommendations = Get-UserRecommendations -User $user -MfaStatus $mfaStatus -AuthMethods $userAuthMethods
            }
            
            $processedData += $processedRecord
            
            # Update statistics
            $stats.TotalUsers++
            if ($record.IsMfaCapable) { $stats.MFACapable++ }
            if ($record.IsMfaRegistered) { $stats.MFARegistered++ }
            if (-not $user.AccountEnabled) { $stats.DisabledUsers++ }
            if ($isLicensed) { $stats.LicensedUsers++ } else { $stats.UnlicensedUsers++ }
            
            # Department statistics
            $dept = $user.Department -or 'Unknown'
            if (-not $stats.Departments.ContainsKey($dept)) {
                $stats.Departments[$dept] = 0
            }
            $stats.Departments[$dept]++
            
            # Authentication method statistics
            foreach ($method in $userAuthMethods) {
                if (-not $stats.AuthMethods.ContainsKey($method)) {
                    $stats.AuthMethods[$method] = 0
                }
                $stats.AuthMethods[$method]++
            }
        }
        
        Write-Log "Processed $($processedData.Count) user records"
        
        return @{
            Data = $processedData
            Statistics = $stats
        }
        
    } catch {
        Write-Log "Failed to process MFA data: $($_.Exception.Message)" -Level Error
        throw
    }
}

function Get-UserRiskLevel {
    param([object]$User, [string]$MfaStatus)
    
    $riskScore = 0
    
    # MFA status risk
    switch ($MfaStatus) {
        'Not Capable' { $riskScore += 40 }
        'Capable but Not Registered' { $riskScore += 30 }
        'Registered' { $riskScore += 0 }
        default { $riskScore += 20 }
    }
    
    # Account status risk
    if ($User.AccountEnabled) {
        $riskScore += 0
    } else {
        $riskScore -= 10  # Disabled accounts are less risky
    }
    
    # License status risk
    $isLicensed = $User.AssignedLicenses -and $User.AssignedLicenses.Count -gt 0
    if (-not $isLicensed) {
        $riskScore += 15
    }
    
    # Last sign-in risk
    if ($User.LastSignInDateTime) {
        $daysSinceLastSignIn = (Get-Date) - $User.LastSignInDateTime
        if ($daysSinceLastSignIn.Days -gt 90) {
            $riskScore += 10
        } elseif ($daysSinceLastSignIn.Days -gt 30) {
            $riskScore += 5
        }
    } else {
        $riskScore += 20  # Never signed in
    }
    
    # User type risk
    if ($User.UserType -eq 'Guest') {
        $riskScore += 10
    }
    
    # Admin roles risk (would need additional API call)
    # For now, assume based on job title
    if ($User.JobTitle -match 'admin|manager|director|executive') {
        $riskScore += 15
    }
    
    # Determine risk level
    if ($riskScore -ge 50) {
        return 'High'
    } elseif ($riskScore -ge 30) {
        return 'Medium'
    } else {
        return 'Low'
    }
}

function Get-UserRecommendations {
    param([object]$User, [string]$MfaStatus, [string[]]$AuthMethods)
    
    $recommendations = @()
    
    # MFA recommendations
    switch ($MfaStatus) {
        'Not Capable' {
            $recommendations += 'Enable MFA capability for this user'
            $recommendations += 'Assign appropriate licenses if needed'
        }
        'Capable but Not Registered' {
            $recommendations += 'Require user to register for MFA'
            $recommendations += 'Provide MFA registration guidance'
        }
        'Registered' {
            if ($AuthMethods -contains 'sms') {
                $recommendations += 'Encourage migration from SMS to more secure methods'
            }
            if ($AuthMethods -notcontains 'microsoftAuthenticatorAuthenticationMethod') {
                $recommendations += 'Recommend Microsoft Authenticator app'
            }
        }
    }
    
    # Account status recommendations
    if (-not $User.AccountEnabled) {
        $recommendations += 'Consider removing disabled accounts if no longer needed'
    }
    
    # License recommendations
    $isLicensed = $User.AssignedLicenses -and $User.AssignedLicenses.Count -gt 0
    if (-not $isLicensed) {
        $recommendations += 'Assign appropriate licenses for security features'
    }
    
    # Sign-in recommendations
    if ($User.LastSignInDateTime) {
        $daysSinceLastSignIn = (Get-Date) - $User.LastSignInDateTime
        if ($daysSinceLastSignIn.Days -gt 90) {
            $recommendations += 'Review if account is still needed (no sign-in for 90+ days)'
        }
    } else {
        $recommendations += 'Account has never signed in - verify if needed'
    }
    
    # Contact information recommendations
    if (-not $User.Mail) {
        $recommendations += 'Add email address for security communications'
    }
    
    if (-not $User.MobilePhone) {
        $recommendations += 'Add mobile phone for MFA backup'
    }
    
    return $recommendations -join '; '
}

function Export-ReportData {
    param(
        [object[]]$Data,
        [hashtable]$Statistics,
        [string]$Format,
        [string]$Path
    )
    
    try {
        Write-Log "Exporting report in $Format format to $Path..."
        
        switch ($Format) {
            'CSV' {
                $Data | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
                Write-Log "CSV report exported to $Path"
            }
            
            'JSON' {
                $reportData = @{
                    GeneratedAt = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
                    TenantId = (Get-MgContext).TenantId
                    Statistics = $Statistics
                    Data = $Data
                }
                
                $reportData | ConvertTo-Json -Depth 10 | Out-File -FilePath $Path -Encoding UTF8
                Write-Log "JSON report exported to $Path"
            }
            
            'HTML' {
                $htmlReport = Generate-HTMLReport -Data $Data -Statistics $Statistics
                $htmlReport | Out-File -FilePath $Path -Encoding UTF8
                Write-Log "HTML report exported to $Path"
            }
            
            'Console' {
                Display-ConsoleReport -Data $Data -Statistics $Statistics
            }
        }
        
    } catch {
        Write-Log "Failed to export report: $($_.Exception.Message)" -Level Error
        throw
    }
}

function Generate-HTMLReport {
    param([object[]]$Data, [hashtable]$Statistics)
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>MFA Registration Status Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #0078d4; color: white; padding: 20px; border-radius: 5px; }
        .summary { background-color: #f5f5f5; padding: 15px; margin: 20px 0; border-radius: 5px; }
        .stats { display: flex; flex-wrap: wrap; gap: 20px; }
        .stat-box { background-color: white; padding: 15px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); min-width: 150px; }
        .stat-value { font-size: 24px; font-weight: bold; color: #0078d4; }
        .stat-label { font-size: 14px; color: #666; }
        table { border-collapse: collapse; width: 100%; margin-top: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #0078d4; color: white; }
        .risk-high { background-color: #ffebee; color: #c62828; }
        .risk-medium { background-color: #fff3e0; color: #ef6c00; }
        .risk-low { background-color: #e8f5e8; color: #2e7d32; }
        .mfa-registered { color: #2e7d32; }
        .mfa-not-registered { color: #c62828; }
        .mfa-capable { color: #ef6c00; }
    </style>
</head>
<body>
    <div class="header">
        <h1>MFA Registration Status Report</h1>
        <p>Generated on: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
        <p>Tenant ID: $((Get-MgContext).TenantId)</p>
    </div>
    
    <div class="summary">
        <h2>Executive Summary</h2>
        <div class="stats">
            <div class="stat-box">
                <div class="stat-value">$($Statistics.TotalUsers)</div>
                <div class="stat-label">Total Users</div>
            </div>
            <div class="stat-box">
                <div class="stat-value">$($Statistics.MFARegistered)</div>
                <div class="stat-label">MFA Registered</div>
            </div>
            <div class="stat-box">
                <div class="stat-value">$([math]::Round(($Statistics.MFARegistered / $Statistics.TotalUsers) * 100, 1))%</div>
                <div class="stat-label">Registration Rate</div>
            </div>
            <div class="stat-box">
                <div class="stat-value">$($Statistics.MFACapable)</div>
                <div class="stat-label">MFA Capable</div>
            </div>
            <div class="stat-box">
                <div class="stat-value">$($Statistics.LicensedUsers)</div>
                <div class="stat-label">Licensed Users</div>
            </div>
            <div class="stat-box">
                <div class="stat-value">$($Statistics.DisabledUsers)</div>
                <div class="stat-label">Disabled Users</div>
            </div>
        </div>
    </div>
    
    <h2>User Details</h2>
    <table>
        <thead>
            <tr>
                <th>User</th>
                <th>Department</th>
                <th>MFA Status</th>
                <th>Auth Methods</th>
                <th>Risk Level</th>
                <th>Account Status</th>
                <th>Last Sign-in</th>
            </tr>
        </thead>
        <tbody>
"@
    
    foreach ($user in $Data) {
        $mfaStatusClass = switch ($user.MfaStatus) {
            'Registered' { 'mfa-registered' }
            'Capable but Not Registered' { 'mfa-capable' }
            default { 'mfa-not-registered' }
        }
        
        $riskClass = "risk-$($user.RiskLevel.ToLower())"
        $lastSignIn = if ($user.LastSignInDateTime) { 
            ([datetime]$user.LastSignInDateTime).ToString('yyyy-MM-dd') 
        } else { 
            'Never' 
        }
        
        $html += @"
            <tr>
                <td>
                    <strong>$($user.DisplayName)</strong><br>
                    <small>$($user.UserPrincipalName)</small>
                </td>
                <td>$($user.Department -or 'Unknown')</td>
                <td class="$mfaStatusClass">$($user.MfaStatus)</td>
                <td>$($user.AuthenticationMethods -or 'None')</td>
                <td class="$riskClass">$($user.RiskLevel)</td>
                <td>$($user.AccountEnabled)</td>
                <td>$lastSignIn</td>
            </tr>
"@
    }
    
    $html += @"
        </tbody>
    </table>
</body>
</html>
"@
    
    return $html
}

function Display-ConsoleReport {
    param([object[]]$Data, [hashtable]$Statistics)
    
    Write-Host "`n=== MFA Registration Status Report ===" -ForegroundColor Cyan
    Write-Host "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
    Write-Host "Tenant: $((Get-MgContext).TenantId)" -ForegroundColor Gray
    
    Write-Host "`n=== Executive Summary ===" -ForegroundColor Yellow
    Write-Host "Total Users: $($Statistics.TotalUsers)" -ForegroundColor Green
    Write-Host "MFA Registered: $($Statistics.MFARegistered)" -ForegroundColor Green
    Write-Host "Registration Rate: $([math]::Round(($Statistics.MFARegistered / $Statistics.TotalUsers) * 100, 1))%" -ForegroundColor Green
    Write-Host "MFA Capable: $($Statistics.MFACapable)" -ForegroundColor Green
    Write-Host "Licensed Users: $($Statistics.LicensedUsers)" -ForegroundColor Green
    Write-Host "Disabled Users: $($Statistics.DisabledUsers)" -ForegroundColor Green
    
    Write-Host "`n=== Department Breakdown ===" -ForegroundColor Yellow
    foreach ($dept in $Statistics.Departments.Keys | Sort-Object) {
        Write-Host "$dept`: $($Statistics.Departments[$dept])" -ForegroundColor Cyan
    }
    
    if ($Statistics.AuthMethods.Count -gt 0) {
        Write-Host "`n=== Authentication Methods ===" -ForegroundColor Yellow
        foreach ($method in $Statistics.AuthMethods.Keys | Sort-Object) {
            Write-Host "$method`: $($Statistics.AuthMethods[$method])" -ForegroundColor Cyan
        }
    }
    
    Write-Host "`n=== User Details ===" -ForegroundColor Yellow
    $Data | Select-Object DisplayName, UserPrincipalName, Department, MfaStatus, RiskLevel, AccountEnabled, LastSignInDateTime | Format-Table -AutoSize
    
    if ($GenerateRecommendations) {
        Write-Host "`n=== Security Recommendations ===" -ForegroundColor Yellow
        $highRiskUsers = $Data | Where-Object { $_.RiskLevel -eq 'High' }
        $unregisteredUsers = $Data | Where-Object { $_.MfaStatus -ne 'Registered' }
        
        if ($highRiskUsers.Count -gt 0) {
            Write-Host "High Risk Users: $($highRiskUsers.Count)" -ForegroundColor Red
        }
        
        if ($unregisteredUsers.Count -gt 0) {
            Write-Host "Users Not Registered for MFA: $($unregisteredUsers.Count)" -ForegroundColor Red
        }
        
        $registrationRate = ($Statistics.MFARegistered / $Statistics.TotalUsers) * 100
        if ($registrationRate -lt 90) {
            Write-Host "MFA registration rate is below 90% - consider mandatory registration" -ForegroundColor Red
        }
    }
}

function Send-EmailReport {
    param(
        [string]$ReportPath,
        [string[]]$Recipients,
        [hashtable]$Statistics
    )
    
    if (-not $SendEmailReport -or -not $Recipients) {
        return
    }
    
    try {
        Write-Log "Sending email report to $($Recipients -join ', ')..."
        
        $subject = "MFA Registration Status Report - $(Get-Date -Format 'yyyy-MM-dd')"
        $body = @"
MFA Registration Status Report

Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Tenant: $((Get-MgContext).TenantId)

Summary:
- Total Users: $($Statistics.TotalUsers)
- MFA Registered: $($Statistics.MFARegistered)
- Registration Rate: $([math]::Round(($Statistics.MFARegistered / $Statistics.TotalUsers) * 100, 1))%
- MFA Capable: $($Statistics.MFACapable)
- Licensed Users: $($Statistics.LicensedUsers)

Please find the detailed report attached.
"@
        
        # This would require additional email configuration
        # For now, just log the attempt
        Write-Log "Email report prepared for: $($Recipients -join ', ')"
        Write-Log "Subject: $subject"
        Write-Log "Attachment: $ReportPath"
        
        # TODO: Implement actual email sending based on your environment
        # Send-MailMessage or Send-MgUserMessage could be used here
        
    } catch {
        Write-Log "Failed to send email report: $($_.Exception.Message)" -Level Error
    }
}

# Main execution
try {
    Write-Log "Starting MFA Registration Status Report generation..."
    
    # Validate parameters
    if ($OutputFormat -ne 'Console' -and -not $ExportPath) {
        throw "ExportPath is required when OutputFormat is not Console"
    }
    
    if ($SendEmailReport -and -not $EmailRecipients) {
        throw "EmailRecipients is required when SendEmailReport is specified"
    }
    
    # Connect to Microsoft Graph
    Connect-ToMicrosoftGraph -TenantId $TenantId
    
    # Get MFA registration report
    $mfaReport = Get-MFARegistrationReport
    
    if (-not $mfaReport -or $mfaReport.Count -eq 0) {
        Write-Log "No MFA registration data found" -Level Warning
        return
    }
    
    # Get user details
    $userIds = $mfaReport | ForEach-Object { $_.Id }
    $userDetails = Get-UserDetails -UserIds $userIds
    
    # Get authentication methods if requested
    $authMethods = Get-UserAuthenticationMethods -UserIds $userIds
    
    # Process the data
    $processedResult = Process-MFAData -MFAReport $mfaReport -UserDetails $userDetails -AuthMethods $authMethods
    
    # Export/display the report
    Export-ReportData -Data $processedResult.Data -Statistics $processedResult.Statistics -Format $OutputFormat -Path $ExportPath
    
    # Send email if requested
    if ($SendEmailReport) {
        Send-EmailReport -ReportPath $ExportPath -Recipients $EmailRecipients -Statistics $processedResult.Statistics
    }
    
    Write-Log "MFA Registration Status Report completed successfully"
    
} catch {
    Write-Log "Script execution failed: $($_.Exception.Message)" -Level Error
    Write-Log "Stack trace: $($_.Exception.StackTrace)" -Level Error
    throw
} finally {
    # Disconnect from Microsoft Graph
    try {
        Disconnect-MgGraph -ErrorAction SilentlyContinue
        Write-Log "Disconnected from Microsoft Graph"
    } catch {
        Write-Log "Failed to disconnect from Microsoft Graph: $($_.Exception.Message)" -Level Warning
    }
}
