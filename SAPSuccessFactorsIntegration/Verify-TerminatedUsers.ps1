#Requires -Modules Microsoft.Graph.Users, Microsoft.Graph.Authentication

<#
.SYNOPSIS
    Verifies user termination status by comparing SAP SuccessFactors data with Active Directory/Entra ID
.DESCRIPTION
    This script integrates with SAP SuccessFactors to identify terminated employees and verifies
    their corresponding user accounts have been properly disabled in Active Directory and Entra ID.
    Provides comprehensive reporting and automated remediation capabilities.
.PARAMETER SuccessFactorsEndpoint
    SAP SuccessFactors OData API endpoint
.PARAMETER ClientId
    Application ID for SAP SuccessFactors authentication
.PARAMETER ClientSecret
    Client secret for SAP SuccessFactors authentication
.PARAMETER TenantId
    Tenant ID for Microsoft Graph authentication
.PARAMETER CompanyId
    Company ID in SAP SuccessFactors
.PARAMETER OutputFormat
    Output format for the report (Console, CSV, HTML, JSON)
.PARAMETER ExportPath
    Path to export the verification report
.PARAMETER AutoRemediate
    Automatically disable accounts for terminated users
.PARAMETER DryRun
    Perform a dry run without making actual changes
.PARAMETER IncludeActiveUsers
    Include active users in the comparison report
.PARAMETER GracePeriodDays
    Grace period in days after termination before flagging as non-compliant
.PARAMETER NotificationEmail
    Email address for sending compliance notifications
.PARAMETER ScheduleReport
    Schedule the verification to run automatically
.EXAMPLE
    .\Verify-TerminatedUsers.ps1 -SuccessFactorsEndpoint "https://api.successfactors.com/odata/v2" -CompanyId "COMPANY" -OutputFormat HTML -ExportPath ".\termination-report.html"
.EXAMPLE
    .\Verify-TerminatedUsers.ps1 -SuccessFactorsEndpoint "https://api.successfactors.com/odata/v2" -CompanyId "COMPANY" -AutoRemediate -DryRun -NotificationEmail "hr@company.com"
.EXAMPLE
    .\Verify-TerminatedUsers.ps1 -SuccessFactorsEndpoint "https://api.successfactors.com/odata/v2" -CompanyId "COMPANY" -OutputFormat CSV -ExportPath ".\compliance-report.csv" -GracePeriodDays 3
.NOTES
    Author: GitHub Copilot
    Version: 1.0
    Requires: Microsoft.Graph.Users, Microsoft.Graph.Authentication modules
    Permissions: User.ReadWrite.All, Directory.ReadWrite.All
    Dependencies: SAP SuccessFactors OData API access
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$SuccessFactorsEndpoint,
    
    [Parameter(Mandatory = $false)]
    [string]$ClientId,
    
    [Parameter(Mandatory = $false)]
    [string]$ClientSecret,
    
    [Parameter(Mandatory = $false)]
    [string]$TenantId,
    
    [Parameter(Mandatory = $true)]
    [string]$CompanyId,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet('Console', 'CSV', 'HTML', 'JSON')]
    [string]$OutputFormat = 'Console',
    
    [Parameter(Mandatory = $false)]
    [string]$ExportPath,
    
    [Parameter(Mandatory = $false)]
    [switch]$AutoRemediate,
    
    [Parameter(Mandatory = $false)]
    [switch]$DryRun,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeActiveUsers,
    
    [Parameter(Mandatory = $false)]
    [int]$GracePeriodDays = 1,
    
    [Parameter(Mandatory = $false)]
    [string]$NotificationEmail,
    
    [Parameter(Mandatory = $false)]
    [switch]$ScheduleReport
)

# Initialize logging
$LogPath = ".\logs\TerminationVerification_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
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

function Connect-ToSuccessFactors {
    param(
        [string]$Endpoint,
        [string]$ClientId,
        [string]$ClientSecret,
        [string]$CompanyId
    )
    
    try {
        Write-Log "Connecting to SAP SuccessFactors..."
        
        # Create authentication header
        $authString = "$ClientId`:$ClientSecret"
        $encodedAuth = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($authString))
        
        $headers = @{
            'Authorization' = "Basic $encodedAuth"
            'Content-Type' = 'application/json'
            'Accept' = 'application/json'
            'DataServiceVersion' = '2.0'
            'MaxDataServiceVersion' = '2.0'
        }
        
        # Test connection
        $testUrl = "$Endpoint/$CompanyId/User?`$select=userId,username,status&`$top=1"
        $response = Invoke-RestMethod -Uri $testUrl -Headers $headers -Method Get
        
        Write-Log "Successfully connected to SAP SuccessFactors"
        return $headers
        
    } catch {
        Write-Log "Failed to connect to SAP SuccessFactors: $($_.Exception.Message)" -Level Error
        throw
    }
}

function Get-SuccessFactorsTerminatedUsers {
    param(
        [string]$Endpoint,
        [hashtable]$Headers,
        [string]$CompanyId,
        [int]$GracePeriodDays
    )
    
    try {
        Write-Log "Retrieving terminated users from SAP SuccessFactors..."
        
        $cutoffDate = (Get-Date).AddDays(-$GracePeriodDays).ToString('yyyy-MM-ddTHH:mm:ss')
        
        # Query for terminated users
        $filter = "status eq 'T' and lastModifiedDateTime le datetime'$cutoffDate'"
        $select = "userId,username,firstName,lastName,email,department,division,location,hireDate,lastWorkingDay,terminationDate,status,lastModifiedDateTime"
        $url = "$Endpoint/$CompanyId/User?`$filter=$filter&`$select=$select&`$orderby=terminationDate desc"
        
        $terminatedUsers = @()
        $skip = 0
        $top = 1000
        
        do {
            $pagedUrl = "$url&`$skip=$skip&`$top=$top"
            Write-Log "Fetching terminated users: $pagedUrl"
            
            $response = Invoke-RestMethod -Uri $pagedUrl -Headers $Headers -Method Get
            
            if ($response.d -and $response.d.results) {
                $terminatedUsers += $response.d.results
                $skip += $top
                
                Write-Log "Retrieved $($response.d.results.Count) terminated users (Total: $($terminatedUsers.Count))"
            } else {
                break
            }
            
        } while ($response.d.results.Count -eq $top)
        
        Write-Log "Total terminated users retrieved: $($terminatedUsers.Count)"
        return $terminatedUsers
        
    } catch {
        Write-Log "Failed to retrieve terminated users: $($_.Exception.Message)" -Level Error
        throw
    }
}

function Get-SuccessFactorsActiveUsers {
    param(
        [string]$Endpoint,
        [hashtable]$Headers,
        [string]$CompanyId
    )
    
    if (-not $IncludeActiveUsers) {
        return @()
    }
    
    try {
        Write-Log "Retrieving active users from SAP SuccessFactors..."
        
        # Query for active users
        $filter = "status eq 'A'"
        $select = "userId,username,firstName,lastName,email,department,division,location,hireDate,status,lastModifiedDateTime"
        $url = "$Endpoint/$CompanyId/User?`$filter=$filter&`$select=$select&`$orderby=lastModifiedDateTime desc"
        
        $activeUsers = @()
        $skip = 0
        $top = 1000
        
        do {
            $pagedUrl = "$url&`$skip=$skip&`$top=$top"
            Write-Log "Fetching active users: $pagedUrl"
            
            $response = Invoke-RestMethod -Uri $pagedUrl -Headers $Headers -Method Get
            
            if ($response.d -and $response.d.results) {
                $activeUsers += $response.d.results
                $skip += $top
                
                Write-Log "Retrieved $($response.d.results.Count) active users (Total: $($activeUsers.Count))"
            } else {
                break
            }
            
        } while ($response.d.results.Count -eq $top)
        
        Write-Log "Total active users retrieved: $($activeUsers.Count)"
        return $activeUsers
        
    } catch {
        Write-Log "Failed to retrieve active users: $($_.Exception.Message)" -Level Error
        throw
    }
}

function Connect-ToMicrosoftGraph {
    param([string]$TenantId)
    
    try {
        Write-Log "Connecting to Microsoft Graph..."
        
        $requiredScopes = @(
            'User.ReadWrite.All',
            'Directory.ReadWrite.All'
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
        
        $context = Get-MgContext
        Write-Log "Connected to tenant: $($context.TenantId)"
        
    } catch {
        Write-Log "Failed to connect to Microsoft Graph: $($_.Exception.Message)" -Level Error
        throw
    }
}

function Get-EntraIDUsers {
    param([string[]]$UserPrincipalNames)
    
    try {
        Write-Log "Retrieving users from Entra ID..."
        
        $entraUsers = @{}
        $batchSize = 100
        
        for ($i = 0; $i -lt $UserPrincipalNames.Count; $i += $batchSize) {
            $batch = $UserPrincipalNames[$i..([Math]::Min($i + $batchSize - 1, $UserPrincipalNames.Count - 1))]
            
            foreach ($upn in $batch) {
                try {
                    $user = Get-MgUser -Filter "userPrincipalName eq '$upn'" -Property @(
                        'id', 'userPrincipalName', 'displayName', 'givenName', 'surname',
                        'mail', 'department', 'jobTitle', 'companyName', 'accountEnabled',
                        'createdDateTime', 'lastSignInDateTime', 'onPremisesDistinguishedName',
                        'onPremisesSyncEnabled', 'userType', 'assignedLicenses'
                    ) -ErrorAction SilentlyContinue
                    
                    if ($user) {
                        $entraUsers[$upn] = $user
                    }
                } catch {
                    Write-Log "Failed to retrieve user $upn from Entra ID: $($_.Exception.Message)" -Level Warning
                }
            }
            
            Write-Progress -Activity "Retrieving Entra ID users" -Status "Processed $($i + $batch.Count) of $($UserPrincipalNames.Count)" -PercentComplete (($i + $batch.Count) / $UserPrincipalNames.Count * 100)
        }
        
        Write-Progress -Activity "Retrieving Entra ID users" -Completed
        Write-Log "Retrieved $($entraUsers.Count) users from Entra ID"
        
        return $entraUsers
        
    } catch {
        Write-Log "Failed to retrieve users from Entra ID: $($_.Exception.Message)" -Level Error
        throw
    }
}

function Get-ActiveDirectoryUsers {
    param([string[]]$UserPrincipalNames)
    
    try {
        Write-Log "Retrieving users from Active Directory..."
        
        # Check if AD module is available
        if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
            Write-Log "Active Directory module not available, skipping AD verification" -Level Warning
            return @{}
        }
        
        Import-Module ActiveDirectory -ErrorAction SilentlyContinue
        
        $adUsers = @{}
        
        foreach ($upn in $UserPrincipalNames) {
            try {
                $user = Get-ADUser -Filter "userPrincipalName -eq '$upn'" -Properties @(
                    'userPrincipalName', 'displayName', 'givenName', 'surname',
                    'mail', 'department', 'title', 'company', 'enabled',
                    'whenCreated', 'whenChanged', 'lastLogonDate', 'distinguishedName'
                ) -ErrorAction SilentlyContinue
                
                if ($user) {
                    $adUsers[$upn] = $user
                }
            } catch {
                Write-Log "Failed to retrieve user $upn from Active Directory: $($_.Exception.Message)" -Level Warning
            }
        }
        
        Write-Log "Retrieved $($adUsers.Count) users from Active Directory"
        return $adUsers
        
    } catch {
        Write-Log "Failed to retrieve users from Active Directory: $($_.Exception.Message)" -Level Warning
        return @{}
    }
}

function Compare-UserStatus {
    param(
        [array]$SFTerminatedUsers,
        [array]$SFActiveUsers,
        [hashtable]$EntraUsers,
        [hashtable]$ADUsers
    )
    
    try {
        Write-Log "Comparing user status between systems..."
        
        $comparisonResults = @()
        $statistics = @{
            TotalTerminatedInSF = $SFTerminatedUsers.Count
            TotalActiveInSF = $SFActiveUsers.Count
            CompliantTerminations = 0
            NonCompliantTerminations = 0
            MissingUsers = 0
            ActiveUsersStillEnabled = 0
            RecommendedActions = @()
        }
        
        # Process terminated users
        foreach ($sfUser in $SFTerminatedUsers) {
            $upn = $sfUser.email -or "$($sfUser.username)@$($env:USERDNSDOMAIN)"
            
            $entraUser = $EntraUsers[$upn]
            $adUser = $ADUsers[$upn]
            
            $complianceStatus = Get-UserComplianceStatus -SFUser $sfUser -EntraUser $entraUser -ADUser $adUser
            
            $result = [PSCustomObject]@{
                SourceSystem = 'SuccessFactors'
                EmployeeId = $sfUser.userId
                Username = $sfUser.username
                UserPrincipalName = $upn
                DisplayName = "$($sfUser.firstName) $($sfUser.lastName)"
                Email = $sfUser.email
                Department = $sfUser.department
                Division = $sfUser.division
                Location = $sfUser.location
                HireDate = $sfUser.hireDate
                LastWorkingDay = $sfUser.lastWorkingDay
                TerminationDate = $sfUser.terminationDate
                SFStatus = $sfUser.status
                SFLastModified = $sfUser.lastModifiedDateTime
                EntraExists = $entraUser -ne $null
                EntraEnabled = if ($entraUser) { $entraUser.AccountEnabled } else { $null }
                EntraLastSignIn = if ($entraUser) { $entraUser.LastSignInDateTime } else { $null }
                ADExists = $adUser -ne $null
                ADEnabled = if ($adUser) { $adUser.Enabled } else { $null }
                ADLastLogon = if ($adUser) { $adUser.LastLogonDate } else { $null }
                ComplianceStatus = $complianceStatus.Status
                ComplianceDetails = $complianceStatus.Details
                RecommendedActions = $complianceStatus.Actions
                RiskLevel = $complianceStatus.RiskLevel
                DaysAfterTermination = if ($sfUser.terminationDate) { 
                    [int]((Get-Date) - [datetime]$sfUser.terminationDate).Days 
                } else { 
                    $null 
                }
                UserType = 'Terminated'
                LastVerified = Get-Date
            }
            
            $comparisonResults += $result
            
            # Update statistics
            if ($complianceStatus.Status -eq 'Compliant') {
                $statistics.CompliantTerminations++
            } else {
                $statistics.NonCompliantTerminations++
            }
            
            if (-not $entraUser -and -not $adUser) {
                $statistics.MissingUsers++
            }
        }
        
        # Process active users if requested
        if ($IncludeActiveUsers) {
            foreach ($sfUser in $SFActiveUsers) {
                $upn = $sfUser.email -or "$($sfUser.username)@$($env:USERDNSDOMAIN)"
                
                $entraUser = $EntraUsers[$upn]
                $adUser = $ADUsers[$upn]
                
                $complianceStatus = Get-ActiveUserComplianceStatus -SFUser $sfUser -EntraUser $entraUser -ADUser $adUser
                
                $result = [PSCustomObject]@{
                    SourceSystem = 'SuccessFactors'
                    EmployeeId = $sfUser.userId
                    Username = $sfUser.username
                    UserPrincipalName = $upn
                    DisplayName = "$($sfUser.firstName) $($sfUser.lastName)"
                    Email = $sfUser.email
                    Department = $sfUser.department
                    Division = $sfUser.division
                    Location = $sfUser.location
                    HireDate = $sfUser.hireDate
                    LastWorkingDay = $null
                    TerminationDate = $null
                    SFStatus = $sfUser.status
                    SFLastModified = $sfUser.lastModifiedDateTime
                    EntraExists = $entraUser -ne $null
                    EntraEnabled = if ($entraUser) { $entraUser.AccountEnabled } else { $null }
                    EntraLastSignIn = if ($entraUser) { $entraUser.LastSignInDateTime } else { $null }
                    ADExists = $adUser -ne $null
                    ADEnabled = if ($adUser) { $adUser.Enabled } else { $null }
                    ADLastLogon = if ($adUser) { $adUser.LastLogonDate } else { $null }
                    ComplianceStatus = $complianceStatus.Status
                    ComplianceDetails = $complianceStatus.Details
                    RecommendedActions = $complianceStatus.Actions
                    RiskLevel = $complianceStatus.RiskLevel
                    DaysAfterTermination = $null
                    UserType = 'Active'
                    LastVerified = Get-Date
                }
                
                $comparisonResults += $result
                
                # Update statistics for active users
                if ($complianceStatus.Status -eq 'Non-Compliant') {
                    $statistics.ActiveUsersStillEnabled++
                }
            }
        }
        
        # Generate recommendations
        $statistics.RecommendedActions = Get-ComplianceRecommendations -Results $comparisonResults -Statistics $statistics
        
        Write-Log "Comparison completed: $($comparisonResults.Count) users processed"
        Write-Log "Compliant terminations: $($statistics.CompliantTerminations)"
        Write-Log "Non-compliant terminations: $($statistics.NonCompliantTerminations)"
        
        return @{
            Results = $comparisonResults
            Statistics = $statistics
        }
        
    } catch {
        Write-Log "Failed to compare user status: $($_.Exception.Message)" -Level Error
        throw
    }
}

function Get-UserComplianceStatus {
    param($SFUser, $EntraUser, $ADUser)
    
    $actions = @()
    $details = @()
    $riskLevel = 'Low'
    
    # Check if user exists in systems
    if (-not $EntraUser -and -not $ADUser) {
        return @{
            Status = 'Unknown'
            Details = @('User not found in Entra ID or Active Directory')
            Actions = @('Verify user existence and mapping')
            RiskLevel = 'Medium'
        }
    }
    
    # Check Entra ID compliance
    if ($EntraUser) {
        if ($EntraUser.AccountEnabled) {
            $details += 'Entra ID account is still enabled'
            $actions += 'Disable Entra ID account'
            $riskLevel = 'High'
        } else {
            $details += 'Entra ID account is properly disabled'
        }
    }
    
    # Check Active Directory compliance
    if ($ADUser) {
        if ($ADUser.Enabled) {
            $details += 'Active Directory account is still enabled'
            $actions += 'Disable Active Directory account'
            $riskLevel = 'High'
        } else {
            $details += 'Active Directory account is properly disabled'
        }
    }
    
    # Check termination date vs current date
    if ($SFUser.terminationDate) {
        $terminationDate = [datetime]$SFUser.terminationDate
        $daysSinceTermination = (Get-Date) - $terminationDate
        
        if ($daysSinceTermination.Days -gt $GracePeriodDays) {
            $details += "User terminated $($daysSinceTermination.Days) days ago"
            
            if ($daysSinceTermination.Days -gt 30) {
                $riskLevel = 'Critical'
                $actions += 'Urgent: Account should have been disabled weeks ago'
            }
        }
    }
    
    # Determine overall compliance
    $isCompliant = $true
    if ($EntraUser -and $EntraUser.AccountEnabled) { $isCompliant = $false }
    if ($ADUser -and $ADUser.Enabled) { $isCompliant = $false }
    
    return @{
        Status = if ($isCompliant) { 'Compliant' } else { 'Non-Compliant' }
        Details = $details
        Actions = $actions
        RiskLevel = $riskLevel
    }
}

function Get-ActiveUserComplianceStatus {
    param($SFUser, $EntraUser, $ADUser)
    
    $actions = @()
    $details = @()
    $riskLevel = 'Low'
    
    # For active users, we want to ensure they have proper access
    if ($EntraUser -and -not $EntraUser.AccountEnabled) {
        $details += 'Active employee has disabled Entra ID account'
        $actions += 'Enable Entra ID account for active employee'
        $riskLevel = 'Medium'
    }
    
    if ($ADUser -and -not $ADUser.Enabled) {
        $details += 'Active employee has disabled Active Directory account'
        $actions += 'Enable Active Directory account for active employee'
        $riskLevel = 'Medium'
    }
    
    if (-not $EntraUser -and -not $ADUser) {
        $details += 'Active employee has no user accounts'
        $actions += 'Create user accounts for active employee'
        $riskLevel = 'High'
    }
    
    # Check if accounts are properly enabled
    $isCompliant = $true
    if ($EntraUser -and -not $EntraUser.AccountEnabled) { $isCompliant = $false }
    if ($ADUser -and -not $ADUser.Enabled) { $isCompliant = $false }
    if (-not $EntraUser -and -not $ADUser) { $isCompliant = $false }
    
    return @{
        Status = if ($isCompliant) { 'Compliant' } else { 'Non-Compliant' }
        Details = $details
        Actions = $actions
        RiskLevel = $riskLevel
    }
}

function Get-ComplianceRecommendations {
    param($Results, $Statistics)
    
    $recommendations = @()
    
    # High-level recommendations
    if ($Statistics.NonCompliantTerminations -gt 0) {
        $recommendations += "Immediate action required: $($Statistics.NonCompliantTerminations) terminated users still have active accounts"
    }
    
    if ($Statistics.MissingUsers -gt 0) {
        $recommendations += "Review user mapping: $($Statistics.MissingUsers) terminated users not found in directory systems"
    }
    
    # Risk-based recommendations
    $criticalUsers = $Results | Where-Object { $_.RiskLevel -eq 'Critical' }
    if ($criticalUsers.Count -gt 0) {
        $recommendations += "Critical security risk: $($criticalUsers.Count) users terminated over 30 days ago still have active accounts"
    }
    
    $highRiskUsers = $Results | Where-Object { $_.RiskLevel -eq 'High' }
    if ($highRiskUsers.Count -gt 0) {
        $recommendations += "High security risk: $($highRiskUsers.Count) users with active accounts after termination"
    }
    
    # Process recommendations
    if ($Statistics.NonCompliantTerminations -gt 10) {
        $recommendations += "Consider implementing automated account disabling process"
    }
    
    if ($Statistics.MissingUsers -gt 5) {
        $recommendations += "Review user provisioning and deprovisioning processes"
    }
    
    # Compliance rate recommendation
    $complianceRate = if ($Statistics.TotalTerminatedInSF -gt 0) { 
        ($Statistics.CompliantTerminations / $Statistics.TotalTerminatedInSF) * 100 
    } else { 
        100 
    }
    
    if ($complianceRate -lt 95) {
        $recommendations += "Compliance rate is $([math]::Round($complianceRate, 1))% - should be above 95%"
    }
    
    return $recommendations
}

function Invoke-AutoRemediation {
    param($NonCompliantUsers)
    
    if (-not $AutoRemediate) {
        return
    }
    
    try {
        Write-Log "Starting auto-remediation for $($NonCompliantUsers.Count) users..."
        
        $remediationResults = @()
        
        foreach ($user in $NonCompliantUsers) {
            $result = @{
                UserPrincipalName = $user.UserPrincipalName
                DisplayName = $user.DisplayName
                EntraRemediation = $null
                ADRemediation = $null
                Success = $false
                Error = $null
            }
            
            try {
                if ($DryRun) {
                    Write-Log "DRY RUN: Would disable account for $($user.DisplayName)" -Level Warning
                    $result.EntraRemediation = "DRY RUN: Would disable Entra ID account"
                    $result.ADRemediation = "DRY RUN: Would disable AD account"
                    $result.Success = $true
                } else {
                    # Disable Entra ID account
                    if ($user.EntraExists -and $user.EntraEnabled) {
                        Update-MgUser -UserId $user.UserPrincipalName -AccountEnabled:$false
                        $result.EntraRemediation = "Disabled Entra ID account"
                        Write-Log "Disabled Entra ID account for $($user.DisplayName)"
                    }
                    
                    # Disable Active Directory account
                    if ($user.ADExists -and $user.ADEnabled) {
                        if (Get-Module -ListAvailable -Name ActiveDirectory) {
                            Disable-ADAccount -Identity $user.UserPrincipalName
                            $result.ADRemediation = "Disabled Active Directory account"
                            Write-Log "Disabled Active Directory account for $($user.DisplayName)"
                        }
                    }
                    
                    $result.Success = $true
                }
                
            } catch {
                $result.Error = $_.Exception.Message
                $result.Success = $false
                Write-Log "Failed to remediate $($user.DisplayName): $($_.Exception.Message)" -Level Error
            }
            
            $remediationResults += $result
        }
        
        Write-Log "Auto-remediation completed: $($remediationResults.Count) users processed"
        return $remediationResults
        
    } catch {
        Write-Log "Auto-remediation failed: $($_.Exception.Message)" -Level Error
        throw
    }
}

function Export-ComplianceReport {
    param(
        [array]$Results,
        [hashtable]$Statistics,
        [string]$Format,
        [string]$Path
    )
    
    try {
        Write-Log "Exporting compliance report in $Format format..."
        
        switch ($Format) {
            'CSV' {
                $Results | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
                Write-Log "CSV report exported to $Path"
            }
            
            'JSON' {
                $reportData = @{
                    GeneratedAt = Get-Date
                    Statistics = $Statistics
                    Results = $Results
                }
                
                $reportData | ConvertTo-Json -Depth 10 | Out-File -FilePath $Path -Encoding UTF8
                Write-Log "JSON report exported to $Path"
            }
            
            'HTML' {
                $htmlReport = New-HTMLComplianceReport -Results $Results -Statistics $Statistics
                $htmlReport | Out-File -FilePath $Path -Encoding UTF8
                Write-Log "HTML report exported to $Path"
            }
            
            'Console' {
                Show-ConsoleReport -Results $Results -Statistics $Statistics
            }
        }
        
    } catch {
        Write-Log "Failed to export report: $($_.Exception.Message)" -Level Error
        throw
    }
}

function New-HTMLComplianceReport {
    param($Results, $Statistics)
    
    $complianceRate = if ($Statistics.TotalTerminatedInSF -gt 0) { 
        [math]::Round(($Statistics.CompliantTerminations / $Statistics.TotalTerminatedInSF) * 100, 1)
    } else { 
        100 
    }
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>SAP SuccessFactors Termination Compliance Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #0078d4; color: white; padding: 20px; border-radius: 5px; }
        .summary { background-color: #f5f5f5; padding: 15px; margin: 20px 0; border-radius: 5px; }
        .stats { display: flex; flex-wrap: wrap; gap: 20px; }
        .stat-box { background-color: white; padding: 15px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); min-width: 150px; }
        .stat-value { font-size: 24px; font-weight: bold; color: #0078d4; }
        .stat-label { font-size: 14px; color: #666; }
        .compliance-rate { color: $(if ($complianceRate -ge 95) { '#28a745' } else { '#dc3545' }); }
        table { border-collapse: collapse; width: 100%; margin-top: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #0078d4; color: white; }
        .compliant { background-color: #d4edda; color: #155724; }
        .non-compliant { background-color: #f8d7da; color: #721c24; }
        .risk-critical { background-color: #721c24; color: white; }
        .risk-high { background-color: #dc3545; color: white; }
        .risk-medium { background-color: #ffc107; color: #212529; }
        .risk-low { background-color: #28a745; color: white; }
        .recommendations { background-color: #fff3cd; padding: 15px; border-radius: 5px; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="header">
        <h1>SAP SuccessFactors Termination Compliance Report</h1>
        <p>Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
    </div>
    
    <div class="summary">
        <h2>Executive Summary</h2>
        <div class="stats">
            <div class="stat-box">
                <div class="stat-value">$($Statistics.TotalTerminatedInSF)</div>
                <div class="stat-label">Terminated Users</div>
            </div>
            <div class="stat-box">
                <div class="stat-value">$($Statistics.CompliantTerminations)</div>
                <div class="stat-label">Compliant</div>
            </div>
            <div class="stat-box">
                <div class="stat-value">$($Statistics.NonCompliantTerminations)</div>
                <div class="stat-label">Non-Compliant</div>
            </div>
            <div class="stat-box">
                <div class="stat-value compliance-rate">$complianceRate%</div>
                <div class="stat-label">Compliance Rate</div>
            </div>
        </div>
    </div>
    
    <div class="recommendations">
        <h3>Recommendations</h3>
        <ul>
"@
    
    foreach ($recommendation in $Statistics.RecommendedActions) {
        $html += "            <li>$recommendation</li>`n"
    }
    
    $html += @"
        </ul>
    </div>
    
    <h2>Detailed Results</h2>
    <table>
        <thead>
            <tr>
                <th>Employee</th>
                <th>Status</th>
                <th>Termination Date</th>
                <th>Entra ID</th>
                <th>Active Directory</th>
                <th>Compliance</th>
                <th>Risk Level</th>
                <th>Actions</th>
            </tr>
        </thead>
        <tbody>
"@
    
    foreach ($result in $Results) {
        $complianceClass = if ($result.ComplianceStatus -eq 'Compliant') { 'compliant' } else { 'non-compliant' }
        $riskClass = "risk-$($result.RiskLevel.ToLower())"
        $terminationDate = if ($result.TerminationDate) { 
            ([datetime]$result.TerminationDate).ToString('yyyy-MM-dd') 
        } else { 
            'N/A' 
        }
        
        $html += @"
            <tr>
                <td>
                    <strong>$($result.DisplayName)</strong><br>
                    <small>$($result.UserPrincipalName)</small><br>
                    <small>$($result.Department)</small>
                </td>
                <td>$($result.SFStatus)</td>
                <td>$terminationDate</td>
                <td>$(if ($result.EntraExists) { if ($result.EntraEnabled) { 'Enabled' } else { 'Disabled' } } else { 'Not Found' })</td>
                <td>$(if ($result.ADExists) { if ($result.ADEnabled) { 'Enabled' } else { 'Disabled' } } else { 'Not Found' })</td>
                <td class="$complianceClass">$($result.ComplianceStatus)</td>
                <td class="$riskClass">$($result.RiskLevel)</td>
                <td>$($result.RecommendedActions -join '<br>')</td>
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

function Show-ConsoleReport {
    param($Results, $Statistics)
    
    Write-Host "`n=== SAP SuccessFactors Termination Compliance Report ===" -ForegroundColor Cyan
    Write-Host "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
    
    Write-Host "`n=== Executive Summary ===" -ForegroundColor Yellow
    Write-Host "Total Terminated Users: $($Statistics.TotalTerminatedInSF)" -ForegroundColor Green
    Write-Host "Compliant Terminations: $($Statistics.CompliantTerminations)" -ForegroundColor Green
    Write-Host "Non-Compliant Terminations: $($Statistics.NonCompliantTerminations)" -ForegroundColor Red
    
    $complianceRate = if ($Statistics.TotalTerminatedInSF -gt 0) { 
        [math]::Round(($Statistics.CompliantTerminations / $Statistics.TotalTerminatedInSF) * 100, 1)
    } else { 
        100 
    }
    
    $complianceColor = if ($complianceRate -ge 95) { 'Green' } else { 'Red' }
    Write-Host "Compliance Rate: $complianceRate%" -ForegroundColor $complianceColor
    
    Write-Host "`n=== Recommendations ===" -ForegroundColor Yellow
    foreach ($recommendation in $Statistics.RecommendedActions) {
        Write-Host "• $recommendation" -ForegroundColor Cyan
    }
    
    Write-Host "`n=== Non-Compliant Users ===" -ForegroundColor Red
    $nonCompliantUsers = $Results | Where-Object { $_.ComplianceStatus -eq 'Non-Compliant' }
    
    if ($nonCompliantUsers.Count -gt 0) {
        $nonCompliantUsers | Select-Object DisplayName, UserPrincipalName, TerminationDate, ComplianceStatus, RiskLevel | Format-Table -AutoSize
    } else {
        Write-Host "No non-compliant users found!" -ForegroundColor Green
    }
}

function Send-ComplianceNotification {
    param($Results, $Statistics, $EmailAddress)
    
    if (-not $NotificationEmail) {
        return
    }
    
    try {
        Write-Log "Sending compliance notification to $EmailAddress..."
        
        $nonCompliantCount = $Statistics.NonCompliantTerminations
        $complianceRate = if ($Statistics.TotalTerminatedInSF -gt 0) { 
            [math]::Round(($Statistics.CompliantTerminations / $Statistics.TotalTerminatedInSF) * 100, 1)
        } else { 
            100 
        }
        
        $subject = "SAP SuccessFactors Termination Compliance Report - $($nonCompliantCount) Non-Compliant Users"
        $body = @"
SAP SuccessFactors Termination Compliance Report

Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

Summary:
- Total Terminated Users: $($Statistics.TotalTerminatedInSF)
- Compliant Terminations: $($Statistics.CompliantTerminations)  
- Non-Compliant Terminations: $($Statistics.NonCompliantTerminations)
- Compliance Rate: $complianceRate%

$(if ($nonCompliantCount -gt 0) { "⚠️  ATTENTION: $nonCompliantCount terminated users still have active accounts!" } else { "✅ All terminated users have been properly disabled." })

Recommendations:
$(foreach ($rec in $Statistics.RecommendedActions) { "• $rec`n" })

Please review the detailed report for specific remediation actions.
"@
        
        # Log the notification details (actual email sending would require configuration)
        Write-Log "Notification prepared for: $EmailAddress"
        Write-Log "Subject: $subject"
        Write-Log "Non-compliant users: $nonCompliantCount"
        Write-Log "Compliance rate: $complianceRate%"
        
        # TODO: Implement actual email sending based on your environment
        # This could use Send-MailMessage, Send-MgUserMessage, or other email solutions
        
    } catch {
        Write-Log "Failed to send compliance notification: $($_.Exception.Message)" -Level Error
    }
}

# Main execution
try {
    Write-Log "Starting SAP SuccessFactors termination verification..."
    
    # Validate parameters
    if ($OutputFormat -ne 'Console' -and -not $ExportPath) {
        throw "ExportPath is required when OutputFormat is not Console"
    }
    
    # Connect to SAP SuccessFactors
    $sfHeaders = Connect-ToSuccessFactors -Endpoint $SuccessFactorsEndpoint -ClientId $ClientId -ClientSecret $ClientSecret -CompanyId $CompanyId
    
    # Get terminated users from SuccessFactors
    $terminatedUsers = Get-SuccessFactorsTerminatedUsers -Endpoint $SuccessFactorsEndpoint -Headers $sfHeaders -CompanyId $CompanyId -GracePeriodDays $GracePeriodDays
    
    # Get active users if requested
    $activeUsers = Get-SuccessFactorsActiveUsers -Endpoint $SuccessFactorsEndpoint -Headers $sfHeaders -CompanyId $CompanyId
    
    if ($terminatedUsers.Count -eq 0 -and $activeUsers.Count -eq 0) {
        Write-Log "No users found in SAP SuccessFactors" -Level Warning
        return
    }
    
    # Connect to Microsoft Graph
    Connect-ToMicrosoftGraph -TenantId $TenantId
    
    # Get all user principal names
    $allUserPrincipalNames = @()
    $allUserPrincipalNames += $terminatedUsers | ForEach-Object { $_.email -or "$($_.username)@$($env:USERDNSDOMAIN)" }
    $allUserPrincipalNames += $activeUsers | ForEach-Object { $_.email -or "$($_.username)@$($env:USERDNSDOMAIN)" }
    $allUserPrincipalNames = $allUserPrincipalNames | Sort-Object -Unique
    
    # Get users from Entra ID and Active Directory
    $entraUsers = Get-EntraIDUsers -UserPrincipalNames $allUserPrincipalNames
    $adUsers = Get-ActiveDirectoryUsers -UserPrincipalNames $allUserPrincipalNames
    
    # Compare user status
    $comparisonResult = Compare-UserStatus -SFTerminatedUsers $terminatedUsers -SFActiveUsers $activeUsers -EntraUsers $entraUsers -ADUsers $adUsers
    
    # Auto-remediate if requested
    $remediationResults = $null
    if ($AutoRemediate) {
        $nonCompliantUsers = $comparisonResult.Results | Where-Object { $_.ComplianceStatus -eq 'Non-Compliant' -and $_.UserType -eq 'Terminated' }
        if ($nonCompliantUsers.Count -gt 0) {
            $remediationResults = Invoke-AutoRemediation -NonCompliantUsers $nonCompliantUsers
        }
    }
    
    # Export report
    Export-ComplianceReport -Results $comparisonResult.Results -Statistics $comparisonResult.Statistics -Format $OutputFormat -Path $ExportPath
    
    # Send notification if configured
    if ($NotificationEmail) {
        Send-ComplianceNotification -Results $comparisonResult.Results -Statistics $comparisonResult.Statistics -EmailAddress $NotificationEmail
    }
    
    Write-Log "SAP SuccessFactors termination verification completed successfully"
    
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
