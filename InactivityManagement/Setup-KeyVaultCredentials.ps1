# Setup-KeyVaultCredentials.ps1
# Helper script to configure Azure Key Vault credentials for multi-domain AD access

param(
    [Parameter(Mandatory = $true)]
    [array]$DomainConfigs,
    [switch]$TestAccess
)

<#
.SYNOPSIS
    Sets up Azure Key Vault credentials for multi-domain Active Directory access

.DESCRIPTION
    This script helps configure Azure Key Vault secrets for domain credentials used by the Disable-InactiveUsers script.
    It can create or update secrets and test domain connectivity.

.PARAMETER DomainConfigs
    Array of domain configuration objects with Name, KeyVaultName, CredentialSecretName, Username, and Password

.PARAMETER TestAccess
    Test access to domains using the stored credentials

.EXAMPLE
    $domains = @(
        @{Name="contoso.com"; KeyVaultName="kv-contoso"; CredentialSecretName="ad-admin-contoso"; Username="CONTOSO\svc-admin"; Password="P@ssw0rd123"},
        @{Name="fabrikam.com"; KeyVaultName="kv-fabrikam"; CredentialSecretName="ad-admin-fabrikam"; Username="FABRIKAM\svc-admin"; Password="P@ssw0rd456"}
    )
    .\Setup-KeyVaultCredentials.ps1 -DomainConfigs $domains

.EXAMPLE
    .\Setup-KeyVaultCredentials.ps1 -DomainConfigs $domains -TestAccess
#>

# Import required modules
try {
    Import-Module Az.KeyVault -ErrorAction Stop
    Import-Module Az.Accounts -ErrorAction Stop
    Import-Module ActiveDirectory -ErrorAction Stop
}
catch {
    Write-Error "Required modules not installed. Please install: Az.KeyVault, Az.Accounts, ActiveDirectory"
    exit 1
}

function Set-KeyVaultCredential {
    param(
        [string]$KeyVaultName,
        [string]$SecretName,
        [string]$Username,
        [string]$Password
    )
    
    try {
        Write-Host "Setting credential in Key Vault: $KeyVaultName, Secret: $SecretName" -ForegroundColor Yellow
        
        # Format: username|password
        $secretValue = "$Username|$Password"
        $secureSecretValue = ConvertTo-SecureString $secretValue -AsPlainText -Force
        
        # Set the secret
        Set-AzKeyVaultSecret -VaultName $KeyVaultName -Name $SecretName -SecretValue $secureSecretValue
        
        Write-Host "Successfully set credential for $Username" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to set credential in Key Vault: $($_.Exception.Message)"
        return $false
    }
    
    return $true
}

function Test-DomainCredential {
    param(
        [string]$DomainName,
        [string]$KeyVaultName,
        [string]$SecretName
    )
    
    try {
        Write-Host "Testing domain access: $DomainName" -ForegroundColor Yellow
        
        # Get the secret
        $secret = Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $SecretName -AsPlainText
        
        if (-not $secret) {
            Write-Error "Secret not found: $SecretName in $KeyVaultName"
            return $false
        }
        
        # Parse the secret
        $parts = $secret -split '\|'
        if ($parts.Length -ne 2) {
            Write-Error "Invalid secret format. Expected: username|password"
            return $false
        }
        
        $username = $parts[0]
        $password = $parts[1] | ConvertTo-SecureString -AsPlainText -Force
        $credential = New-Object System.Management.Automation.PSCredential($username, $password)
        
        # Test domain connection
        $testResult = Get-ADDomain -Identity $DomainName -Credential $credential -ErrorAction Stop
        
        Write-Host "Successfully connected to domain: $DomainName as $username" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error "Failed to connect to domain $DomainName : $($_.Exception.Message)"
        return $false
    }
}

# Main execution
Write-Host "=== Azure Key Vault Credential Setup ===" -ForegroundColor Cyan

# Ensure Azure connection
try {
    $context = Get-AzContext
    if (-not $context) {
        Write-Host "Connecting to Azure..." -ForegroundColor Yellow
        Connect-AzAccount
    }
    else {
        Write-Host "Using existing Azure context: $($context.Account.Id)" -ForegroundColor Green
    }
}
catch {
    Write-Error "Failed to connect to Azure: $($_.Exception.Message)"
    exit 1
}

if (-not $TestAccess) {
    Write-Host "`nSetting up Key Vault credentials..." -ForegroundColor Cyan
    
    foreach ($domainConfig in $DomainConfigs) {
        $domainName = $domainConfig.Name
        $keyVaultName = $domainConfig.KeyVaultName
        $secretName = $domainConfig.CredentialSecretName
        $username = $domainConfig.Username
        $password = $domainConfig.Password
        
        Write-Host "`nProcessing domain: $domainName" -ForegroundColor White
        
        # Validate required properties
        if (-not $domainName -or -not $keyVaultName -or -not $secretName -or -not $username -or -not $password) {
            Write-Error "Missing required properties for domain: $domainName"
            continue
        }
        
        # Check if Key Vault exists
        try {
            $keyVault = Get-AzKeyVault -VaultName $keyVaultName -ErrorAction Stop
            Write-Host "Key Vault found: $keyVaultName" -ForegroundColor Green
        }
        catch {
            Write-Error "Key Vault not found: $keyVaultName"
            continue
        }
        
        # Set the credential
        if (Set-KeyVaultCredential -KeyVaultName $keyVaultName -SecretName $secretName -Username $username -Password $password) {
            Write-Host "Credential configured successfully for domain: $domainName" -ForegroundColor Green
        }
        else {
            Write-Error "Failed to configure credential for domain: $domainName"
        }
    }
}
else {
    Write-Host "`nTesting domain access..." -ForegroundColor Cyan
    
    foreach ($domainConfig in $DomainConfigs) {
        $domainName = $domainConfig.Name
        $keyVaultName = $domainConfig.KeyVaultName
        $secretName = $domainConfig.CredentialSecretName
        
        Write-Host "`nTesting domain: $domainName" -ForegroundColor White
        
        if (Test-DomainCredential -DomainName $domainName -KeyVaultName $keyVaultName -SecretName $secretName) {
            Write-Host "Domain access test passed: $domainName" -ForegroundColor Green
        }
        else {
            Write-Host "Domain access test failed: $domainName" -ForegroundColor Red
        }
    }
}

Write-Host "`n=== Setup Complete ===" -ForegroundColor Cyan
Write-Host "IMPORTANT SECURITY NOTES:" -ForegroundColor Red
Write-Host "1. Ensure Key Vault access policies are properly configured" -ForegroundColor Yellow
Write-Host "2. Use managed identities when possible instead of service principals" -ForegroundColor Yellow
Write-Host "3. Enable Key Vault audit logging for security monitoring" -ForegroundColor Yellow
Write-Host "4. Regularly rotate domain service account passwords" -ForegroundColor Yellow
Write-Host "5. Use least privilege principles for domain service accounts" -ForegroundColor Yellow
