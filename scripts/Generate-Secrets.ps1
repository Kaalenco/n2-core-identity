#Requires -Version 5.1
<#
.SYNOPSIS
    Generates cryptographically secure Base64 secrets for N2.Core.Identity configuration.

.DESCRIPTION
    Outputs ready-to-use values for AuthenticationConfig:
      - TokenSigningSecret   (HMAC-SHA256 JWT signing key)
      - MfaTokenSecret       (AES-256-GCM MFA secret encryption key)
      - MfaTokenSecret2      (optional — previous key during key rotation)

    Each value is 32 random bytes encoded as Base64 (256 bits of entropy).

.EXAMPLE
    .\Generate-Secrets.ps1

.EXAMPLE
    # Pipe directly into user-secrets
    .\Generate-Secrets.ps1 | dotnet user-secrets set TokenSigningSecret
#>

function New-Secret {
    [System.Convert]::ToBase64String(
        [System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32)
    )
}

$tokenSigningSecret = New-Secret
$mfaTokenSecret     = New-Secret
$mfaTokenSecret2    = New-Secret

Write-Host ""
Write-Host "Generated secrets for AuthenticationConfig:" -ForegroundColor Cyan
Write-Host ""
Write-Host "  TokenSigningSecret : $tokenSigningSecret" -ForegroundColor Green
Write-Host "  MfaTokenSecret     : $mfaTokenSecret"     -ForegroundColor Green
Write-Host "  MfaTokenSecret2    : $mfaTokenSecret2  (only needed during key rotation)" -ForegroundColor DarkGray
Write-Host ""
Write-Host "Store these in user secrets (development) or a secrets manager (production)." -ForegroundColor Yellow
Write-Host ""
Write-Host "User-secrets commands:" -ForegroundColor Cyan
Write-Host "  dotnet user-secrets set ""AuthenticationConfig:TokenSigningSecret"" ""$tokenSigningSecret"" --project src/N2.Core.Identity"
Write-Host "  dotnet user-secrets set ""AuthenticationConfig:MfaTokenSecret""     ""$mfaTokenSecret""     --project src/N2.Core.Identity"
Write-Host ""
