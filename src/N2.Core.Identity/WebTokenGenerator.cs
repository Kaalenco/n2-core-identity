using Microsoft.IdentityModel.Tokens;

using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

namespace N2.Core.Identity;

#pragma warning disable CA1725
// Using ct and not token for CancellationToken parameter names in async methods
// is a common convention in .NET, and it is more concise. The CA1725 warning is not relevant in this context.

public class WebTokenGenerator : IWebTokenGenerator {
    private readonly string audience;
    private readonly string issuer;
    private readonly byte[] secret;
    private readonly int refreshTokenExpirationInMinutes;

    public WebTokenGenerator(JwtSettings jwtSettings) {
        ArgumentNullException.ThrowIfNull(jwtSettings);
        this.secret = Convert.FromBase64String(jwtSettings.Secret);
        this.issuer = jwtSettings.Issuer;
        this.audience = jwtSettings.Audience;
        this.refreshTokenExpirationInMinutes = jwtSettings.RefreshTokenExpirationInMinutes;
    }

    public WebTokenGenerator(string issuer, string audience, string securityKey) {
        this.secret = Convert.FromBase64String(securityKey);
        this.issuer = issuer;
        this.audience = audience;
        this.refreshTokenExpirationInMinutes = JwtSettings.DefaultRefreshTokenExpirationInMinutes;
    }

    public string GenerateWebToken(IUserContext userContext, int timeoutInMinutes) {
        ArgumentNullException.ThrowIfNull(userContext);

        secret.ValidateKeySecurity();
        SigningCredentials credentials = new(new SymmetricSecurityKey(secret), SecurityAlgorithms.HmacSha256);

        ArgumentException.ThrowIfNullOrEmpty(issuer);
        ArgumentException.ThrowIfNullOrEmpty(audience);
        if (timeoutInMinutes > 15) {
            throw new ArgumentOutOfRangeException(nameof(timeoutInMinutes), "Timeout must be between 1 and 15 minutes.");
        }

        List<Claim> claims =
        [
            new(ClaimTypes.NameIdentifier, userContext.PublicId.ToString())
        ];
        if (!string.IsNullOrEmpty(userContext.Name)) {
            claims.Add(new(ClaimTypes.GivenName, userContext.Name));
        }
        if (!string.IsNullOrEmpty(userContext.Email)) {
            claims.Add(new(ClaimTypes.Email, userContext.Email));
        }
        if (!string.IsNullOrEmpty(userContext.PhoneNumber)) {
            claims.Add(new(ClaimTypes.MobilePhone, userContext.PhoneNumber));
        }
        foreach (var membership in userContext.TenantMemberships ?? []) {
            claims.Add(new Claim(N2ClaimTypes.TenantMembership,
                $"{membership.TenantId}:{membership.TenantName}"));
            foreach (var role in membership.Roles) {
                claims.Add(new Claim(N2ClaimTypes.TenantRole,
                    $"{membership.TenantId}:{role}"));
            }
        }

        if (timeoutInMinutes < 1) {
            timeoutInMinutes = 1;
        }

        // Use UTC time for all JWT timestamps
        var now = DateTime.UtcNow;
        var expiration = now.AddMinutes(timeoutInMinutes);

        // Add standard JWT claims
        claims.Add(new Claim(
            JwtRegisteredClaimNames.Jti,
            Guid.NewGuid().ToString())); // Token ID for revocation
        claims.Add(new Claim(JwtRegisteredClaimNames.Iat,
            new DateTimeOffset(now).ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture), ClaimValueTypes.Integer64)); // Issued at

        JwtSecurityToken token = new(
            issuer,
            audience,
            claims,
            expires: expiration,
            signingCredentials: credentials);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    public string GenerateRefreshToken()
        => Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));

    public DateTime RefreshTokenExpiry()
        => DateTime.UtcNow.AddMinutes(refreshTokenExpirationInMinutes);
}