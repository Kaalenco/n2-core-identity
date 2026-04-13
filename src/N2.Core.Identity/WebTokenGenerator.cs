using Microsoft.IdentityModel.Tokens;

using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace N2.Core.Identity;

public class WebTokenGenerator : IWebTokenGenerator {
    private readonly string audience;
    private readonly string issuer;
    private readonly byte[] secret;

    public WebTokenGenerator(JwtSettings jwtSettings) {
        ArgumentNullException.ThrowIfNull(jwtSettings);
        if(jwtSettings.Secret.Length < 16) {
            throw new ArgumentException("JWT secret must be at least 16 characters long.");
        }
        this.secret = Encoding.UTF8.GetBytes(jwtSettings.Secret);
        this.issuer = jwtSettings.Issuer;
        this.audience = jwtSettings.Audience;
    }

    public WebTokenGenerator(string issuer, string audience, string securityKey) {
        this.secret = Encoding.UTF8.GetBytes(securityKey);
        this.issuer = issuer;
        this.audience = audience;
    }

    public string GenerateWebToken(IUserContext userContext, int timeoutInMinutes) {
        ArgumentNullException.ThrowIfNull(userContext);

        secret.ValidateKeySecurity();
        SigningCredentials credentials = new(new SymmetricSecurityKey(secret), SecurityAlgorithms.HmacSha256);

        ArgumentException.ThrowIfNullOrEmpty(issuer);
        ArgumentException.ThrowIfNullOrEmpty(audience);

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

        if (timeoutInMinutes > 15) {
            timeoutInMinutes = 15;
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


}