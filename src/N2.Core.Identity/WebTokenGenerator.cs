using Microsoft.IdentityModel.Tokens;

using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace N2.Core.Identity;

public class WebTokenGenerator : IWebTokenGenerator {
    private const int minimumKeyBytes = 32;
    private readonly string audience;
    private readonly string issuer;
    private readonly SymmetricSecurityKey securityKey;
    public WebTokenGenerator(JwtSettings jwtSettings) {
        ArgumentNullException.ThrowIfNull(jwtSettings);
        var byteData = Encoding.UTF8.GetBytes(jwtSettings.Secret);
        ValidateKeySize(byteData);
        this.issuer = jwtSettings.Issuer;
        this.audience = jwtSettings.Audience;

        this.securityKey = new SymmetricSecurityKey(byteData);
    }

    public WebTokenGenerator(string issuer, string audience, string securityKey) {
        var byteData = Encoding.UTF8.GetBytes(securityKey);
        ValidateKeySize(byteData);
        this.issuer = issuer;
        this.audience = audience;
        this.securityKey = new SymmetricSecurityKey(byteData);
    }

    public string GenerateWebToken(IUserContext userContext, int timeoutInMinutes) {
        ArgumentNullException.ThrowIfNull(userContext);
        SigningCredentials credentials = new(securityKey, SecurityAlgorithms.HmacSha256);

        ArgumentException.ThrowIfNullOrEmpty(issuer);
        ArgumentException.ThrowIfNullOrEmpty(audience);

        List<Claim> claims = new()
        {
            new(ClaimTypes.GivenName, userContext.Name),
            new(ClaimTypes.NameIdentifier, userContext.PublicId.ToString())
        };
        foreach (var role in userContext.CurrentRoles()) {
            claims.Add(new Claim(ClaimTypes.Role, role));
        }

        if (timeoutInMinutes < 0) {
            timeoutInMinutes = -1;
        }

        if (timeoutInMinutes > 1440) {
            timeoutInMinutes = 1440;
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
            expires: DateTime.UtcNow.AddMinutes(timeoutInMinutes),
            signingCredentials: credentials);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private static void ValidateKeySize(byte[] byteData) {
        // Validate key length for HMAC-SHA256 (256 bits minimum)
        if (byteData.Length < minimumKeyBytes) {
            throw new ArgumentException(
                $"JWT key is too short ({byteData.Length} bytes). HMAC-SHA256 requires at least {minimumKeyBytes} bytes (256 bits). " +
                $"This validation prevents cryptographically weak JWT tokens."
            );
        }
    }
}