using Microsoft.IdentityModel.Tokens;

using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace N2.Core.Identity;

public class WebTokenGenerator : IWebTokenGenerator {
    private readonly string audience;
    private readonly string issuer;
    private readonly SymmetricSecurityKey securityKey;

    public WebTokenGenerator(string issuer, string audience, string securityKey) {
        var byteData = Encoding.UTF8.GetBytes(securityKey);
        this.issuer = issuer;
        this.audience = audience;
        this.securityKey = new SymmetricSecurityKey(byteData);
    }

    public string GenerateWebToken(IUserContext userContext, int timeoutInMinutes) {
        ArgumentNullException.ThrowIfNull(userContext);
        SigningCredentials credentials = new(securityKey, SecurityAlgorithms.HmacSha256);
        List<Claim> claims = new()
        {
            new(ClaimTypes.NameIdentifier, userContext.PublicId.ToString())
        };
        foreach (var role in userContext.CurrentRoles()) {
            claims.Add(new Claim(ClaimTypes.Role, role));
        }

#if DEBUG
        if (timeoutInMinutes <= 0) {
            timeoutInMinutes = 14400;
        }
#endif
        if (timeoutInMinutes <= 5) {
            timeoutInMinutes = 5;
        }

        if (timeoutInMinutes > 1440) {
            timeoutInMinutes = 1440;
        }

        JwtSecurityToken token = new(
            issuer,
            audience,
            claims,
            expires: DateTime.UtcNow.AddMinutes(timeoutInMinutes),
            signingCredentials: credentials);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}