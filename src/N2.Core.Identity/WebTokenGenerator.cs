using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace N2.Core.Identity;

public class WebTokenGenerator : IWebTokenGenerator
{
    private readonly string audience;
    private readonly string issuer;
    private readonly SymmetricSecurityKey securityKey;

    public WebTokenGenerator(string issuer, string audience, string securityKey)
    {
        var byteData = Encoding.UTF8.GetBytes(securityKey);
        this.issuer = issuer;
        this.audience = audience;
        this.securityKey = new SymmetricSecurityKey(byteData);
    }

    public string GenerateWebToken(IUserContext userContext, int timeoutInMinutes)
    {
        Contracts.Requires(userContext, nameof(userContext));
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, userContext.UserName)
        };
        foreach (var role in userContext.CurrentRoles())
        {
            claims.Add(new Claim(ClaimTypes.Role, role));
        }

#if DEBUG
        if (timeoutInMinutes <= 0) timeoutInMinutes = 14400;
#endif
        if (timeoutInMinutes <= 5) timeoutInMinutes = 5;
        if (timeoutInMinutes > 1440) timeoutInMinutes = 1440;

        var token = new JwtSecurityToken(
            issuer,
            audience,
            claims,
            expires: DateTime.Now.AddMinutes(timeoutInMinutes),
            signingCredentials: credentials);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}