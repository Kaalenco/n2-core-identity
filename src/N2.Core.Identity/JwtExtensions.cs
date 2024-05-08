using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;
using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace N2.Core.Identity;

public static class JwtExtensions
{
    private const string PathForAudience = "Jwt:Audience";
    private const string PathForIssuer = "Jwt:Issuer";
    private const string PathForKey = "Jwt:Secret";
    public static IHostApplicationBuilder AddJwtBearerAuthentication([NotNull] this IHostApplicationBuilder builder)
    {
        var services = builder.Services;

        var issuer = builder.Configuration[PathForIssuer];
        var audience = builder.Configuration[PathForAudience];
        var key = builder.Configuration[PathForKey];

        Contracts.Requires(issuer, PathForIssuer);
        Contracts.Requires(audience, PathForAudience);
        Contracts.Requires(key, PathForKey);
        Contracts.MinLength(key, 20, PathForKey);

        var symKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key));

        services
            .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(options =>
            {
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = issuer,
                    ValidAudience = audience,
                    IssuerSigningKey = symKey
                };
            });
        services.AddAuthorization();        
        services.AddSingleton<IWebTokenGenerator>(new WebTokenGenerator(issuer, audience, key));
        return builder;
    }

    public static IUserContext? HttpCurrentUser(this IHttpContextAccessor httpContext)
    {
        var principal = httpContext?.HttpContext?.User;
        if (principal == null)
        {
            return null;
        }
        return new IdentityUserContext(principal);
    }
}
