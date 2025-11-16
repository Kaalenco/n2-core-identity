using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;

using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;

namespace N2.Core.Identity;

public static class JwtExtensions {
    private const string PathForAudience = "Jwt:Audience";
    private const string PathForIssuer = "Jwt:Issuer";
    private const string PathForKey = "Jwt:Secret";
    // Minimum key length for HMAC-SHA256 (256 bits = 32 bytes)
    private const int MinimumKeyLengthBytes = 32;

    public static IHostApplicationBuilder AddJwtBearerAuthentication([NotNull] this IHostApplicationBuilder builder) {
        var services = builder.Services;

        var issuer = builder.Configuration[PathForIssuer];
        var audience = builder.Configuration[PathForAudience];
        var key = builder.Configuration[PathForKey];

        ArgumentException.ThrowIfNullOrEmpty(issuer, PathForIssuer);
        ArgumentException.ThrowIfNullOrEmpty(audience, PathForAudience);
        ArgumentException.ThrowIfNullOrEmpty(key, PathForKey);

        if (key.Length < MinimumKeyLengthBytes) {
            var message = $"JWT signing key must be at least {MinimumKeyLengthBytes} bytes (256 bits) for HMAC-SHA256 security. " +
                $"Current length: {key.Length} bytes ({key.Length * 8} bits). " +
                Environment.NewLine +
                $"Generate a secure key using: Convert.ToBase64String(RandomNumberGenerator.GetBytes({MinimumKeyLengthBytes}))" +
                Environment.NewLine +
                "NIST SP 800-57 requires 256-bit keys for HMAC operations.";
            throw new ArgumentException(message ?? "JWT signing key too short.");
        }

        // Optional: Validate key entropy (warn about weak keys)
        if (HasLowEntropy(key)) {
            throw new ArgumentException(
                "JWT signing key appears to have low entropy. " +
                "Use a cryptographically secure random key generator. " +
                "Do NOT use dictionary words, common phrases, or predictable patterns."
            );
        }

        var symKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key));

        services
            .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(options => {
                options.TokenValidationParameters = new TokenValidationParameters {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = issuer,
                    ValidAudience = audience,
                    IssuerSigningKey = symKey,
                    ClockSkew = TimeSpan.FromMinutes(5) // Allow 5 minutes clock skew
                };
            });
        services.AddAuthorization();
        services.AddSingleton<IWebTokenGenerator>(new WebTokenGenerator(issuer, audience, key));
        return builder;
    }

    public static IUserContext? HttpCurrentUser(this IHttpContextAccessor httpContext) {
        var principal = httpContext?.HttpContext?.User;
        if (principal == null) {
            return null;
        }
        return new IdentityUserContext(principal);
    }

    /// <summary>
    /// Helper method to generate a cryptographically secure JWT signing key.
    /// </summary>
    public static string GenerateSecureKey(this AuthenticationConfig config, int lengthInBytes = MinimumKeyLengthBytes) {
        ArgumentNullException.ThrowIfNull(config);

        if (lengthInBytes < MinimumKeyLengthBytes) {
            throw new ArgumentException(
                $"Key length must be at least {MinimumKeyLengthBytes} bytes",
                nameof(lengthInBytes)
            );
        }

        var randomBytes = RandomNumberGenerator.GetBytes(lengthInBytes);
        return Convert.ToBase64String(randomBytes);
    }

    /// <summary>
    /// Performs basic entropy check on the key to detect weak patterns.
    /// </summary>
    private static bool HasLowEntropy(string key) {
        // Check for repeated characters
        var uniqueChars = key.Distinct().Count();
        var repetitionRatio = (double)uniqueChars / key.Length;

        // If less than 50% unique characters, likely low entropy
        if (repetitionRatio < 0.5) {
            return true;
        }

        // Check for sequential patterns (e.g., "123456", "abcdef")
        var sequentialCount = 0;
        for (var i = 1; i < key.Length; i++) {
            if (Math.Abs(key[i] - key[i - 1]) == 1) {
                sequentialCount++;
            }
        }

        // If more than 70% sequential, likely weak
        if (sequentialCount > key.Length * 0.7) {
            return true;
        }

        return false;
    }
}