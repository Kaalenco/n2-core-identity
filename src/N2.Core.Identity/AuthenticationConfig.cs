using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace N2.Core.Identity;

public sealed class AuthenticationConfig {
    public const string SectionName = nameof(AuthenticationConfig);

    public string TwoFactorTotpName { get; set; } = "N2Identity";
    public string Program2ProgramSecret { get; set; } = string.Empty;
    public int Program2ProgramTimeMarginInMinutes { get; set; } = 2;

    // Account lockout settings
    public int MaxFailedAccessAttempts { get; set; } = 5;
    public int LockoutDurationMinutes { get; set; } = 15;
    public bool EnableAccountLockout { get; set; } = true;

    public int MfaMaxAttempts { get; set; } = 5;
    public int MfaLockoutMinutes { get; set; } = 15;

    /// <summary>
    /// Secret key for HMAC-based token signing. MUST be at least 32 bytes (256 bits).
    /// Generate using: Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
    /// Store in secure configuration (Azure Key Vault, AWS Secrets Manager, etc.)
    /// </summary>
    public string TokenSigningSecret { get; set; } = string.Empty;

    /// <summary>
    /// Secret key for MFA tokens in the user scope. MUST be at least 32 bytes (256 bits).
    /// Generate using: Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
    /// Store in secure configuration (Azure Key Vault, AWS Secrets Manager, etc.)
    /// </summary>
    public string MfaTokenSecret { get; set; } = string.Empty;

    // for key rotation, this is the "old" MFA token secret that can still validate tokens for a short grace period after rotation
    public string MfaTokenSecret2 { get; set; } = string.Empty;

    /// <summary>
    /// The settings for the JWT token.
    /// </summary>
    public JwtSettings JwtSettings { get; set; } = new();
}

public static class AuthenticationExtensions {
    public static AuthenticationConfig GetAuthenticationConfig(this IServiceProvider serviceProvider) {
        var configuration = serviceProvider.GetRequiredService<IConfiguration>();
        return configuration.GetAuthenticationConfig();
    }

    public static AuthenticationConfig GetAuthenticationConfig(this IConfiguration configuration) {
        var authConfig = new AuthenticationConfig();
        var appConfigSection = configuration?.GetSection(AuthenticationConfig.SectionName);
        if (appConfigSection != null) {
            appConfigSection.Bind(authConfig);
        }
        return authConfig;
    }
}