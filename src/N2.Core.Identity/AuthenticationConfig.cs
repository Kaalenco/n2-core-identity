namespace N2.Core.Identity;

public sealed class AuthenticationConfig {
    public const string SectionName = nameof(AuthenticationConfig);

    public string PasswordPepper { get; set; } = string.Empty;
    public string TwoFactorTotpName { get; set; } = "N2Identity";
    public string Program2ProgramSecret { get; set; } = string.Empty;
    public int Program2ProgramTimeMarginInMinutes { get; set; } = 2;

    // Account lockout settings
    public int MaxFailedAccessAttempts { get; set; } = 5;
    public int LockoutDurationMinutes { get; set; } = 15;
    public bool EnableAccountLockout { get; set; } = true;

    /// <summary>
    /// The settings for the JWT token.
    /// </summary>
    public JwtSettings JwtSettings { get; set; } = new();
}
