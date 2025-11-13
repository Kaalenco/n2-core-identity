namespace N2.Core.Identity;

public sealed class JwtSettings {
    public string Secret { get; set; } = string.Empty;
    public string Audience { get; set; } = string.Empty;
    public string Issuer { get; set; } = string.Empty;

    /// <summary>
    /// The scheme to use for authentication. Default is Bearer, but it can be set in the configuration.
    /// </summary>
    public string AuthenticateScheme { get; set; } = "bearer";

    /// <summary>
    /// The scheme to use for challenge / response. Default is Bearer, but it can be set in the configuration.
    /// </summary>
    public string ChallengeScheme { get; set; } = "bearer";

    public int TokenExpirationInMinutes { get; set; } = 5;

    public int RefreshTokenExpirationInMinutes { get; set; } = 1440; // 24 hours

    public int PreAuthTokenExpirationInMinutes { get; set; } = 60;
}
