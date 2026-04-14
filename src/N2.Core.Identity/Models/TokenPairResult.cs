namespace N2.Core.Identity.Models;

/// <summary>
/// The result of a successful token issuance or refresh operation, containing
/// a short-lived JWT access token and a long-lived opaque refresh token.
/// </summary>
public sealed class TokenPairResult {
    public required string AccessToken { get; init; }
    public required string RefreshToken { get; init; }
    public DateTime RefreshTokenExpiresAt { get; init; }
}
