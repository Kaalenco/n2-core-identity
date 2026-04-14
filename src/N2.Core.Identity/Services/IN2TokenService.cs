using N2.Core.Identity.Models;

namespace N2.Core.Identity.Services;

/// <summary>
/// Issues and validates JWT access tokens and their accompanying refresh tokens.
/// </summary>
public interface IN2TokenService {
    /// <summary>
    /// Issues a JWT access token and a persistent refresh token for the given user context.
    /// </summary>
    Task<TokenPairResult> IssueTokenPair(IUserContext userContext, int timeoutInMinutes, CancellationToken ct);

    /// <summary>
    /// Validates the given refresh token and issues a new token pair.
    /// The old token is revoked atomically with the creation of the new one.
    /// Results are cached for a short grace window to handle retries and simultaneous calls
    /// without invalidating the token on duplicate requests.
    /// Returns <c>null</c> if the token is invalid, expired, or the user's security stamp has changed.
    /// </summary>
    Task<TokenPairResult?> Refresh(string refreshToken, CancellationToken ct);

    /// <summary>
    /// Revokes the given refresh token.
    /// Returns <c>true</c> if the token was found and revoked, <c>false</c> if it was not found or already revoked.
    /// </summary>
    Task<bool> RevokeRefreshToken(string refreshToken, CancellationToken ct);

    /// <summary>
    /// Reads the user ID from a JWT without validating its signature or lifetime.
    /// Intended for use at the refresh endpoint, where the caller presents an expired access
    /// token alongside a refresh token to identify the subject.
    /// Returns <c>null</c> if the token cannot be parsed or contains no subject claim.
    /// </summary>
    Guid? ReadUserIdFromExpiredToken(string token);

    /// <summary>
    /// Issues a short-lived JWT containing only the user's identity claims (no roles or tenant memberships).
    /// Intended for use after credential validation and before MFA confirmation.
    /// No refresh token is issued at this stage.
    /// </summary>
    Task<string> IssuePreAuthToken(IUserContext userContext, CancellationToken ct);

    /// <summary>
    /// Revokes all active refresh tokens for the given user, invalidating all sessions.
    /// The access token itself remains valid until it expires; the security stamp validation
    /// (when enabled) will reject it at the next request within the stamp validity window.
    /// Returns <c>true</c> if the operation completed successfully.
    /// </summary>
    Task<bool> Logoff(Guid userId, CancellationToken ct);
}
