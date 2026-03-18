namespace N2.Core.Identity.Models;

/// <summary>
/// Request parameters for creating a new secret.
/// </summary>
public class CreateSecretDto {
    /// <summary>Human-readable display name for the secret.</summary>
    public string Name { get; init; } = null!;

    /// <summary>UTC expiry time, or <c>null</c> if the secret should never expire.</summary>
    public DateTime? Expiration { get; init; }

    /// <summary>Optional description of the secret's purpose.</summary>
    public string? Description { get; init; }

    /// <summary>
    /// The secret payload to encrypt and store (e.g. connection string, API key, base secret).
    /// Stored as AES-256-GCM ciphertext. May be <c>null</c> for token-only secrets.
    /// </summary>
    public string? Value { get; init; }
}
