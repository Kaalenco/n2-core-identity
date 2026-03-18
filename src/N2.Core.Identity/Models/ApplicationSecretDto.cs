using N2.Core.Identity.Services;

namespace N2.Core.Identity.Models;

/// <summary>
/// A read-only view of an <c>ApplicationSecret</c>.
/// The <see cref="Payload"/> property is only populated when retrieved via
/// <see cref="ISecretManager.ValidateAsync"/>, which authenticates and decrypts in one step.
/// </summary>
public class ApplicationSecretDto {
    /// <summary>Unique identifier of the secret record.</summary>
    public Guid Id { get; init; }

    /// <summary>Human-readable display name for the secret.</summary>
    public string? Name { get; init; }

    /// <summary>UTC expiry time, or <c>null</c> if the secret never expires.</summary>
    public DateTime? Expiration { get; init; }

    /// <summary>Optional description of the secret's purpose.</summary>
    public string? Description { get; init; }

    /// <summary>
    /// Decrypted secret payload. Only populated when retrieved via
    /// <see cref="ISecretManager.ValidateAsync"/>; <c>null</c> for metadata-only lookups
    /// or when no value was stored.
    /// </summary>
    public string? Payload { get; init; }
}
