namespace N2.Core.Identity.Models;

/// <summary>
/// A safe, read-only view of an <c>ApplicationSecret</c> that exposes no sensitive material.
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
}
