namespace N2.Core.Identity.Models;

/// <summary>
/// Identifies the entity that owns a secret (user, application, tenant, etc.)
/// and provides its key material for HKDF-based encryption.
/// </summary>
public interface ISecretOwner {
    /// <summary>Unique identifier of the owning entity.</summary>
    Guid Id { get; }

    /// <summary>
    /// Opaque 4-character base64url type code derived from the owner's type name.
    /// Use <see cref="OwnerTypeCode.Compute"/> or the pre-computed constants in <see cref="OwnerTypeCode"/>.
    /// </summary>
    string Type { get; }

    /// <summary>
    /// Owner-specific key material combined with the system secret during HKDF key derivation.
    /// Must be at least 32 bytes of cryptographically random data.
    /// </summary>
    byte[] OwnerSecret { get; }
}

public record SecretOwner(Guid Id, string Type, byte[] OwnerSecret) : ISecretOwner;