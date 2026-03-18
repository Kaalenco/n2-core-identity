namespace N2.Core.Identity.Models;

/// <summary>
/// Returned once on secret creation. <see cref="PlainToken"/> is never stored and cannot be recovered after this point.
/// </summary>
public class SecretCreateResultDto {
    /// <summary>Unique identifier of the created secret record.</summary>
    public Guid Id { get; init; }

    /// <summary>
    /// The authentication credential to hand to the caller. Store it securely — it will not be retrievable again.
    /// </summary>
    /// <remarks>
    /// Format: <c>{base64url(ownerId)}.{ownerTypeCode}.{base64url(randomBytes)}</c>.
    /// <para>
    /// This token is a <b>lookup credential only</b>. It does not encode, derive from, or reveal
    /// anything about the secret value stored in <c>ApplicationSecret.Secret</c>.
    /// The token's length is fixed for a given <c>ownerType</c> and is independent of the
    /// secret value's size, so an observer cannot infer the secret value from the token length.
    /// </para>
    /// <para>
    /// The owner identity embedded in the token allows <c>ISecretManager.ValidateAsync</c>
    /// to resolve the correct owner and its key material without any additional context from the caller.
    /// </para>
    /// </remarks>
    public string PlainToken { get; init; } = null!;

    /// <summary>UTC expiry time, or <c>null</c> if the secret never expires.</summary>
    public DateTime? Expiration { get; init; }
}
