using N2.Core.Commands;
using N2.Core.Identity.Models;

using System.Diagnostics.CodeAnalysis;

namespace N2.Core.Identity.Services;

/// <summary>
/// Manages the full lifecycle of <c>ApplicationSecret</c> records.
/// </summary>
/// <remarks>
/// <para><b>Token vs. secret value — they are orthogonal</b></para>
/// <para>
/// The <em>token</em> and the <em>secret value</em> are two completely independent concepts:
/// <list type="bullet">
///   <item>
///     <term>Token (<c>PlainToken</c>)</term>
///     <description>
///       A fixed-length authentication credential used to identify and look up a record.
///       It contains owner identity and cryptographically random bytes, but carries
///       <b>no information about the secret value</b>.
///       Its length is constant for a given <c>ownerType</c> regardless of what is stored in
///       <c>ApplicationSecret.Secret</c>. Knowing the token does not help an attacker
///       recover the secret value.
///     </description>
///   </item>
///   <item>
///     <term>Secret value (<c>ApplicationSecret.Secret</c>)</term>
///     <description>
///       An arbitrary encrypted payload stored in the database. It is encrypted with
///       AES-256-GCM and can only be decrypted by the implementation after successful
///       token validation. Its size has no bearing on the token.
///     </description>
///   </item>
/// </list>
/// </para>
/// <para><b>Token format</b></para>
/// <para>
/// Every plaintext token produced by <see cref="CreateAsync"/> is a dot-separated string:
/// <code>
///   {base64url(ownerId)}.{ownerTypeCode}.{base64url(randomBytes)}
/// </code>
/// <list type="bullet">
///   <item><term>ownerId</term><description>Base64url-encoded bytes of the owner's <see cref="Guid"/>.
///   <b>Note:</b> the owner identifier is embedded in plaintext (base64url). Callers must never log,
///   store in URLs, or expose tokens in contexts where the owner identity should remain private.</description></item>
///   <item><term>ownerTypeCode</term><description>An 8-character base64url code derived from <c>SHA-256(typeName)[0..5]</c> via <see cref="N2.Core.Identity.Models.OwnerTypeCode.Compute"/>. Opaque — does not reveal the type name.</description></item>
///   <item><term>randomBytes</term><description>Cryptographically random bytes (minimum 32) that constitute the token's entropy. These have no relation to the stored secret value.</description></item>
/// </list>
/// Embedding the owner identity in the token allows <see cref="ValidateAsync"/> to
/// resolve the correct owner record and its key material without any caller-supplied context.
/// The full token string is HMAC-SHA256 signed with <c>TokenSigningSecret</c> and the result
/// is stored in <c>ApplicationSecret.HashedToken</c>; the plaintext is never persisted.
/// Using HMAC instead of a plain hash ensures that an attacker with read-only database access
/// cannot pre-compute valid token hashes.
/// </para>
/// <para><b>Encryption of the secret value</b></para>
/// <para>
/// The secret value is encrypted with AES-256-GCM independently of the token.
/// The key is derived via HKDF using:
/// <list type="bullet">
///   <item><term>IKM</term><description>System secret (from configuration).</description></item>
///   <item><term>Salt</term><description>Per-record random bytes in <c>ApplicationSecret.EncryptionSalt</c>.</description></item>
///   <item><term>Info</term><description>Concatenation of the owner's <c>SecretKeyMaterial</c> and <c>HashedToken</c>,
///   binding the ciphertext to both this record and its owner.</description></item>
/// </list>
/// A database dump alone is insufficient to recover the plaintext secret value.
/// </para>
/// </remarks>
public interface ISecretManager {
    // -------------------------------------------------------------------------
    // Secret lifecycle
    // -------------------------------------------------------------------------

    /// <summary>
    /// Creates a new secret for the given owner.
    /// </summary>
    /// <remarks>
    /// Generates a fixed-length token of the form
    /// <c>{base64url(ownerId)}.{ownerTypeCode}.{base64url(randomBytes)}</c>.
    /// The random bytes are the sole source of entropy for the token; they bear no
    /// relationship to the secret value supplied in <paramref name="request"/>.
    /// The token is HMAC-SHA256 signed with <c>TokenSigningSecret</c> for storage.
    /// The secret value is encrypted separately with AES-256-GCM.
    /// The plaintext token is returned once in
    /// <see cref="SecretCreateResultDto.PlainToken"/> and cannot be recovered afterwards.
    /// </remarks>
    Task<ICommandResponse<SecretCreateResultDto>> CreateAsync(
        [NotNull] ISecretOwner owner,
        [NotNull] CreateSecretDto request,
        CancellationToken token);

    /// <summary>
    /// Revokes (permanently deletes) a secret belonging to the given owner.
    /// Returns <see cref="ResponseStatus.NotFound"/> if the secret does not exist
    /// or does not belong to <paramref name="owner"/>.
    /// </summary>
    Task<ICommandResponse> RevokeAsync(
        [NotNull] ISecretOwner owner,
        Guid secretId,
        CancellationToken token);

    /// <summary>
    /// Stores or replaces the encrypted value of an existing secret, authenticated by its plain token.
    /// </summary>
    /// <remarks>
    /// The plain token is the sole authentication credential — no owner context is required or accepted.
    /// On each call the value is re-encrypted with a fresh per-record salt, so repeated calls with the
    /// same value produce distinct ciphertexts.
    /// Passing <c>null</c> for <paramref name="value"/> clears any previously stored payload.
    /// Returns <see cref="ResponseStatus.NotFound"/> for unknown, tampered, or expired tokens
    /// without distinguishing the failure reason.
    /// </remarks>
    Task<ICommandResponse> SetValueAsync(
        string plainToken,
        string? value,
        CancellationToken token);

    // -------------------------------------------------------------------------
    // Validation
    // -------------------------------------------------------------------------

    /// <summary>
    /// Validates a plaintext token presented by a caller.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The token must follow the format
    /// <c>{base64url(ownerId)}.{ownerTypeCode}.{base64url(randomBytes)}</c>.
    /// The implementation parses the owner identity from the token itself — no caller-supplied
    /// owner context is needed or accepted, eliminating the possibility of owner-confusion attacks.
    /// Steps performed:
    /// <list type="number">
    ///   <item>Parse <c>ownerId</c> and <c>ownerType</c> from the token segments.</item>
    ///   <item>Look up the owner record to obtain its <c>SecretKeyMaterial</c>.</item>
    ///   <item>HMAC-SHA256 sign the full token with <c>TokenSigningSecret</c> and locate the
    ///   <c>ApplicationSecret</c> by <c>HashedToken</c>.</item>
    ///   <item>Verify <c>ReferenceId</c> and <c>ReferenceType</c> match the parsed owner.</item>
    ///   <item>Check the record has not expired.</item>
    ///   <item>Derive the AES-256-GCM key via HKDF and decrypt <c>ApplicationSecret.Secret</c>.</item>
    /// </list>
    /// Returns <see cref="ResponseStatus.NotFound"/> for unknown or expired tokens and
    /// <see cref="ResponseStatus.Forbidden"/> on ownership mismatch — both without
    /// distinguishing the failure reason to avoid leaking token existence.
    /// </para>
    /// <para><b>Rate limiting</b></para>
    /// <para>
    /// Callers are responsible for applying rate limiting and lockout policy before invoking this method.
    /// Implementations do not enforce per-IP or per-owner throttling internally. Repeated failed
    /// validation attempts should trigger back-off or revocation at the call site to prevent
    /// brute-force enumeration of token hashes.
    /// </para>
    /// </remarks>
    Task<ICommandResponse<ApplicationSecretDto>> ValidateAsync(
        string plainToken,
        CancellationToken token);

    // -------------------------------------------------------------------------
    // Lookup
    // -------------------------------------------------------------------------

    /// <summary>
    /// Returns the metadata for a single secret, or <c>null</c> if not found or not owned by <paramref name="owner"/>.
    /// </summary>
    Task<ApplicationSecretDto?> FindByIdAsync(
        [NotNull] ISecretOwner owner,
        Guid secretId,
        CancellationToken token);

    /// <summary>
    /// Returns a select list of all active (non-expired, named) secrets for the given owner.
    /// </summary>
    Task<SelectItemList<HtmlString>> GetSelectListAsync(
        [NotNull] ISecretOwner owner,
        CancellationToken token);

    // -------------------------------------------------------------------------
    // Policy management
    // -------------------------------------------------------------------------

    /// <summary>
    /// Deserialises the JSON policy payload stored on the secret into <typeparamref name="T"/>.
    /// Returns <c>null</c> if no policy is set, the secret does not exist, or the secret does not belong to <paramref name="owner"/>.
    /// </summary>
    Task<T?> GetPolicyAsync<T>(
        [NotNull] ISecretOwner owner,
        Guid secretId,
        CancellationToken token);

    /// <summary>
    /// Serialises <paramref name="policy"/> as JSON and persists it on the secret,
    /// overwriting any previously stored value.
    /// Returns <see cref="ResponseStatus.NotFound"/> if the secret does not exist or does not belong to <paramref name="owner"/>.
    /// </summary>
    Task<ICommandResponse> SetPolicyAsync<T>(
        [NotNull] ISecretOwner owner,
        Guid secretId,
        [NotNull] T policy,
        CancellationToken token);
}
