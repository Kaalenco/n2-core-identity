using Microsoft.Extensions.Logging;

using N2.Core.Commands;
using N2.Core.Identity.Commands;
using N2.Core.Identity.Data;
using N2.Core.Identity.Models;

using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace N2.Core.Identity.Services;

/// <summary>
/// Concrete implementation of <see cref="ISecretManager"/> that manages the full lifecycle
/// of <c>ApplicationSecret</c> records. Constructed directly by the manager classes
/// (<see cref="N2UserManager"/>, <see cref="N2ApplicationManager"/>, <see cref="N2TenantManager"/>)
/// so no separate DI registration is required.
/// </summary>
public class N2SecretManager : ISecretManager {

    private readonly IIdentityContextFactory factory;
    private readonly DatabaseProvider provider;
    private readonly string connectionName;
    private readonly AuthenticationConfig configuration;
    private readonly ILogger logger;
    private readonly IChangeLogWriter? changeLogWriter;
    private readonly IVaultCallerContext? callerContext;

    /// <summary>
    /// Initializes a new instance of <see cref="N2SecretManager"/>.
    /// </summary>
    public N2SecretManager(
        IIdentityContextFactory factory,
        DatabaseProvider provider,
        string connectionName,
        AuthenticationConfig configuration,
        ILogger logger,
        IChangeLogWriter? changeLogWriter = null,
        IVaultCallerContext? callerContext = null) {
        this.factory = factory;
        this.provider = provider;
        this.connectionName = connectionName;
        this.configuration = configuration;
        this.logger = logger;
        this.changeLogWriter = changeLogWriter;
        this.callerContext = callerContext;
    }

    private Task<IIdentityContext> CreateContext(CancellationToken ct) =>
        factory.Create(provider, connectionName, ct);

    // -------------------------------------------------------------------------
    // Token helpers
    // -------------------------------------------------------------------------

    private void Log(Guid referenceId, string message) {
        changeLogWriter?.Add(new QueueLogEntry {
            LogRecordId = Guid.NewGuid(),
            TableName = nameof(ApplicationSecret),
            ReferenceId = referenceId,
            Message = message,
            CreatedBy = callerContext?.CallerId ?? Guid.Empty,
            CreatedByName = callerContext?.CallerName ?? "system",
            Created = DateTime.UtcNow
        });
    }

    private string ComputeHmac(string plainToken) {
        var keyBytes = Convert.FromBase64String(configuration.TokenSigningSecret);
        var tokenBytes = Encoding.UTF8.GetBytes(plainToken);
        var hmacBytes = HMACSHA256.HashData(keyBytes, tokenBytes);
        return Base64UrlExtensions.Encode(hmacBytes);
    }

    // -------------------------------------------------------------------------
    // Secret lifecycle
    // -------------------------------------------------------------------------

    /// <inheritdoc/>
    public async Task<ICommandResponse<SecretCreateResultDto>> Create(
        [NotNull] ISecretOwner owner,
        [NotNull] CreateSecretDto request,
        CancellationToken ct) {
        ArgumentNullException.ThrowIfNull(owner);
        ArgumentNullException.ThrowIfNull(request);
        ArgumentException.ThrowIfNullOrWhiteSpace(request.Name);

        var randomBytes = RandomNumberGenerator.GetBytes(32);
        var ownerIdBytes = owner.Id.ToByteArray();
        var plainToken = $"{Base64UrlExtensions.Encode(ownerIdBytes)}.{owner.Type}.{Base64UrlExtensions.Encode(randomBytes)}";
        var hashedToken = ComputeHmac(plainToken);
        var encryptionSalt = RandomNumberGenerator.GetBytes(32);

        using var ctx = await CreateContext(ct);

        byte[]? encryptedValue = null;
        if (request.Value != null) {
            var ownerSecret = await GetOwnerKeyMaterial(owner.Id, owner.Type, ctx, ct);
            if (ownerSecret == null) {
                Log(owner.Id, "Secret create failed: owner key material not found");
                return new SecretCreateResponse(ResponseStatus.NotFound, $"Owner '{owner.Id}' key material not found.");
            }
            encryptedValue = EncryptSecret(request.Value, ownerSecret, hashedToken, encryptionSalt);
        }

        var secret = new ApplicationSecret {
            Id = Guid.NewGuid(),
            ReferenceId = owner.Id,
            ReferenceType = owner.Type,
            Name = request.Name,
            NormalizedName = request.Name.Trim().ToUpperInvariant(),
            HashedToken = hashedToken,
            Expiration = request.Expiration,
            Description = request.Description,
            EncryptionSalt = encryptionSalt,
            Secret = encryptedValue,
            KeyVersion = configuration.SecretEncryptionKeyVersion
        };

        ctx.SecretAdd(secret);
        (var code, var message) = await ctx.Complete(ct);

        if (code != ResponseStatus.Success) {
            Log(secret.Id, $"Secret create failed: {message}");
            return new SecretCreateResponse(code, message ?? string.Empty);
        }

        Log(secret.Id, $"Secret created: {request.Name}");
        return new SecretCreateResponse(new SecretCreateResultDto {
            Id = secret.Id,
            PlainToken = plainToken,
            Expiration = request.Expiration
        });
    }

    /// <inheritdoc/>
    public async Task<ICommandResponse> Revoke(
        [NotNull] ISecretOwner owner,
        Guid secretId,
        CancellationToken ct) {
        ArgumentNullException.ThrowIfNull(owner);

        using var ctx = await CreateContext(ct);
        var secret = await ctx.SecretFindRecord(secretId, ct);

        // Guid equality compares 16 bytes with no short-circuit path — no timing side-channel.
        // FixedTimeEquals is not needed here; it is reserved for HMAC/token comparisons (Validate, SetValue).
        if (secret == null || secret.ReferenceId != owner.Id || secret.ReferenceType != owner.Type) {
            return new RequestResult(ResponseStatus.NotFound, $"Secret '{secretId}' not found");
        }

        ctx.SecretDelete(secret);
        (var code, var message) = await ctx.Complete(ct);

        if (code == ResponseStatus.Success) Log(secretId, "Secret revoked");
        else Log(secretId, $"Secret revoke failed: {message}");

        return new RequestResult(code, message ?? string.Empty);
    }

    /// <inheritdoc/>
    public async Task<ICommandResponse> SetValue(
            string plainToken,
            string? value,
            CancellationToken ct) {
        if (TryParseToken(plainToken) is not { } owner) return new RequestResult(ResponseStatus.NotFound, string.Empty);
        var hashedToken = ComputeHmac(plainToken);

        using var ctx = await CreateContext(ct);
        var secret = await ctx.SecretFindRecord(hashedToken, ct);
        if (secret == null) return new RequestResult(ResponseStatus.NotFound, string.Empty);

        if (RejectionReason(secret, owner.OwnerId, owner.OwnerTypeCode) != null) {
            return new RequestResult(ResponseStatus.NotFound, string.Empty);
        }

        if (!await TryApplyValue(secret, value, owner, hashedToken, ctx, ct)) {
            Log(secret.Id, "Secret value update failed: owner key material not found");
            return new RequestResult(ResponseStatus.NotFound, string.Empty);
        }

        (var code, var message) = await ctx.Complete(ct);

        if (code == ResponseStatus.Success) Log(secret.Id, "Secret value updated");
        else Log(secret.Id, $"Secret value update failed: {message}");

        return new RequestResult(code, message ?? string.Empty);
    }

    // -------------------------------------------------------------------------
    // Validation
    // -------------------------------------------------------------------------

    /// <inheritdoc/>
    public async Task<ICommandResponse<ApplicationSecretDto>> Validate(
        string plainToken,
        CancellationToken ct) {
        if (TryParseToken(plainToken) is not { } owner) return new SecretResponse();
        var hashedToken = ComputeHmac(plainToken);

        using var ctx = await CreateContext(ct);
        var secret = await ctx.SecretFindRecord(hashedToken, ct);
        if (secret == null) return new SecretResponse();

        var rejection = RejectionReason(secret, owner.OwnerId, owner.OwnerTypeCode);
        if (rejection != null) {
            Log(secret.Id, $"Secret validation failed: {rejection}");
            return new SecretResponse();
        }

        // Decrypt and return the stored value when present
        var (decrypted, secretValue, failure) = await TryDecryptPayload(secret, owner, hashedToken, ctx, ct);
        if (!decrypted) {
            Log(secret.Id, $"Secret validation failed: {failure}");
            return new SecretResponse();
        }

        Log(secret.Id, "Secret validated");
        return new SecretResponse(new ApplicationSecretDto {
            Id = secret.Id,
            Name = secret.Name,
            Expiration = secret.Expiration,
            Description = secret.Description,
            Payload = secretValue
        });
    }

    // -------------------------------------------------------------------------
    // Lookup
    // -------------------------------------------------------------------------

    /// <inheritdoc/>
    public async Task<ApplicationSecretDto?> FindById(
        [NotNull] ISecretOwner owner,
        Guid secretId,
        CancellationToken ct) {
        ArgumentNullException.ThrowIfNull(owner);

        using var ctx = await CreateContext(ct);
        var secret = await ctx.SecretFindRecord(secretId, ct);

        // Guid equality compares 16 bytes with no short-circuit path — no timing side-channel.
        // FixedTimeEquals is not needed here; it is reserved for HMAC/token comparisons (Validate, SetValue).
        if (secret == null || secret.ReferenceId != owner.Id || secret.ReferenceType != owner.Type) {
            return null;
        }

        return new ApplicationSecretDto {
            Id = secret.Id,
            Name = secret.Name,
            Expiration = secret.Expiration,
            Description = secret.Description
        };
    }

    /// <inheritdoc/>
    public async Task<SelectItemList<HtmlString>> GetSelectList(
        [NotNull] ISecretOwner owner,
        CancellationToken ct) {
        ArgumentNullException.ThrowIfNull(owner);

        using var ctx = await CreateContext(ct);
        return await ctx.SecretGetSelectList(owner.Id, owner.Type, ct);
    }

    // -------------------------------------------------------------------------
    // Policy management
    // -------------------------------------------------------------------------

    /// <inheritdoc/>
    public async Task<T?> GetPolicy<T>(
        [NotNull] ISecretOwner owner,
        Guid secretId,
        CancellationToken ct) {
        ArgumentNullException.ThrowIfNull(owner);

        using var ctx = await CreateContext(ct);
        var secret = await ctx.SecretFindRecord(secretId, ct);

        // Guid equality compares 16 bytes with no short-circuit path — no timing side-channel.
        // FixedTimeEquals is not needed here; it is reserved for HMAC/token comparisons (Validate, SetValue).
        if (secret == null || secret.ReferenceId != owner.Id || secret.ReferenceType != owner.Type) {
            return default;
        }

        if (string.IsNullOrEmpty(secret.Policies)) return default;

        return JsonSerializer.Deserialize<T>(secret.Policies);
    }

    /// <inheritdoc/>
    public async Task<ICommandResponse> SetPolicy<T>(
        [NotNull] ISecretOwner owner,
        Guid secretId,
        [NotNull] T policy,
        CancellationToken ct) {
        ArgumentNullException.ThrowIfNull(owner);
        ArgumentNullException.ThrowIfNull(policy);

        using var ctx = await CreateContext(ct);
        var secret = await ctx.SecretFindRecord(secretId, ct);

        // Guid equality compares 16 bytes with no short-circuit path — no timing side-channel.
        // FixedTimeEquals is not needed here; it is reserved for HMAC/token comparisons (Validate, SetValue).
        if (secret == null || secret.ReferenceId != owner.Id || secret.ReferenceType != owner.Type) {
            return new RequestResult(ResponseStatus.NotFound, $"Secret '{secretId}' not found");
        }

        secret.Policies = JsonSerializer.Serialize(policy);
        (var code, var message) = await ctx.Complete(ct);
        return new RequestResult(code, message ?? string.Empty);
    }

    // -------------------------------------------------------------------------
    // Private crypto helpers
    // -------------------------------------------------------------------------

    /// <summary>
    /// Parses the owner part of a plain token (<c>{ownerId}.{ownerType}.{random}</c>).
    /// Returns <c>null</c> when the token is empty or malformed.
    /// </summary>
    private static (Guid OwnerId, string OwnerTypeCode)? TryParseToken(string plainToken) {
        if (string.IsNullOrEmpty(plainToken)) return null;

        var parts = plainToken.Split('.');
        if (parts.Length != 3) return null;

        var ownerIdBytes = Base64UrlExtensions.TryDecode(parts[0]);
        if (ownerIdBytes == null || ownerIdBytes.Length != 16) return null;

        return (new Guid(ownerIdBytes), parts[1]);
    }

    /// <summary>
    /// Returns why <paramref name="secret"/> may not be used by the token owner, or <c>null</c>
    /// when it may. The ownership check is constant-time.
    /// </summary>
    private static string? RejectionReason(ApplicationSecret secret, Guid ownerId, string ownerTypeCode) {
        if (!CryptographicOperations.FixedTimeEquals(
                secret.ReferenceId.ToByteArray(),
                ownerId.ToByteArray()) ||
            secret.ReferenceType != ownerTypeCode) {
            return "ownership mismatch";
        }
        if (secret.Expiration.HasValue && secret.Expiration.Value < DateTime.UtcNow) {
            return "expired";
        }
        return null;
    }

    /// <summary>
    /// Encrypts <paramref name="value"/> into <paramref name="secret"/>, or clears the stored value
    /// when <paramref name="value"/> is <c>null</c>.
    /// </summary>
    /// <returns><c>false</c> when the owner key material could not be found.</returns>
    private async Task<bool> TryApplyValue(
        ApplicationSecret secret,
        string? value,
        (Guid OwnerId, string OwnerTypeCode) owner,
        string hashedToken,
        IIdentityContext ctx,
        CancellationToken ct) {
        if (value == null) {
            secret.Secret = null;
            return true;
        }

        var ownerSecret = await GetOwnerKeyMaterial(owner.OwnerId, owner.OwnerTypeCode, ctx, ct);
        if (ownerSecret == null) return false;

        // Fresh salt on every update: distinct ciphertexts for the same value across calls
        var newSalt = RandomNumberGenerator.GetBytes(32);
        secret.EncryptionSalt = newSalt;
        secret.Secret = EncryptSecret(value, ownerSecret, hashedToken, newSalt);
        secret.KeyVersion = configuration.SecretEncryptionKeyVersion;
        return true;
    }

    /// <summary>
    /// Decrypts the stored payload of <paramref name="secret"/> when it has one.
    /// </summary>
    /// <returns>
    /// <c>Success</c> false with a failure reason when the key material is missing or decryption
    /// fails; otherwise true with the payload (<c>null</c> when nothing is stored).
    /// </returns>
    private async Task<(bool Success, string? Value, string? Failure)> TryDecryptPayload(
        ApplicationSecret secret,
        (Guid OwnerId, string OwnerTypeCode) owner,
        string hashedToken,
        IIdentityContext ctx,
        CancellationToken ct) {
        if (secret.Secret == null || secret.EncryptionSalt == null) {
            return (true, null, null);
        }

        var ownerSecret = await GetOwnerKeyMaterial(owner.OwnerId, owner.OwnerTypeCode, ctx, ct);
        if (ownerSecret == null) {
            return (false, null, "owner key material not found");
        }
#pragma warning disable CA1031 // Do not catch general exception types - any crypto-related exception is a validation failure
        try {
            var plaintext = DecryptSecret(secret, ownerSecret, hashedToken);
            return (true, plaintext != null ? Encoding.UTF8.GetString(plaintext) : null, null);
        } catch {
            return (false, null, "decryption error");
        }
#pragma warning restore CA1031
    }

    private byte[] EncryptSecret(string value, byte[] ownerSecret, string hashedToken, byte[] encryptionSalt) {
        if (string.IsNullOrEmpty(configuration.SecretEncryptionKey)) {
            throw new CryptographicException("SecretEncryptionKey is not configured.");
        }

        var systemSecret = Convert.FromBase64String(configuration.SecretEncryptionKey);
        var info = ownerSecret.Concat(Encoding.UTF8.GetBytes(hashedToken)).ToArray();
        var key = HKDF.DeriveKey(HashAlgorithmName.SHA256, systemSecret, 32, encryptionSalt, info);

        var plaintext = Encoding.UTF8.GetBytes(value);
        var nonce = RandomNumberGenerator.GetBytes(12);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[16];

        using var aes = new AesGcm(key, 16);
        aes.Encrypt(nonce, plaintext, ciphertext, tag);

        // Stored format: nonce (12 bytes) + auth tag (16 bytes) + ciphertext
        return [.. nonce, .. tag, .. ciphertext];
    }

    private byte[]? DecryptSecret(ApplicationSecret secret, byte[] ownerSecret, string hashedToken) {
        if (string.IsNullOrEmpty(configuration.SecretEncryptionKey)) {
            throw new CryptographicException("SecretEncryptionKey is not configured.");
        }

        var systemSecret = Convert.FromBase64String(configuration.SecretEncryptionKey);
        var info = ownerSecret.Concat(Encoding.UTF8.GetBytes(hashedToken)).ToArray();
        var key = HKDF.DeriveKey(HashAlgorithmName.SHA256, systemSecret, 32, secret.EncryptionSalt, info);

        // Stored format: nonce (12 bytes) + auth tag (16 bytes) + ciphertext
        var encrypted = secret.Secret!;
        if (encrypted.Length < 28) {
            throw new CryptographicException("Invalid ciphertext: too short.");
        }

        var nonce = encrypted[..12];
        var tag = encrypted[12..28];
        var ciphertext = encrypted[28..];
        var plaintext = new byte[ciphertext.Length];

        using var aes = new AesGcm(key, 16);
        aes.Decrypt(nonce, ciphertext, tag, plaintext);
        return plaintext;
    }

    private static async Task<byte[]?> GetOwnerKeyMaterial(
        Guid ownerId,
        string ownerTypeCode,
        IIdentityContext ctx,
        CancellationToken ct) {
        if (ownerTypeCode == OwnerTypeCode.User) {
            var user = await ctx.UserFindRecord(ownerId, ct);
            return user?.SecretKeyMaterial;
        }
        if (ownerTypeCode == OwnerTypeCode.Application) {
            var app = await ctx.ApplicationFindRecord(ownerId, ct);
            return app?.SecretKeyMaterial;
        }
        if (ownerTypeCode == OwnerTypeCode.Tenant) {
            var tenant = await ctx.TenantFindRecord(ownerId, ct);
            return tenant?.SecretKeyMaterial;
        }
        return null;
    }
}
