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

    /// <summary>
    /// Initializes a new instance of <see cref="N2SecretManager"/>.
    /// </summary>
    public N2SecretManager(
        IIdentityContextFactory factory,
        DatabaseProvider provider,
        string connectionName,
        AuthenticationConfig configuration,
        ILogger logger) {
        this.factory = factory;
        this.provider = provider;
        this.connectionName = connectionName;
        this.configuration = configuration;
        this.logger = logger;
    }

    private Task<IIdentityContext> CreateContextAsync() =>
        factory.CreateAsync(provider, connectionName);

    // -------------------------------------------------------------------------
    // Token helpers
    // -------------------------------------------------------------------------

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
    public async Task<ICommandResponse<SecretCreateResultDto>> CreateAsync(
        [NotNull] ISecretOwner owner,
        [NotNull] CreateSecretDto request,
        CancellationToken token) {
        ArgumentNullException.ThrowIfNull(owner);
        ArgumentNullException.ThrowIfNull(request);
        ArgumentException.ThrowIfNullOrWhiteSpace(request.Name);

        var randomBytes = RandomNumberGenerator.GetBytes(32);
        var ownerIdBytes = owner.Id.ToByteArray();
        var plainToken = $"{Base64UrlExtensions.Encode(ownerIdBytes)}.{owner.Type}.{Base64UrlExtensions.Encode(randomBytes)}";
        var hashedToken = ComputeHmac(plainToken);
        var encryptionSalt = RandomNumberGenerator.GetBytes(32);

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
            Secret = null
        };

        using var ctx = await CreateContextAsync();
        await ctx.SecretAdd(secret, token);
        (var code, var message) = await ctx.Complete();

        if (code != ResponseStatus.Success) {
            return new SecretCreateResponse(code, message ?? string.Empty);
        }

        return new SecretCreateResponse(new SecretCreateResultDto {
            Id = secret.Id,
            PlainToken = plainToken,
            Expiration = request.Expiration
        });
    }

    /// <inheritdoc/>
    public async Task<ICommandResponse> RevokeAsync(
        [NotNull] ISecretOwner owner,
        Guid secretId,
        CancellationToken token) {
        ArgumentNullException.ThrowIfNull(owner);

        using var ctx = await CreateContextAsync();
        var secret = await ctx.SecretFindRecord(secretId, token);

        if (secret == null || secret.ReferenceId != owner.Id || secret.ReferenceType != owner.Type) {
            return new RequestResult(ResponseStatus.NotFound, $"Secret '{secretId}' not found");
        }

        ctx.SecretDelete(secret);
        (var code, var message) = await ctx.Complete();
        return new RequestResult(code, message ?? string.Empty);
    }

    // -------------------------------------------------------------------------
    // Validation
    // -------------------------------------------------------------------------

    /// <inheritdoc/>
    public async Task<ICommandResponse<ApplicationSecretDto>> ValidateAsync(
        string plainToken,
        CancellationToken token) {
        if (string.IsNullOrEmpty(plainToken)) return new SecretResponse();

        var parts = plainToken.Split('.');
        if (parts.Length != 3) return new SecretResponse();

        var ownerIdBytes = Base64UrlExtensions.TryDecode(parts[0]);
        if (ownerIdBytes == null || ownerIdBytes.Length != 16) return new SecretResponse();

        var ownerId = new Guid(ownerIdBytes);
        var ownerTypeCode = parts[1];

        var hashedToken = ComputeHmac(plainToken);

        using var ctx = await CreateContextAsync();
        var secret = await ctx.SecretFindRecord(hashedToken, token);
        if (secret == null) return new SecretResponse();

        // Constant-time ownership check
        if (!CryptographicOperations.FixedTimeEquals(
                secret.ReferenceId.ToByteArray(),
                ownerId.ToByteArray()) ||
            secret.ReferenceType != ownerTypeCode) {
            return new SecretResponse();
        }

        // Expiration check
        if (secret.Expiration.HasValue && secret.Expiration.Value < DateTime.UtcNow) {
            return new SecretResponse(null);
        }

        // If an encrypted secret value is stored, validate decryption
        if (secret.Secret != null && secret.EncryptionSalt != null) {
            var ownerSecret = await GetOwnerKeyMaterial(ownerId, ownerTypeCode, ctx, token);
            if (ownerSecret == null) return new SecretResponse(null!, ResponseStatus.Forbidden);
#pragma warning disable CA1031 // Do not catch general exception types - we want to catch any crypto-related exceptions and treat them as validation failures
            try {
                DecryptSecret(secret, ownerSecret, hashedToken);
            } catch {
                return new SecretResponse(null!, ResponseStatus.Forbidden);
            }
#pragma warning restore CA1031
        }

        return new SecretResponse(new ApplicationSecretDto {
            Id = secret.Id,
            Name = secret.Name,
            Expiration = secret.Expiration,
            Description = secret.Description
        });
    }

    // -------------------------------------------------------------------------
    // Lookup
    // -------------------------------------------------------------------------

    /// <inheritdoc/>
    public async Task<ApplicationSecretDto?> FindByIdAsync(
        [NotNull] ISecretOwner owner,
        Guid secretId,
        CancellationToken token) {
        ArgumentNullException.ThrowIfNull(owner);

        using var ctx = await CreateContextAsync();
        var secret = await ctx.SecretFindRecord(secretId, token);

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
    public async Task<SelectItemList<HtmlString>> GetSelectListAsync(
        [NotNull] ISecretOwner owner,
        CancellationToken token) {
        ArgumentNullException.ThrowIfNull(owner);

        using var ctx = await CreateContextAsync();
        return await ctx.SecretGetSelectList(owner.Id, owner.Type, token);
    }

    // -------------------------------------------------------------------------
    // Policy management
    // -------------------------------------------------------------------------

    /// <inheritdoc/>
    public async Task<T?> GetPolicyAsync<T>(
        [NotNull] ISecretOwner owner,
        Guid secretId,
        CancellationToken token) {
        ArgumentNullException.ThrowIfNull(owner);

        using var ctx = await CreateContextAsync();
        var secret = await ctx.SecretFindRecord(secretId, token);

        if (secret == null || secret.ReferenceId != owner.Id || secret.ReferenceType != owner.Type) {
            return default;
        }

        if (string.IsNullOrEmpty(secret.Policies)) return default;

        return JsonSerializer.Deserialize<T>(secret.Policies);
    }

    /// <inheritdoc/>
    public async Task<ICommandResponse> SetPolicyAsync<T>(
        [NotNull] ISecretOwner owner,
        Guid secretId,
        [NotNull] T policy,
        CancellationToken token) {
        ArgumentNullException.ThrowIfNull(owner);
        ArgumentNullException.ThrowIfNull(policy);

        using var ctx = await CreateContextAsync();
        var secret = await ctx.SecretFindRecord(secretId, token);

        if (secret == null || secret.ReferenceId != owner.Id || secret.ReferenceType != owner.Type) {
            return new RequestResult(ResponseStatus.NotFound, $"Secret '{secretId}' not found");
        }

        secret.Policies = JsonSerializer.Serialize(policy);
        (var code, var message) = await ctx.Complete();
        return new RequestResult(code, message ?? string.Empty);
    }

    // -------------------------------------------------------------------------
    // Private crypto helpers
    // -------------------------------------------------------------------------

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
        CancellationToken token) {
        if (ownerTypeCode == OwnerTypeCode.User) {
            var user = await ctx.UserFindRecord(ownerId, token);
            return user?.SecretKeyMaterial;
        }
        if (ownerTypeCode == OwnerTypeCode.Application) {
            var app = await ctx.ApplicationFindRecord(ownerId, token);
            return app?.SecretKeyMaterial;
        }
        if (ownerTypeCode == OwnerTypeCode.Tenant) {
            var tenant = await ctx.TenantFindRecord(ownerId, token);
            return tenant?.SecretKeyMaterial;
        }
        return null;
    }
}
