using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

using N2.Core.Identity.Data;
using N2.Core.Identity.Services;

using System.Security.Cryptography;

namespace N2.Core.Identity.UnitTests;

[TestClass]
public class UsingRotateMfaSecrets {

    // Two independent 256-bit keys used across all tests.
    private static readonly string PrimaryKey = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
    private static readonly string SecondaryKey = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));

    /// <summary>
    /// Builds a <see cref="N2UserManager"/> wired to an isolated in-memory database and the
    /// supplied MFA key pair.
    /// </summary>
    /// <remarks>
    /// Replaces <see cref="IConfiguration"/> with a complete set of required keys so that
    /// <c>N2UserManager</c> can resolve <c>AuthenticationConfig</c> at construction time via
    /// <c>IConfiguration.GetAuthenticationConfig()</c>.
    /// </remarks>
    private static (ServiceProvider ServiceProvider, N2UserManager Manager) BuildManager(
        string primaryKey,
        string? secondaryKey = null) {

        ServiceCollection services = new();
        TestContext.ConfigureServices(services);

        // Build a replacement IConfiguration that contains all keys required by N2UserManager,
        // plus our MFA-specific overrides. Replacing only the MFA keys would drop required
        // fields (e.g. TokenSigningSecret) and cause the constructor to throw.
        var fullConfig = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> {
                ["AuthenticationConfig:TokenSigningSecret"] = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
                ["AuthenticationConfig:SecretEncryptionKey"] = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
                ["AuthenticationConfig:MfaTokenSecret"]     = primaryKey,
                ["AuthenticationConfig:MfaTokenSecret2"]    = secondaryKey ?? string.Empty,
                ["AuthenticationConfig:JwtSettings:Secret"]   = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
                ["AuthenticationConfig:JwtSettings:Issuer"]   = "http://localhost:8080",
                ["AuthenticationConfig:JwtSettings:Audience"] = "http://localhost:8081",
            })
            .Build();

        services.Replace(ServiceDescriptor.Singleton<IConfiguration>(fullConfig));
        services.Replace(ServiceDescriptor.Singleton(fullConfig.GetAuthenticationConfig()));

        var provider = services.BuildServiceProvider();
        var manager = (N2UserManager)provider.GetRequiredService<IUserManager<ApplicationUser>>();
        return (provider, manager);
    }

    /// <summary>
    /// Seeds a user whose <c>MfaSecret</c> is encrypted with <paramref name="encryptedWithKey"/>
    /// using the proper <see cref="IIdentityContext.UserAdd"/> write path.
    /// </summary>
    private static async Task<ApplicationUser> SeedUserWithMfaSecretAsync(
        IIdentityContextFactory factory,
        string plainSecret,
        string encryptedWithKey) {

        using var ctx = await factory.CreateAsync();
        var user = new ApplicationUser {
            Id = Guid.NewGuid(),
            UserName = $"mfa.user.{Guid.NewGuid()}@test.com",
            NormalizedUserName = $"MFA.USER.{Guid.NewGuid()}@TEST.COM",
            MfaSecret = MfaSecretEncryption.Encrypt(plainSecret, encryptedWithKey),
        };
        await ctx.UserAdd(user, CancellationToken.None);
        await ctx.Complete();
        return user;
    }

    // -------------------------------------------------------------------------
    // Guard: missing secondary key
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task RotateMfaSecretsAsync_ThrowsWhenMfaTokenSecret2IsEmpty() {
        // Arrange — no secondary key configured
        var (provider, manager) = BuildManager(PrimaryKey, secondaryKey: null);
        await using var _ = provider;

        // Act & Assert
            await Assert.ThrowsAsync<InvalidOperationException>(
            () => manager.RotateMfaSecretsAsync());
    }

    // -------------------------------------------------------------------------
    // Happy path: users encrypted with secondary key are rotated
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task RotateMfaSecretsAsync_RotatesSecretsEncryptedWithSecondaryKey() {
        // Arrange
        var (provider, manager) = BuildManager(PrimaryKey, SecondaryKey);
        await using var _ = provider;

        var factory = provider.GetRequiredService<IIdentityContextFactory>();
        const string plainSecret = "JBSWY3DPEHPK3PXP";

        // Encrypt the secret with the *old* (secondary) key — simulates pre-rotation state.
        var user = await SeedUserWithMfaSecretAsync(factory, plainSecret, SecondaryKey);
        var originalCiphertext = user.MfaSecret;

        // Act
        var rotated = await manager.RotateMfaSecretsAsync();

        // Assert
        Assert.AreEqual(1, rotated, "Exactly one secret should have been rotated.");

        // Verify the stored value has changed and decrypts correctly with the primary key.
        using var ctx = await factory.CreateAsync();
        var updated = await ctx.UserFindRecord(user.Id, CancellationToken.None);
        Assert.IsNotNull(updated);
        Assert.AreNotEqual(originalCiphertext, updated.MfaSecret, "Ciphertext should have changed.");

        var decrypted = MfaSecretEncryption.TryDecrypt(updated.MfaSecret, PrimaryKey);
        Assert.AreEqual(plainSecret, decrypted, "Secret must decrypt correctly with the primary key.");
    }

    // -------------------------------------------------------------------------
    // Idempotency: already-primary-key users are left unchanged
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task RotateMfaSecretsAsync_SkipsUsersAlreadyEncryptedWithPrimaryKey() {
        // Arrange
        var (provider, manager) = BuildManager(PrimaryKey, SecondaryKey);
        await using var _ = provider;

        var factory = provider.GetRequiredService<IIdentityContextFactory>();

        // Encrypt with the *primary* key — already up-to-date.
        await SeedUserWithMfaSecretAsync(factory, "JBSWY3DPEHPK3PXP", PrimaryKey);

        // Act
        var rotated = await manager.RotateMfaSecretsAsync();

        // Assert
        Assert.AreEqual(0, rotated, "No secrets should be rotated when already current.");
    }

    // -------------------------------------------------------------------------
    // Resilience: decryption failure skips the user and does not throw
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task RotateMfaSecretsAsync_SkipsAndLogsWhenDecryptionFails() {
        // Arrange — store a value that neither key can decrypt.
        var (provider, manager) = BuildManager(PrimaryKey, SecondaryKey);
        await using var _ = provider;

        var factory = provider.GetRequiredService<IIdentityContextFactory>();
        using var ctx = await factory.CreateAsync();

        var user = new ApplicationUser {
            Id = Guid.NewGuid(),
            UserName = $"bad.mfa.{Guid.NewGuid()}@test.com",
            NormalizedUserName = $"BAD.MFA.{Guid.NewGuid()}@TEST.COM",
            // v1: prefix but garbage payload — passes the EF filter, fails AES-GCM authentication.
            MfaSecret = "v1:" + Convert.ToBase64String(RandomNumberGenerator.GetBytes(64)),
        };
        await ctx.UserAdd(user, CancellationToken.None);
        await ctx.Complete();

        // Act — must not throw
        var rotated = await manager.RotateMfaSecretsAsync();

        // Assert
        Assert.AreEqual(0, rotated, "Corrupted secret should be skipped, not counted.");
    }

    // -------------------------------------------------------------------------
    // Boundary: users without an MFA secret are ignored
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task RotateMfaSecretsAsync_IgnoresUsersWithoutMfaSecret() {
        // Arrange
        var (provider, manager) = BuildManager(PrimaryKey, SecondaryKey);
        await using var _ = provider;

        var factory = provider.GetRequiredService<IIdentityContextFactory>();
        using var ctx = await factory.CreateAsync();

        await ctx.UserAdd(new ApplicationUser {
            Id = Guid.NewGuid(),
            UserName = $"nomfa.{Guid.NewGuid()}@test.com",
            NormalizedUserName = $"NOMFA.{Guid.NewGuid()}@TEST.COM",
            MfaSecret = null,
        }, CancellationToken.None);
        await ctx.Complete();

        // Act
        var rotated = await manager.RotateMfaSecretsAsync();

        // Assert
        Assert.AreEqual(0, rotated, "Users without an MFA secret must be ignored.");
    }

    // -------------------------------------------------------------------------
    // Bulk: mixed users — only stale ones are rotated
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task RotateMfaSecretsAsync_OnlyRotatesStaleSecrets_WhenMixed() {
        // Arrange
        var (provider, manager) = BuildManager(PrimaryKey, SecondaryKey);
        await using var _ = provider;

        var factory = provider.GetRequiredService<IIdentityContextFactory>();
        const string plain = "MIXED_SECRET_TEST";

        // One user already on the primary key, two on the secondary (old) key.
        await SeedUserWithMfaSecretAsync(factory, plain, PrimaryKey);
        await SeedUserWithMfaSecretAsync(factory, plain, SecondaryKey);
        await SeedUserWithMfaSecretAsync(factory, plain, SecondaryKey);

        // Act
        var rotated = await manager.RotateMfaSecretsAsync();

        // Assert
        Assert.AreEqual(2, rotated, "Only the two stale secrets should be rotated.");
    }
}