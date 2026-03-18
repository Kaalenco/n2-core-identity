using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;

using Moq;

using N2.Core.Commands;
using N2.Core.Entity;
using N2.Core.Identity.Data;
using N2.Core.Identity.Models;
using N2.Core.Identity.Services;

using System.Security.Cryptography;

namespace N2.Core.Identity.UnitTests;

/// <summary>
/// Provider-agnostic integration tests for <see cref="N2SecretManager"/>.
/// Subclasses supply the target <see cref="Provider"/> and <see cref="ConnectionName"/>;
/// every <c>[TestMethod]</c> defined here is discovered and executed by each subclass.
/// All tests are self-contained: they create and clean up their own data.
/// </summary>
public abstract class N2SecretManagerIntegrationTestsBase {
    protected abstract DatabaseProvider Provider { get; }
    protected abstract string ConnectionName { get; }

    // -------------------------------------------------------------------------
    // Infrastructure helpers
    // -------------------------------------------------------------------------

    private static IConfiguration BuildConfiguration() =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> {
                // Secrets required by N2SecretManager / N2UserManager constructors
                ["AuthenticationConfig:TokenSigningSecret"] = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
                ["AuthenticationConfig:MfaTokenSecret"] = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
                ["AuthenticationConfig:JwtSettings:Secret"] = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
                ["AuthenticationConfig:JwtSettings:Issuer"] = "http://localhost:8080",
                ["AuthenticationConfig:JwtSettings:Audience"] = "http://localhost:8081",
            })
            .AddUserSecrets<N2IdentityContextIntegrationTestsBase>()
            .AddEnvironmentVariables()
            .Build();

    private static IIdentityContextFactory BuildFactory(IConfiguration configuration) {
        var mock = new Mock<IConnectionStringService>();
        mock.Setup(s => s.GetConnectionString(It.IsAny<string>()))
            .Returns((string name) => configuration.GetConnectionString(name) ?? string.Empty);
        return new N2IdentityContextFactory(mock.Object);
    }

    protected N2SecretManager BuildSecretManager() {
        var config = BuildConfiguration();
        var authConfig = config.GetAuthenticationConfig();
        var factory = BuildFactory(config);
        return new N2SecretManager(factory, Provider, ConnectionName, authConfig, NullLogger.Instance);
    }

    protected IUserManager<ApplicationUser> BuildUserManager() {
        var config = BuildConfiguration();
        var factory = BuildFactory(config);
        var options = new PasswordHasherOptions {
            CompatibilityMode = PasswordHasherCompatibilityMode.IdentityV3,
            IterationCount = 310000
        };
        var hasher = new PasswordHasher<ApplicationUser>(
            Microsoft.Extensions.Options.Options.Create(options));
        var rateLimiter = new Mock<IRateLimiter>().Object;
        return new N2UserManager(factory, config, rateLimiter, hasher, ConnectionName, NullLogger<N2UserManager>.Instance, Provider);
    }

    private async Task<N2IdentityContext> CreateAndMigrateContextAsync() {
        var config = BuildConfiguration();
        var factory = (N2IdentityContextFactory)BuildFactory(config);
        var context = (N2IdentityContext)await factory.CreateAsync(Provider, ConnectionName);
        await context.Database.MigrateAsync();
        return context;
    }

    // -------------------------------------------------------------------------
    // Test-data helpers
    // -------------------------------------------------------------------------

    /// <summary>
    /// Creates a fresh user with a 32-byte SecretKeyMaterial set and returns both
    /// the persisted <see cref="ApplicationUser"/> and its <see cref="ISecretOwner"/>.
    /// Callers are responsible for deleting the user in a finally block.
    /// </summary>
    protected async Task<(ApplicationUser user, ISecretOwner owner)> CreateUserWithKeyMaterialAsync() {
        using var userManager = BuildUserManager();
        var name = $"sec_int_{Guid.NewGuid():N}";
        var user = new ApplicationUser { UserName = name, Email = $"{name}@test.com" };
        var result = await userManager.CreateAsync(user, "TestPassword1!", CancellationToken.None);
        if (!result.Status.IsSuccess()) {
            throw new InvalidOperationException($"Failed to create user: {result.Message}");
        }

        var keyMaterial = RandomNumberGenerator.GetBytes(32);
        using var ctx = await CreateAndMigrateContextAsync();
        var found = await ctx.UserFindRecord(user.Id, CancellationToken.None);
        found!.SecretKeyMaterial = keyMaterial;
        await ctx.Complete();

        var owner = new SecretOwner(found.Id, OwnerTypeCode.User, keyMaterial);
        return (found, owner);
    }

    protected async Task DeleteUserAsync(ApplicationUser user) {
        ArgumentNullException.ThrowIfNull(user);
        using var ctx = await CreateAndMigrateContextAsync();
        var existing = await ctx.UserFindRecord(user.Id, CancellationToken.None);
        if (existing != null) {
            ctx.UserDelete(existing);
            await ctx.Complete();
        }
    }

    protected async Task DeleteSecretAsync(Guid secretId) {
        using var ctx = await CreateAndMigrateContextAsync();
        var existing = await ctx.SecretFindRecord(secretId, CancellationToken.None);
        if (existing != null) {
            ctx.SecretDelete(existing);
            await ctx.Complete();
        }
    }

    private static CreateSecretDto NewCreateDto(string? name = null, DateTime? expiration = null) => new() {
        Name = name ?? $"IntSecret_{Guid.NewGuid():N}",
        Expiration = expiration ?? DateTime.UtcNow.AddDays(30),
        Description = "Integration test secret"
    };

    // -------------------------------------------------------------------------
    // CreateAsync
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task CreateAsync_ValidOwnerAndRequest_ShouldSucceed() {
        var (user, owner) = await CreateUserWithKeyMaterialAsync();
        var manager = BuildSecretManager();

        var result = await manager.CreateAsync(owner, NewCreateDto(), CancellationToken.None);

        try {
            Assert.IsTrue(result.Status.IsSuccess());
            Assert.IsNotNull(result.Value);
            Assert.AreNotEqual(Guid.Empty, result.Value!.Id);
            Assert.IsFalse(string.IsNullOrEmpty(result.Value.PlainToken));
        } finally {
            await DeleteSecretAsync(result.Value?.Id ?? Guid.Empty);
            await DeleteUserAsync(user);
        }
    }

    [TestMethod]
    public async Task CreateAsync_PlainTokenHasThreeSegments() {
        var (user, owner) = await CreateUserWithKeyMaterialAsync();
        var manager = BuildSecretManager();

        var result = await manager.CreateAsync(owner, NewCreateDto(), CancellationToken.None);

        try {
            Assert.IsTrue(result.Status.IsSuccess());
            var parts = result.Value!.PlainToken.Split('.');
            Assert.AreEqual(3, parts.Length, "Token format must be <ownerIdB64>.<typeCode>.<randomB64>");
        } finally {
            await DeleteSecretAsync(result.Value?.Id ?? Guid.Empty);
            await DeleteUserAsync(user);
        }
    }

    [TestMethod]
    public async Task CreateAsync_SecretIsPersisted() {
        var (user, owner) = await CreateUserWithKeyMaterialAsync();
        var manager = BuildSecretManager();

        var result = await manager.CreateAsync(owner, NewCreateDto("Persisted"), CancellationToken.None);

        try {
            var found = await manager.FindByIdAsync(owner, result.Value!.Id, CancellationToken.None);
            Assert.IsNotNull(found);
            Assert.AreEqual("Persisted", found!.Name);
        } finally {
            await DeleteSecretAsync(result.Value?.Id ?? Guid.Empty);
            await DeleteUserAsync(user);
        }
    }

    // -------------------------------------------------------------------------
    // ValidateAsync
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task ValidateAsync_ValidToken_ShouldReturnSuccess() {
        var (user, owner) = await CreateUserWithKeyMaterialAsync();
        var manager = BuildSecretManager();
        var created = await manager.CreateAsync(owner, NewCreateDto(), CancellationToken.None);

        try {
            var result = await manager.ValidateAsync(created.Value!.PlainToken, CancellationToken.None);
            Assert.IsTrue(result.Status.IsSuccess());
            Assert.AreEqual(created.Value.Id, result.Value!.Id);
        } finally {
            await DeleteSecretAsync(created.Value?.Id ?? Guid.Empty);
            await DeleteUserAsync(user);
        }
    }

    [TestMethod]
    public async Task ValidateAsync_TamperedToken_ShouldReturnForbidden() {
        var (user, owner) = await CreateUserWithKeyMaterialAsync();
        var manager = BuildSecretManager();
        var created = await manager.CreateAsync(owner, NewCreateDto(), CancellationToken.None);
        var parts = created.Value!.PlainToken.Split('.');
        var tampered = $"{parts[0]}.{parts[1]}.{Base64UrlExtensions.Encode(RandomNumberGenerator.GetBytes(32))}";

        try {
            var result = await manager.ValidateAsync(tampered, CancellationToken.None);
            Assert.AreEqual(ResponseStatus.Forbidden, result.Status);
        } finally {
            await DeleteSecretAsync(created.Value.Id);
            await DeleteUserAsync(user);
        }
    }

    [TestMethod]
    public async Task ValidateAsync_ExpiredToken_ShouldReturnForbidden() {
        var (user, owner) = await CreateUserWithKeyMaterialAsync();
        var manager = BuildSecretManager();
        var created = await manager.CreateAsync(owner, NewCreateDto(expiration: DateTime.UtcNow.AddSeconds(-1)), CancellationToken.None);

        try {
            var result = await manager.ValidateAsync(created.Value!.PlainToken, CancellationToken.None);
            Assert.AreEqual(ResponseStatus.Forbidden, result.Status);
        } finally {
            await DeleteSecretAsync(created.Value?.Id ?? Guid.Empty);
            await DeleteUserAsync(user);
        }
    }

    [TestMethod]
    public async Task ValidateAsync_UnknownToken_ShouldReturnForbidden() {
        var manager = BuildSecretManager();
        // Build a syntactically valid but non-existent token
        var fakeOwner = new SecretOwner(Guid.NewGuid(), OwnerTypeCode.User, RandomNumberGenerator.GetBytes(32));
        var fakeToken = $"{Base64UrlExtensions.Encode(fakeOwner.Id.ToByteArray())}.{OwnerTypeCode.User}.{Base64UrlExtensions.Encode(RandomNumberGenerator.GetBytes(32))}";

        var result = await manager.ValidateAsync(fakeToken, CancellationToken.None);

        Assert.AreEqual(ResponseStatus.Forbidden, result.Status);
    }

    // -------------------------------------------------------------------------
    // RevokeAsync
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task RevokeAsync_ExistingSecret_ShouldSucceedAndMakeTokenInvalid() {
        var (user, owner) = await CreateUserWithKeyMaterialAsync();
        var manager = BuildSecretManager();
        var created = await manager.CreateAsync(owner, NewCreateDto(), CancellationToken.None);

        try {
            var revokeResult = await manager.RevokeAsync(owner, created.Value!.Id, CancellationToken.None);
            Assert.IsTrue(revokeResult.Status.IsSuccess());

            var validateResult = await manager.ValidateAsync(created.Value.PlainToken, CancellationToken.None);
            Assert.IsFalse(validateResult.Status.IsSuccess());
        } finally {
            // Secret already deleted by revoke, but cleanup user
            await DeleteUserAsync(user);
        }
    }

    [TestMethod]
    public async Task RevokeAsync_UnknownId_ShouldReturnNotFound() {
        var (user, owner) = await CreateUserWithKeyMaterialAsync();
        var manager = BuildSecretManager();

        try {
            var result = await manager.RevokeAsync(owner, Guid.NewGuid(), CancellationToken.None);
            Assert.AreEqual(ResponseStatus.NotFound, result.Status);
        } finally {
            await DeleteUserAsync(user);
        }
    }

    [TestMethod]
    public async Task RevokeAsync_WrongOwner_ShouldReturnNotFound() {
        var (user1, owner1) = await CreateUserWithKeyMaterialAsync();
        var (user2, owner2) = await CreateUserWithKeyMaterialAsync();
        var manager = BuildSecretManager();
        var created = await manager.CreateAsync(owner1, NewCreateDto(), CancellationToken.None);

        try {
            var result = await manager.RevokeAsync(owner2, created.Value!.Id, CancellationToken.None);
            Assert.AreEqual(ResponseStatus.NotFound, result.Status);

            // Secret should still be valid for the correct owner
            var validateResult = await manager.ValidateAsync(created.Value.PlainToken, CancellationToken.None);
            Assert.IsTrue(validateResult.Status.IsSuccess());
        } finally {
            await DeleteSecretAsync(created.Value?.Id ?? Guid.Empty);
            await DeleteUserAsync(user1);
            await DeleteUserAsync(user2);
        }
    }

    // -------------------------------------------------------------------------
    // FindByIdAsync
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task FindByIdAsync_ExistingSecret_ShouldReturnDto() {
        var (user, owner) = await CreateUserWithKeyMaterialAsync();
        var manager = BuildSecretManager();
        var created = await manager.CreateAsync(owner, NewCreateDto("FindMe"), CancellationToken.None);

        try {
            var found = await manager.FindByIdAsync(owner, created.Value!.Id, CancellationToken.None);
            Assert.IsNotNull(found);
            Assert.AreEqual(created.Value.Id, found!.Id);
            Assert.AreEqual("FindMe", found.Name);
        } finally {
            await DeleteSecretAsync(created.Value?.Id ?? Guid.Empty);
            await DeleteUserAsync(user);
        }
    }

    [TestMethod]
    public async Task FindByIdAsync_WrongOwner_ShouldReturnNull() {
        var (user1, owner1) = await CreateUserWithKeyMaterialAsync();
        var (user2, owner2) = await CreateUserWithKeyMaterialAsync();
        var manager = BuildSecretManager();
        var created = await manager.CreateAsync(owner1, NewCreateDto(), CancellationToken.None);

        try {
            var found = await manager.FindByIdAsync(owner2, created.Value!.Id, CancellationToken.None);
            Assert.IsNull(found);
        } finally {
            await DeleteSecretAsync(created.Value?.Id ?? Guid.Empty);
            await DeleteUserAsync(user1);
            await DeleteUserAsync(user2);
        }
    }

    // -------------------------------------------------------------------------
    // GetSelectListAsync
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task GetSelectListAsync_ActiveSecret_ShouldAppearInList() {
        var (user, owner) = await CreateUserWithKeyMaterialAsync();
        var manager = BuildSecretManager();
        var created = await manager.CreateAsync(owner, NewCreateDto(), CancellationToken.None);

        try {
            var list = await manager.GetSelectListAsync(owner, CancellationToken.None);
            Assert.IsTrue(list.Any(item => item.Key == created.Value!.Id));
        } finally {
            await DeleteSecretAsync(created.Value?.Id ?? Guid.Empty);
            await DeleteUserAsync(user);
        }
    }

    // -------------------------------------------------------------------------
    // GetPolicyAsync / SetPolicyAsync
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task SetAndGetPolicyAsync_RoundTrip_ShouldReturnCorrectValues() {
        var (user, owner) = await CreateUserWithKeyMaterialAsync();
        var manager = BuildSecretManager();
        var created = await manager.CreateAsync(owner, NewCreateDto(), CancellationToken.None);
        var policy = new IntTestPolicy { Scope = "read:write", MaxRequests = 250 };

        try {
            var setResult = await manager.SetPolicyAsync(owner, created.Value!.Id, policy, CancellationToken.None);
            Assert.IsTrue(setResult.Status.IsSuccess());

            var retrieved = await manager.GetPolicyAsync<IntTestPolicy>(owner, created.Value.Id, CancellationToken.None);
            Assert.IsNotNull(retrieved);
            Assert.AreEqual("read:write", retrieved!.Scope);
            Assert.AreEqual(250, retrieved.MaxRequests);
        } finally {
            await DeleteSecretAsync(created.Value?.Id ?? Guid.Empty);
            await DeleteUserAsync(user);
        }
    }

    [TestMethod]
    public async Task GetPolicyAsync_NoPolicy_ShouldReturnNull() {
        var (user, owner) = await CreateUserWithKeyMaterialAsync();
        var manager = BuildSecretManager();
        var created = await manager.CreateAsync(owner, NewCreateDto(), CancellationToken.None);

        try {
            var result = await manager.GetPolicyAsync<IntTestPolicy>(owner, created.Value!.Id, CancellationToken.None);
            Assert.IsNull(result);
        } finally {
            await DeleteSecretAsync(created.Value?.Id ?? Guid.Empty);
            await DeleteUserAsync(user);
        }
    }

    // -------------------------------------------------------------------------
    // Full lifecycle
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task FullLifecycle_CreateValidateRevokeValidate_ShouldFollowExpectedStatuses() {
        var (user, owner) = await CreateUserWithKeyMaterialAsync();
        var manager = BuildSecretManager();

        // Create
        var createResult = await manager.CreateAsync(owner, NewCreateDto(), CancellationToken.None);
        Assert.IsTrue(createResult.Status.IsSuccess());
        var plainToken = createResult.Value!.PlainToken;
        var secretId = createResult.Value.Id;

        try {
            // Validate → success
            var valid1 = await manager.ValidateAsync(plainToken, CancellationToken.None);
            Assert.IsTrue(valid1.Status.IsSuccess());

            // Set a policy
            await manager.SetPolicyAsync(owner, secretId, new IntTestPolicy { Scope = "admin" }, CancellationToken.None);
            var policy = await manager.GetPolicyAsync<IntTestPolicy>(owner, secretId, CancellationToken.None);
            Assert.AreEqual("admin", policy!.Scope);

            // Revoke
            var revokeResult = await manager.RevokeAsync(owner, secretId, CancellationToken.None);
            Assert.IsTrue(revokeResult.Status.IsSuccess());

            // Validate after revoke → forbidden
            var valid2 = await manager.ValidateAsync(plainToken, CancellationToken.None);
            Assert.IsFalse(valid2.Status.IsSuccess());
        } finally {
            // Secret already revoked; only clean up user
            await DeleteUserAsync(user);
        }
    }

    // -------------------------------------------------------------------------
    // Helper DTO for policy tests
    // -------------------------------------------------------------------------

    protected sealed class IntTestPolicy {
        public string Scope { get; set; } = string.Empty;
        public int MaxRequests { get; set; }
    }
}
