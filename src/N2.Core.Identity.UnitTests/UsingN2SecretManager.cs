using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;

using N2.Core.Commands;
using N2.Core.Identity.Data;
using N2.Core.Identity.Models;
using N2.Core.Identity.Services;

using System.Security.Cryptography;

namespace N2.Core.Identity.UnitTests;

[TestClass]
public class UsingN2SecretManager {
    private readonly ServiceProvider serviceProvider;

    public UsingN2SecretManager() {
        ServiceCollection serviceCollection = new();
        TestContext.ConfigureServices(serviceCollection);
        serviceProvider = serviceCollection.BuildServiceProvider();
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private N2SecretManager BuildSecretManager() {
        var config = serviceProvider.GetRequiredService<IConfiguration>();
        var factory = serviceProvider.GetRequiredService<IIdentityContextFactory>();
        var authConfig = config.GetAuthenticationConfig();
        return new N2SecretManager(factory, DatabaseProvider.SqlServer, "IdentityDb", authConfig, NullLogger.Instance);
    }

    private IUserManager<ApplicationUser> BuildUserManager() {
        var config = serviceProvider.GetRequiredService<IConfiguration>();
        var factory = serviceProvider.GetRequiredService<IIdentityContextFactory>();
        var hasher = serviceProvider.GetRequiredService<IPasswordHasher<ApplicationUser>>();
        var rateLimiter = serviceProvider.GetRequiredService<IRateLimiter>();
        return new N2UserManager(factory, config, rateLimiter, hasher, "IdentityDb", NullLogger<N2UserManager>.Instance);
    }

    /// <summary>Creates a user with SecretKeyMaterial set and returns both the user and its ISecretOwner.</summary>
    private async Task<(ApplicationUser user, ISecretOwner owner)> CreateUserWithKeyMaterialAsync() {
        using var userManager = BuildUserManager();
        var name = $"secret.user.{Guid.NewGuid():N}";
        ApplicationUser user = new() { UserName = name, Email = $"{name}@test.com" };
        var result = await userManager.Create(user, "TestPassword1!", CancellationToken.None);
        if (!result.Status.IsSuccess()) {
            throw new InvalidOperationException($"Failed to create user: {result.Message}");
        }

        // Directly set SecretKeyMaterial on the persisted record
        var keyMaterial = RandomNumberGenerator.GetBytes(32);
        var config = serviceProvider.GetRequiredService<IConfiguration>();
        var factory = serviceProvider.GetRequiredService<IIdentityContextFactory>();
        using var ctx = await factory.Create(DatabaseProvider.SqlServer, "IdentityDb", CancellationToken.None);
        var found = await ctx.UserFindRecord(user.Id, CancellationToken.None);
        found!.SecretKeyMaterial = keyMaterial;
        await ctx.Complete(CancellationToken.None);

        var owner = new SecretOwner(found.Id, OwnerTypeCode.User, keyMaterial);
        return (found, owner);
    }

    private static CreateSecretDto NewCreateDto(string? name = null, DateTime? expiration = null, string? value = null) => new() {
        Name = name ?? $"Secret_{Guid.NewGuid():N}",
        Expiration = expiration ?? DateTime.UtcNow.AddDays(30),
        Description = "Unit test secret",
        Value = value
    };

    // -------------------------------------------------------------------------
    // Create
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task CreateAsync_ValidOwnerAndRequest_ShouldSucceed() {
        var (_, owner) = await CreateUserWithKeyMaterialAsync();
        var manager = BuildSecretManager();

        var result = await manager.Create(owner, NewCreateDto(), CancellationToken.None);

        Assert.IsTrue(result.Status.IsSuccess());
        Assert.IsNotNull(result.Value);
        Assert.AreNotEqual(Guid.Empty, result.Value!.Id);
        Assert.IsFalse(string.IsNullOrEmpty(result.Value.PlainToken));
    }

    [TestMethod]
    public async Task CreateAsync_PlainTokenHasThreeSegments() {
        var (_, owner) = await CreateUserWithKeyMaterialAsync();
        var manager = BuildSecretManager();

        var result = await manager.Create(owner, NewCreateDto(), CancellationToken.None);

        Assert.IsTrue(result.Status.IsSuccess());
        var parts = result.Value!.PlainToken.Split('.');
        Assert.AreEqual(3, parts.Length, "Token must have format <ownerIdB64>.<typeCode>.<randomB64>");
    }

    [TestMethod]
    public async Task CreateAsync_PlainTokenContainsOwnerTypeCode() {
        var (_, owner) = await CreateUserWithKeyMaterialAsync();
        var manager = BuildSecretManager();

        var result = await manager.Create(owner, NewCreateDto(), CancellationToken.None);

        Assert.IsTrue(result.Status.IsSuccess());
        var parts = result.Value!.PlainToken.Split('.');
        Assert.AreEqual(OwnerTypeCode.User, parts[1]);
    }

    [TestMethod]
    public async Task CreateAsync_NullOwner_ShouldThrow() {
        var manager = BuildSecretManager();

        await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.Create(null!, NewCreateDto(), CancellationToken.None));
    }

    [TestMethod]
    public async Task CreateAsync_NullRequest_ShouldThrow() {
        var (_, owner) = await CreateUserWithKeyMaterialAsync();
        var manager = BuildSecretManager();

        await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.Create(owner, null!, CancellationToken.None));
    }

    [TestMethod]
    public async Task CreateAsync_ExpirationPersistedCorrectly() {
        var (_, owner) = await CreateUserWithKeyMaterialAsync();
        var manager = BuildSecretManager();
        var expiration = DateTime.UtcNow.AddDays(7);

        var result = await manager.Create(owner, NewCreateDto(expiration: expiration), CancellationToken.None);

        Assert.IsTrue(result.Status.IsSuccess());
        Assert.IsNotNull(result.Value!.Expiration);
        // Allow a few seconds of clock skew
        Assert.IsTrue(Math.Abs((result.Value.Expiration!.Value - expiration).TotalSeconds) < 5);
    }

    // -------------------------------------------------------------------------
    // Validate
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task ValidateAsync_ValidToken_ShouldReturnSuccess() {
        var (_, owner) = await CreateUserWithKeyMaterialAsync();
        var manager = BuildSecretManager();
        var created = await manager.Create(owner, NewCreateDto(), CancellationToken.None);

        var result = await manager.Validate(created.Value!.PlainToken, CancellationToken.None);

        Assert.IsTrue(result.Status.IsSuccess());
        Assert.IsNotNull(result.Value);
        Assert.AreEqual(created.Value.Id, result.Value!.Id);
    }

    [TestMethod]
    public async Task ValidateAsync_NullToken_ShouldReturnForbidden() {
        var manager = BuildSecretManager();

        var result = await manager.Validate(null!, CancellationToken.None);

        Assert.AreEqual(ResponseStatus.Forbidden, result.Status);
    }

    [TestMethod]
    public async Task ValidateAsync_EmptyToken_ShouldReturnForbidden() {
        var manager = BuildSecretManager();

        var result = await manager.Validate(string.Empty, CancellationToken.None);

        Assert.AreEqual(ResponseStatus.Forbidden, result.Status);
    }

    [TestMethod]
    public async Task ValidateAsync_RandomGarbage_ShouldReturnForbidden() {
        var manager = BuildSecretManager();

        var result = await manager.Validate("notavalidtoken", CancellationToken.None);

        Assert.AreEqual(ResponseStatus.Forbidden, result.Status);
    }

    [TestMethod]
    public async Task ValidateAsync_TamperedRandomSegment_ShouldReturnForbidden() {
        var (_, owner) = await CreateUserWithKeyMaterialAsync();
        var manager = BuildSecretManager();
        var created = await manager.Create(owner, NewCreateDto(), CancellationToken.None);
        var parts = created.Value!.PlainToken.Split('.');
        // Replace the random segment with fresh random bytes
        var tampered = $"{parts[0]}.{parts[1]}.{Base64UrlExtensions.Encode(RandomNumberGenerator.GetBytes(32))}";

        var result = await manager.Validate(tampered, CancellationToken.None);

        Assert.AreEqual(ResponseStatus.Forbidden, result.Status);
    }

    [TestMethod]
    public async Task ValidateAsync_TamperedOwnerSegment_ShouldReturnForbidden() {
        var (_, owner) = await CreateUserWithKeyMaterialAsync();
        var manager = BuildSecretManager();
        var created = await manager.Create(owner, NewCreateDto(), CancellationToken.None);
        var parts = created.Value!.PlainToken.Split('.');
        // Replace owner ID segment with a different GUID
        var differentOwner = Base64UrlExtensions.Encode(Guid.NewGuid().ToByteArray());
        var tampered = $"{differentOwner}.{parts[1]}.{parts[2]}";

        var result = await manager.Validate(tampered, CancellationToken.None);

        Assert.AreEqual(ResponseStatus.Forbidden, result.Status);
    }

    [TestMethod]
    public async Task ValidateAsync_ExpiredToken_ShouldReturnForbidden() {
        var (_, owner) = await CreateUserWithKeyMaterialAsync();
        var manager = BuildSecretManager();
        var expiredDto = NewCreateDto(expiration: DateTime.UtcNow.AddSeconds(-1));
        var created = await manager.Create(owner, expiredDto, CancellationToken.None);

        var result = await manager.Validate(created.Value!.PlainToken, CancellationToken.None);

        Assert.AreEqual(ResponseStatus.Forbidden, result.Status);
    }

    [TestMethod]
    public async Task ValidateAsync_RevokedToken_ShouldReturnForbidden() {
        var (_, owner) = await CreateUserWithKeyMaterialAsync();
        var manager = BuildSecretManager();
        var created = await manager.Create(owner, NewCreateDto(), CancellationToken.None);
        await manager.Revoke(owner, created.Value!.Id, CancellationToken.None);

        var result = await manager.Validate(created.Value.PlainToken, CancellationToken.None);

        Assert.AreEqual(ResponseStatus.Forbidden, result.Status);
    }

    // -------------------------------------------------------------------------
    // Revoke
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task RevokeAsync_ExistingSecret_ShouldSucceed() {
        var (_, owner) = await CreateUserWithKeyMaterialAsync();
        var manager = BuildSecretManager();
        var created = await manager.Create(owner, NewCreateDto(), CancellationToken.None);

        var result = await manager.Revoke(owner, created.Value!.Id, CancellationToken.None);

        Assert.IsTrue(result.Status.IsSuccess());
    }

    [TestMethod]
    public async Task RevokeAsync_UnknownId_ShouldReturnNotFound() {
        var (_, owner) = await CreateUserWithKeyMaterialAsync();
        var manager = BuildSecretManager();

        var result = await manager.Revoke(owner, Guid.NewGuid(), CancellationToken.None);

        Assert.AreEqual(ResponseStatus.NotFound, result.Status);
    }

    [TestMethod]
    public async Task RevokeAsync_WrongOwner_ShouldReturnNotFound() {
        var (_, owner) = await CreateUserWithKeyMaterialAsync();
        var (_, otherOwner) = await CreateUserWithKeyMaterialAsync();
        var manager = BuildSecretManager();
        var created = await manager.Create(owner, NewCreateDto(), CancellationToken.None);

        var result = await manager.Revoke(otherOwner, created.Value!.Id, CancellationToken.None);

        Assert.AreEqual(ResponseStatus.NotFound, result.Status);
        // The original secret should still validate
        var validateResult = await manager.Validate(created.Value.PlainToken, CancellationToken.None);
        Assert.IsTrue(validateResult.Status.IsSuccess());
    }

    [TestMethod]
    public async Task RevokeAsync_NullOwner_ShouldThrow() {
        var manager = BuildSecretManager();

        await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.Revoke(null!, Guid.NewGuid(), CancellationToken.None));
    }

    // -------------------------------------------------------------------------
    // FindById
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task FindByIdAsync_ExistingSecret_ShouldReturnDto() {
        var (_, owner) = await CreateUserWithKeyMaterialAsync();
        var manager = BuildSecretManager();
        var created = await manager.Create(owner, NewCreateDto("My Token"), CancellationToken.None);

        var found = await manager.FindById(owner, created.Value!.Id, CancellationToken.None);

        Assert.IsNotNull(found);
        Assert.AreEqual(created.Value.Id, found!.Id);
        Assert.AreEqual("My Token", found.Name);
    }

    [TestMethod]
    public async Task FindByIdAsync_UnknownId_ShouldReturnNull() {
        var (_, owner) = await CreateUserWithKeyMaterialAsync();
        var manager = BuildSecretManager();

        var found = await manager.FindById(owner, Guid.NewGuid(), CancellationToken.None);

        Assert.IsNull(found);
    }

    [TestMethod]
    public async Task FindByIdAsync_WrongOwner_ShouldReturnNull() {
        var (_, owner) = await CreateUserWithKeyMaterialAsync();
        var (_, otherOwner) = await CreateUserWithKeyMaterialAsync();
        var manager = BuildSecretManager();
        var created = await manager.Create(owner, NewCreateDto(), CancellationToken.None);

        var found = await manager.FindById(otherOwner, created.Value!.Id, CancellationToken.None);

        Assert.IsNull(found);
    }

    // -------------------------------------------------------------------------
    // GetSelectList
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task GetSelectListAsync_ActiveSecrets_ShouldReturnEntry() {
        var (_, owner) = await CreateUserWithKeyMaterialAsync();
        var manager = BuildSecretManager();
        var name = $"Listed_{Guid.NewGuid():N}";
        var created = await manager.Create(owner, NewCreateDto(name), CancellationToken.None);

        var list = await manager.GetSelectList(owner, CancellationToken.None);

        Assert.IsTrue(list.Any(item => item.Key == created.Value!.Id));
    }

    [TestMethod]
    public async Task GetSelectListAsync_AfterRevoke_ShouldNotContainSecret() {
        var (_, owner) = await CreateUserWithKeyMaterialAsync();
        var manager = BuildSecretManager();
        var created = await manager.Create(owner, NewCreateDto(), CancellationToken.None);
        await manager.Revoke(owner, created.Value!.Id, CancellationToken.None);

        var list = await manager.GetSelectList(owner, CancellationToken.None);

        Assert.IsFalse(list.Any(item => item.Key == created.Value.Id));
    }

    // -------------------------------------------------------------------------
    // GetPolicy / SetPolicy
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task SetPolicyAsync_NewPolicy_ShouldSucceed() {
        var (_, owner) = await CreateUserWithKeyMaterialAsync();
        var manager = BuildSecretManager();
        var created = await manager.Create(owner, NewCreateDto(), CancellationToken.None);
        var policy = new TestPolicy { Scope = "read", MaxRequests = 1000 };

        var result = await manager.SetPolicy(owner, created.Value!.Id, policy, CancellationToken.None);

        Assert.IsTrue(result.Status.IsSuccess());
    }

    [TestMethod]
    public async Task GetPolicyAsync_AfterSet_ShouldReturnCorrectValues() {
        var (_, owner) = await CreateUserWithKeyMaterialAsync();
        var manager = BuildSecretManager();
        var created = await manager.Create(owner, NewCreateDto(), CancellationToken.None);
        var policy = new TestPolicy { Scope = "write", MaxRequests = 500 };
        await manager.SetPolicy(owner, created.Value!.Id, policy, CancellationToken.None);

        var retrieved = await manager.GetPolicy<TestPolicy>(owner, created.Value.Id, CancellationToken.None);

        Assert.IsNotNull(retrieved);
        Assert.AreEqual("write", retrieved!.Scope);
        Assert.AreEqual(500, retrieved.MaxRequests);
    }

    [TestMethod]
    public async Task GetPolicyAsync_NoPolicy_ShouldReturnNull() {
        var (_, owner) = await CreateUserWithKeyMaterialAsync();
        var manager = BuildSecretManager();
        var created = await manager.Create(owner, NewCreateDto(), CancellationToken.None);

        var result = await manager.GetPolicy<TestPolicy>(owner, created.Value!.Id, CancellationToken.None);

        Assert.IsNull(result);
    }

    [TestMethod]
    public async Task GetPolicyAsync_UnknownSecret_ShouldReturnNull() {
        var (_, owner) = await CreateUserWithKeyMaterialAsync();
        var manager = BuildSecretManager();

        var result = await manager.GetPolicy<TestPolicy>(owner, Guid.NewGuid(), CancellationToken.None);

        Assert.IsNull(result);
    }

    [TestMethod]
    public async Task SetPolicyAsync_WrongOwner_ShouldReturnNotFound() {
        var (_, owner) = await CreateUserWithKeyMaterialAsync();
        var (_, otherOwner) = await CreateUserWithKeyMaterialAsync();
        var manager = BuildSecretManager();
        var created = await manager.Create(owner, NewCreateDto(), CancellationToken.None);

        var result = await manager.SetPolicy(otherOwner, created.Value!.Id,
            new TestPolicy { Scope = "none" }, CancellationToken.None);

        Assert.AreEqual(ResponseStatus.NotFound, result.Status);
    }

    [TestMethod]
    public async Task SetPolicyAsync_OverwritesPreviousPolicy() {
        var (_, owner) = await CreateUserWithKeyMaterialAsync();
        var manager = BuildSecretManager();
        var created = await manager.Create(owner, NewCreateDto(), CancellationToken.None);
        await manager.SetPolicy(owner, created.Value!.Id, new TestPolicy { Scope = "read" }, CancellationToken.None);

        await manager.SetPolicy(owner, created.Value.Id, new TestPolicy { Scope = "admin" }, CancellationToken.None);

        var result = await manager.GetPolicy<TestPolicy>(owner, created.Value.Id, CancellationToken.None);
        Assert.AreEqual("admin", result!.Scope);
    }

    // -------------------------------------------------------------------------
    // Full lifecycle
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task FullLifecycle_CreateValidateRevokeValidate_ShouldFollowExpectedStatuses() {
        var (_, owner) = await CreateUserWithKeyMaterialAsync();
        var manager = BuildSecretManager();

        // Create
        var createResult = await manager.Create(owner, NewCreateDto(), CancellationToken.None);
        Assert.IsTrue(createResult.Status.IsSuccess());
        var plainToken = createResult.Value!.PlainToken;
        var secretId = createResult.Value.Id;

        // Validate → should succeed
        var validateResult = await manager.Validate(plainToken, CancellationToken.None);
        Assert.IsTrue(validateResult.Status.IsSuccess());

        // Revoke
        var revokeResult = await manager.Revoke(owner, secretId, CancellationToken.None);
        Assert.IsTrue(revokeResult.Status.IsSuccess());

        // Validate after revoke → should fail
        var afterRevoke = await manager.Validate(plainToken, CancellationToken.None);
        Assert.IsFalse(afterRevoke.Status.IsSuccess());
    }

    // -------------------------------------------------------------------------
    // Payload storage — Create with value
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task CreateAsync_WithValue_ValidateAsync_ShouldReturnDecryptedValue() {
        var (_, owner) = await CreateUserWithKeyMaterialAsync();
        var manager = BuildSecretManager();
        const string expectedValue = "Server=prod;Database=mydb;Password=s3cr3t";

        var created = await manager.Create(owner, NewCreateDto(value: expectedValue), CancellationToken.None);
        Assert.IsTrue(created.Status.IsSuccess());

        var result = await manager.Validate(created.Value!.PlainToken, CancellationToken.None);

        Assert.IsTrue(result.Status.IsSuccess());
        Assert.AreEqual(expectedValue, result.Value!.Payload);
    }

    [TestMethod]
    public async Task CreateAsync_WithoutValue_ValidateAsync_ShouldReturnNullValue() {
        var (_, owner) = await CreateUserWithKeyMaterialAsync();
        var manager = BuildSecretManager();

        var created = await manager.Create(owner, NewCreateDto(), CancellationToken.None);
        var result = await manager.Validate(created.Value!.PlainToken, CancellationToken.None);

        Assert.IsTrue(result.Status.IsSuccess());
        Assert.IsNull(result.Value!.Payload);
    }

    // -------------------------------------------------------------------------
    // Payload storage — SetValue
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task SetValueAsync_ExistingToken_ShouldStoreEncryptedValue() {
        var (_, owner) = await CreateUserWithKeyMaterialAsync();
        var manager = BuildSecretManager();
        const string expectedValue = "my-api-key-abc123";

        var created = await manager.Create(owner, NewCreateDto(), CancellationToken.None);
        var plainToken = created.Value!.PlainToken;

        var setResult = await manager.SetValue(plainToken, expectedValue, CancellationToken.None);
        Assert.IsTrue(setResult.Status.IsSuccess());

        var validated = await manager.Validate(plainToken, CancellationToken.None);
        Assert.IsTrue(validated.Status.IsSuccess());
        Assert.AreEqual(expectedValue, validated.Value!.Payload);
    }

    [TestMethod]
    public async Task SetValueAsync_CalledTwice_ShouldReturnLatestValue() {
        var (_, owner) = await CreateUserWithKeyMaterialAsync();
        var manager = BuildSecretManager();

        var created = await manager.Create(owner, NewCreateDto(value: "initial-value"), CancellationToken.None);
        var plainToken = created.Value!.PlainToken;

        await manager.SetValue(plainToken, "updated-value", CancellationToken.None);
        var validated = await manager.Validate(plainToken, CancellationToken.None);

        Assert.AreEqual("updated-value", validated.Value!.Payload);
    }

    [TestMethod]
    public async Task SetValueAsync_NullValue_ShouldClearStoredValue() {
        var (_, owner) = await CreateUserWithKeyMaterialAsync();
        var manager = BuildSecretManager();

        var created = await manager.Create(owner, NewCreateDto(value: "some-value"), CancellationToken.None);
        var plainToken = created.Value!.PlainToken;

        var setResult = await manager.SetValue(plainToken, null, CancellationToken.None);
        Assert.IsTrue(setResult.Status.IsSuccess());

        var validated = await manager.Validate(plainToken, CancellationToken.None);
        Assert.IsTrue(validated.Status.IsSuccess());
        Assert.IsNull(validated.Value!.Payload);
    }

    [TestMethod]
    public async Task SetValueAsync_InvalidToken_ShouldReturnNotFound() {
        var manager = BuildSecretManager();

        var result = await manager.SetValue("not.a.valid.token.at.all", "value", CancellationToken.None);

        Assert.IsFalse(result.Status.IsSuccess());
    }

    [TestMethod]
    public async Task SetValueAsync_RevokedToken_ShouldReturnNotFound() {
        var (_, owner) = await CreateUserWithKeyMaterialAsync();
        var manager = BuildSecretManager();

        var created = await manager.Create(owner, NewCreateDto(), CancellationToken.None);
        var plainToken = created.Value!.PlainToken;
        await manager.Revoke(owner, created.Value.Id, CancellationToken.None);

        var result = await manager.SetValue(plainToken, "new-value", CancellationToken.None);

        Assert.IsFalse(result.Status.IsSuccess());
    }

    // -------------------------------------------------------------------------
    // Full lifecycle with value update
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task FullLifecycle_CreateSetValueValidateRevoke_ShouldFollowExpectedStatuses() {
        var (_, owner) = await CreateUserWithKeyMaterialAsync();
        var manager = BuildSecretManager();
        const string initialValue = "Server=db1;Password=initial";
        const string updatedValue = "Server=db2;Password=updated";

        // Create with an initial value
        var createResult = await manager.Create(owner, NewCreateDto(value: initialValue), CancellationToken.None);
        Assert.IsTrue(createResult.Status.IsSuccess());
        var plainToken = createResult.Value!.PlainToken;
        var secretId = createResult.Value.Id;

        // Validate → initial value returned
        var firstValidate = await manager.Validate(plainToken, CancellationToken.None);
        Assert.IsTrue(firstValidate.Status.IsSuccess());
        Assert.AreEqual(initialValue, firstValidate.Value!.Payload);

        // Update the value
        var setResult = await manager.SetValue(plainToken, updatedValue, CancellationToken.None);
        Assert.IsTrue(setResult.Status.IsSuccess());

        // Validate → updated value returned
        var secondValidate = await manager.Validate(plainToken, CancellationToken.None);
        Assert.IsTrue(secondValidate.Status.IsSuccess());
        Assert.AreEqual(updatedValue, secondValidate.Value!.Payload);

        // Revoke
        var revokeResult = await manager.Revoke(owner, secretId, CancellationToken.None);
        Assert.IsTrue(revokeResult.Status.IsSuccess());

        // Validate after revoke → should fail
        var afterRevoke = await manager.Validate(plainToken, CancellationToken.None);
        Assert.IsFalse(afterRevoke.Status.IsSuccess());

        // SetValue after revoke → should also fail
        var setAfterRevoke = await manager.SetValue(plainToken, "any-value", CancellationToken.None);
        Assert.IsFalse(setAfterRevoke.Status.IsSuccess());
    }

    // -------------------------------------------------------------------------
    // Helper DTO for policy tests
    // -------------------------------------------------------------------------

    private sealed class TestPolicy {
        public string Scope { get; set; } = string.Empty;
        public int MaxRequests { get; set; }
    }
}
