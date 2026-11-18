using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;

using Moq;

using N2.Core.Commands;
using N2.Core.Entity;
using N2.Core.Identity.Data;
using N2.Core.Identity.Services;

using System.Globalization;
using System.Security.Cryptography;

namespace N2.Core.Identity.UnitTests;

/// <summary>
/// Provider-agnostic integration tests for <see cref="N2TenantManager"/>.
/// Subclasses supply the target <see cref="Provider"/> and <see cref="ConnectionName"/>;
/// every <c>[TestMethod]</c> defined here is discovered and executed by each subclass.
/// All tests are self-contained: they create and clean up their own data.
/// </summary>
public abstract class N2TenantManagerIntegrationTestsBase {
    protected abstract DatabaseProvider Provider { get; }
    protected abstract string ConnectionName { get; }

    private static CultureInfo DefaultCulture => CultureInfo.InvariantCulture;

    private static IConfiguration BuildConfiguration() =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> {
                ["AuthenticationConfig:TokenSigningSecret"] = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
                ["AuthenticationConfig:MfaTokenSecret"] = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
                ["AuthenticationConfig:JwtSettings:Secret"] = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
                ["AuthenticationConfig:JwtSettings:Issuer"] = "http://localhost:8080",
                ["AuthenticationConfig:JwtSettings:Audience"] = "http://localhost:8081",
            })
            .AddUserSecrets<N2IdentityContextIntegrationTestsBase>()
            .AddEnvironmentVariables()
            .Build();

    private IIdentityContextFactory BuildFactory(IConfiguration configuration) {
        var mock = new Mock<IConnectionStringService>();
        mock.Setup(s => s.GetConnectionString(It.IsAny<string>()))
            .Returns((string name) => configuration.GetConnectionString(name) ?? string.Empty);
        return new N2IdentityContextFactory(mock.Object, Provider, ConnectionName);
    }

    protected ITenantManager BuildTenantManager() {
        var config = BuildConfiguration();
        var factory = BuildFactory(config);
        return new N2TenantManager(factory, config, ConnectionName, NullLogger<N2TenantManager>.Instance, Provider);
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

    protected async Task<N2IdentityContext> CreateAndPrepareContextAsync() {
        var config = BuildConfiguration();
        var factory = (N2IdentityContextFactory)BuildFactory(config);
        var context = (N2IdentityContext)await factory.Create(Provider, ConnectionName, CancellationToken.None);
        await IntegrationMigrationGate.EnsureMigratedAsync(context.Database);
        return context;
    }

    [TestInitialize]
    public async Task EnsureDatabaseMigratedAsync() {
        using var _ = await CreateAndPrepareContextAsync();
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private static ApplicationTenant NewTenant(string? name = null, string? email = null) {
        var id = Guid.NewGuid();
        return new ApplicationTenant {
            Id = id,
            Name = name ?? $"Tenant_{id:N}",
            AdminEmail = email ?? $"admin_{id:N}@test.com"
        };
    }

    private static async Task<ApplicationTenant> CreateTenantAsync(ITenantManager manager, string? name = null) {
        var tenant = NewTenant(name);
        var result = await manager.Create(tenant, CancellationToken.None);
        if (!result.Status.IsSuccess()) {
            throw new InvalidOperationException($"Failed to seed tenant: {result.Message}");
        }

        tenant.NormalizedName = tenant.Name!.Trim().ToUpperInvariant();
        tenant.NormalizedEmail = tenant.AdminEmail!.Trim().ToUpperInvariant();
        return tenant;
    }

    private async Task<ApplicationUser> CreateUserAsync(string? userName = null) {
        using var userManager = BuildUserManager();
        var name = userName ?? $"u_{Guid.NewGuid():N}";
        var user = new ApplicationUser { UserName = name, Email = $"{name}@test.com" };
        var result = await userManager.Create(user, "TestPassword1!", CancellationToken.None);
        if (!result.Status.IsSuccess()) {
            throw new InvalidOperationException($"Failed to seed user: {result.Message}");
        }

        var found = await userManager.FindByName(name, CancellationToken.None);
        return found.Value ?? throw new InvalidOperationException("Failed to retrieve created user.");
    }

    private async Task DeleteUserAsync(ApplicationUser user) {
        using var context = await CreateAndPrepareContextAsync();
        var existing = await context.UserFindRecord(user.Id, CancellationToken.None);
        if (existing != null) {
            context.UserDelete(existing);
            await context.Complete(CancellationToken.None);
        }
    }

    // -------------------------------------------------------------------------
    // Create
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task CreateAsync_NewTenant_ShouldSucceed() {
        var manager = BuildTenantManager();
        var tenant = NewTenant();

        var result = await manager.Create(tenant, CancellationToken.None);

        try {
            Assert.IsTrue(result.Status.IsSuccess());
        } finally {
            await manager.Delete(tenant, CancellationToken.None);
        }
    }

    [TestMethod]
    public async Task CreateAsync_NormalizesNameAndEmail() {
        var manager = BuildTenantManager();
        var id = Guid.NewGuid();
        var rawName = $"  Norm {id:N}  ";
        var tenant = NewTenant(rawName.Trim(), "  Admin@NormTest.com  ");
        tenant.Name = rawName;

        var result = await manager.Create(tenant, CancellationToken.None);

        try {
            Assert.IsTrue(result.Status.IsSuccess());
            var found = await manager.FindByName(rawName.Trim(), CancellationToken.None);
            Assert.IsNotNull(found);
            Assert.AreEqual(rawName.Trim().ToUpperInvariant(), found!.NormalizedName);
            Assert.AreEqual("ADMIN@NORMTEST.COM", found.NormalizedEmail);
        } finally {
            await manager.Delete(tenant, CancellationToken.None);
        }
    }

    [TestMethod]
    public async Task CreateAsync_DuplicateTenant_ShouldFail() {
        var manager = BuildTenantManager();
        var tenant = await CreateTenantAsync(manager);

        var duplicate = NewTenant(tenant.Name!);
        duplicate.NormalizedName = tenant.NormalizedName;
        var result = await manager.Create(duplicate, CancellationToken.None);

        try {
            Assert.AreEqual(ResponseStatus.NotAcceptable, result.Status);
        } finally {
            await manager.Delete(tenant, CancellationToken.None);
        }
    }

    // -------------------------------------------------------------------------
    // Delete
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task DeleteAsync_ExistingTenant_ShouldSucceed() {
        var manager = BuildTenantManager();
        var tenant = await CreateTenantAsync(manager);

        var result = await manager.Delete(tenant, CancellationToken.None);

        Assert.IsTrue(result.Status.IsSuccess());
        var found = await manager.FindById(tenant.Id, CancellationToken.None);
        Assert.IsNull(found);
    }

    [TestMethod]
    public async Task DeleteAsync_NonExistentTenant_ShouldFail() {
        var manager = BuildTenantManager();

        var result = await manager.Delete(NewTenant(), CancellationToken.None);

        Assert.AreEqual(ResponseStatus.NotFound, result.Status);
    }

    [TestMethod]
    public async Task DeleteAsync_EmptyId_ShouldThrow() {
        var manager = BuildTenantManager();
        var bad = NewTenant();
        bad.Id = Guid.Empty;

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
            () => manager.Delete(bad, CancellationToken.None));
    }

    // -------------------------------------------------------------------------
    // Update
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task UpdateAsync_ExistingTenant_ShouldPersistChanges() {
        var manager = BuildTenantManager();
        var tenant = await CreateTenantAsync(manager);

        tenant.Name = $"Updated_{Guid.NewGuid():N}";
        tenant.AdminEmail = "updated@email.com";
        tenant.ContactInfo = "updated contact";
        var result = await manager.Update(tenant, CancellationToken.None);

        try {
            Assert.IsTrue(result.Status.IsSuccess());
            var found = await manager.FindById(tenant.Id, CancellationToken.None);
            Assert.IsNotNull(found);
            Assert.AreEqual(tenant.Name, found!.Name);
            Assert.AreEqual(tenant.Name.ToUpperInvariant(), found.NormalizedName);
            Assert.AreEqual("updated@email.com", found.AdminEmail);
            Assert.AreEqual("UPDATED@EMAIL.COM", found.NormalizedEmail);
            Assert.AreEqual("updated contact", found.ContactInfo);
        } finally {
            await manager.Delete(tenant, CancellationToken.None);
        }
    }

    [TestMethod]
    public async Task UpdateAsync_NonExistentTenant_ShouldFail() {
        var manager = BuildTenantManager();

        var result = await manager.Update(NewTenant(), CancellationToken.None);

        Assert.AreEqual(ResponseStatus.NotFound, result.Status);
    }

    [TestMethod]
    public async Task UpdateAsync_EmptyName_ShouldThrow() {
        var manager = BuildTenantManager();
        var tenant = await CreateTenantAsync(manager);
        tenant.Name = "  ";

        try {
            await Assert.ThrowsAsync<ArgumentException>(
                () => manager.Update(tenant, CancellationToken.None));
        } finally {
            await manager.Delete(tenant, CancellationToken.None);
        }
    }

    // -------------------------------------------------------------------------
    // FindById
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task FindByIdAsync_ExistingTenant_ShouldReturn() {
        var manager = BuildTenantManager();
        var tenant = await CreateTenantAsync(manager);

        try {
            var found = await manager.FindById(tenant.Id, CancellationToken.None);
            Assert.IsNotNull(found);
            Assert.AreEqual(tenant.Id, found!.Id);
        } finally {
            await manager.Delete(tenant, CancellationToken.None);
        }
    }

    [TestMethod]
    public async Task FindByIdAsync_UnknownId_ShouldReturnNull() {
        var manager = BuildTenantManager();

        var found = await manager.FindById(Guid.NewGuid(), CancellationToken.None);

        Assert.IsNull(found);
    }

    [TestMethod]
    public async Task FindByIdAsync_EmptyId_ShouldThrow() {
        var manager = BuildTenantManager();

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
            () => manager.FindById(Guid.Empty, CancellationToken.None));
    }

    // -------------------------------------------------------------------------
    // FindByName
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task FindByNameAsync_ExistingTenant_ShouldReturn() {
        var manager = BuildTenantManager();
        var tenant = await CreateTenantAsync(manager);

        try {
            var found = await manager.FindByName(tenant.Name!, CancellationToken.None);
            Assert.IsNotNull(found);
            Assert.AreEqual(tenant.Id, found!.Id);
        } finally {
            await manager.Delete(tenant, CancellationToken.None);
        }
    }

    [TestMethod]
    public async Task FindByNameAsync_NormalizesInput_ShouldFindWithMixedCase() {
        var manager = BuildTenantManager();
        var tenant = await CreateTenantAsync(manager);

        try {
            var found = await manager.FindByName($"  {tenant.Name!.ToLower(DefaultCulture)}  ", CancellationToken.None);
            Assert.IsNotNull(found);
            Assert.AreEqual(tenant.Id, found!.Id);
        } finally {
            await manager.Delete(tenant, CancellationToken.None);
        }
    }

    [TestMethod]
    public async Task FindByNameAsync_UnknownName_ShouldReturnNull() {
        var manager = BuildTenantManager();

        var found = await manager.FindByName($"DoesNotExist_{Guid.NewGuid():N}", CancellationToken.None);

        Assert.IsNull(found);
    }

    // -------------------------------------------------------------------------
    // FindByEmail
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task FindByEmailAsync_ExistingEmail_ShouldReturn() {
        var manager = BuildTenantManager();
        var tenant = await CreateTenantAsync(manager);

        try {
            var found = await manager.FindByEmail(tenant.AdminEmail!, CancellationToken.None);
            Assert.IsNotNull(found);
            Assert.AreEqual(tenant.Id, found!.Id);
        } finally {
            await manager.Delete(tenant, CancellationToken.None);
        }
    }

    [TestMethod]
    public async Task FindByEmailAsync_NormalizesInput_ShouldFindWithMixedCase() {
        var manager = BuildTenantManager();
        var tenant = await CreateTenantAsync(manager);

        try {
            var found = await manager.FindByEmail($"  {tenant.AdminEmail!.ToUpper(DefaultCulture)}  ", CancellationToken.None);
            Assert.IsNotNull(found);
            Assert.AreEqual(tenant.Id, found!.Id);
        } finally {
            await manager.Delete(tenant, CancellationToken.None);
        }
    }

    [TestMethod]
    public async Task FindByEmailAsync_UnknownEmail_ShouldReturnNull() {
        var manager = BuildTenantManager();

        var found = await manager.FindByEmail($"nobody_{Guid.NewGuid():N}@nowhere.com", CancellationToken.None);

        Assert.IsNull(found);
    }

    // -------------------------------------------------------------------------
    // GetTenants
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task GetTenantsAsync_ShouldReturnCreatedTenant() {
        var manager = BuildTenantManager();
        var tenant = await CreateTenantAsync(manager);

        try {
            var list = await manager.GetTenants(CancellationToken.None);
            Assert.IsTrue(list.Any(t => t.Key == tenant.Id));
        } finally {
            await manager.Delete(tenant, CancellationToken.None);
        }
    }

    // -------------------------------------------------------------------------
    // Lock / Unlock
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task LockAsync_UnlockedTenant_ShouldSetIsLockedTrue() {
        var manager = BuildTenantManager();
        var tenant = await CreateTenantAsync(manager);

        try {
            var result = await manager.Lock(tenant, CancellationToken.None);
            Assert.IsTrue(result.Status.IsSuccess());
            var found = await manager.FindById(tenant.Id, CancellationToken.None);
            Assert.IsTrue(found!.IsLocked);
        } finally {
            await manager.Delete(tenant, CancellationToken.None);
        }
    }

    [TestMethod]
    public async Task LockAsync_NonExistentTenant_ShouldFail() {
        var manager = BuildTenantManager();

        var result = await manager.Lock(NewTenant(), CancellationToken.None);

        Assert.AreEqual(ResponseStatus.NotFound, result.Status);
    }

    [TestMethod]
    public async Task UnlockAsync_LockedTenant_ShouldSetIsLockedFalse() {
        var manager = BuildTenantManager();
        var tenant = await CreateTenantAsync(manager);
        await manager.Lock(tenant, CancellationToken.None);

        try {
            var result = await manager.Unlock(tenant, CancellationToken.None);
            Assert.IsTrue(result.Status.IsSuccess());
            var found = await manager.FindById(tenant.Id, CancellationToken.None);
            Assert.IsFalse(found!.IsLocked);
        } finally {
            await manager.Delete(tenant, CancellationToken.None);
        }
    }

    [TestMethod]
    public async Task UnlockAsync_NonExistentTenant_ShouldFail() {
        var manager = BuildTenantManager();

        var result = await manager.Unlock(NewTenant(), CancellationToken.None);

        Assert.AreEqual(ResponseStatus.NotFound, result.Status);
    }

    // -------------------------------------------------------------------------
    // AddUser / RemoveUser
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task AddUserAsync_NewAssignment_ShouldSucceed() {
        var manager = BuildTenantManager();
        var user = await CreateUserAsync();
        var tenant = await CreateTenantAsync(manager);

        try {
            var result = await manager.AddUser(user, tenant, CancellationToken.None);
            Assert.IsTrue(result.Status.IsSuccess());
            var ids = await manager.GetTenantIdsForUser(user.Id, CancellationToken.None);
            Assert.IsTrue(ids.Contains(tenant.Id));
        } finally {
            await manager.RemoveUser(user, tenant, CancellationToken.None);
            await manager.Delete(tenant, CancellationToken.None);
            await DeleteUserAsync(user);
        }
    }

    [TestMethod]
    public async Task AddUserAsync_AlreadyAssigned_ShouldBeIdempotent() {
        var manager = BuildTenantManager();
        var user = await CreateUserAsync();
        var tenant = await CreateTenantAsync(manager);
        await manager.AddUser(user, tenant, CancellationToken.None);

        try {
            var result = await manager.AddUser(user, tenant, CancellationToken.None);
            Assert.IsTrue(result.Status.IsSuccess());
            var users = (await manager.GetUsersForTenant(tenant.Id, CancellationToken.None)).ToList();
            Assert.AreEqual(1, users.Count(u => u == user.UserName));
        } finally {
            await manager.RemoveUser(user, tenant, CancellationToken.None);
            await manager.Delete(tenant, CancellationToken.None);
            await DeleteUserAsync(user);
        }
    }

    [TestMethod]
    public async Task AddUserAsync_NonExistentUser_ShouldFail() {
        var manager = BuildTenantManager();
        var tenant = await CreateTenantAsync(manager);
        var ghost = new ApplicationUser { Id = Guid.NewGuid() };

        try {
            var result = await manager.AddUser(ghost, tenant, CancellationToken.None);
            Assert.AreEqual(ResponseStatus.NotFound, result.Status);
        } finally {
            await manager.Delete(tenant, CancellationToken.None);
        }
    }

    [TestMethod]
    public async Task AddUserAsync_NonExistentTenant_ShouldFail() {
        var manager = BuildTenantManager();
        var user = await CreateUserAsync();

        try {
            var result = await manager.AddUser(user, NewTenant(), CancellationToken.None);
            Assert.AreEqual(ResponseStatus.NotFound, result.Status);
        } finally {
            await DeleteUserAsync(user);
        }
    }

    [TestMethod]
    public async Task RemoveUserAsync_ExistingAssignment_ShouldSucceed() {
        var manager = BuildTenantManager();
        var user = await CreateUserAsync();
        var tenant = await CreateTenantAsync(manager);
        await manager.AddUser(user, tenant, CancellationToken.None);

        try {
            var result = await manager.RemoveUser(user, tenant, CancellationToken.None);
            Assert.IsTrue(result.Status.IsSuccess());
            var ids = await manager.GetTenantIdsForUser(user.Id, CancellationToken.None);
            Assert.IsFalse(ids.Contains(tenant.Id));
        } finally {
            await manager.Delete(tenant, CancellationToken.None);
            await DeleteUserAsync(user);
        }
    }

    [TestMethod]
    public async Task RemoveUserAsync_NotAssigned_ShouldBeIdempotent() {
        var manager = BuildTenantManager();
        var user = await CreateUserAsync();
        var tenant = await CreateTenantAsync(manager);

        try {
            var result = await manager.RemoveUser(user, tenant, CancellationToken.None);
            Assert.IsTrue(result.Status.IsSuccess());
        } finally {
            await manager.Delete(tenant, CancellationToken.None);
            await DeleteUserAsync(user);
        }
    }

    // -------------------------------------------------------------------------
    // GetUsersForTenant / GetTenantIdsForUser
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task GetUsersForTenantAsync_ShouldReturnAssignedUser() {
        var manager = BuildTenantManager();
        var user = await CreateUserAsync();
        var tenant = await CreateTenantAsync(manager);
        await manager.AddUser(user, tenant, CancellationToken.None);

        try {
            var users = (await manager.GetUsersForTenant(tenant.Id, CancellationToken.None)).ToList();
            Assert.IsTrue(users.Contains(user.UserName, StringComparer.OrdinalIgnoreCase));
        } finally {
            await manager.RemoveUser(user, tenant, CancellationToken.None);
            await manager.Delete(tenant, CancellationToken.None);
            await DeleteUserAsync(user);
        }
    }

    [TestMethod]
    public async Task GetUsersForTenantAsync_LockedTenant_ShouldReturnEmpty() {
        var manager = BuildTenantManager();
        var user = await CreateUserAsync();
        var tenant = await CreateTenantAsync(manager);
        await manager.AddUser(user, tenant, CancellationToken.None);
        await manager.Lock(tenant, CancellationToken.None);

        try {
            var users = await manager.GetUsersForTenant(tenant.Id, CancellationToken.None);
            Assert.IsFalse(users.Any());
        } finally {
            await manager.RemoveUser(user, tenant, CancellationToken.None);
            await manager.Delete(tenant, CancellationToken.None);
            await DeleteUserAsync(user);
        }
    }

    [TestMethod]
    public async Task GetTenantIdsForUserAsync_ShouldReturnAllAssignedTenants() {
        var manager = BuildTenantManager();
        var user = await CreateUserAsync();
        var tenant1 = await CreateTenantAsync(manager);
        var tenant2 = await CreateTenantAsync(manager);
        await manager.AddUser(user, tenant1, CancellationToken.None);
        await manager.AddUser(user, tenant2, CancellationToken.None);

        try {
            var ids = (await manager.GetTenantIdsForUser(user.Id, CancellationToken.None)).ToList();
            Assert.IsTrue(ids.Contains(tenant1.Id));
            Assert.IsTrue(ids.Contains(tenant2.Id));
        } finally {
            await manager.RemoveUser(user, tenant1, CancellationToken.None);
            await manager.RemoveUser(user, tenant2, CancellationToken.None);
            await manager.Delete(tenant1, CancellationToken.None);
            await manager.Delete(tenant2, CancellationToken.None);
            await DeleteUserAsync(user);
        }
    }

    [TestMethod]
    public async Task GetTenantIdsForUserAsync_UnknownUser_ShouldReturnEmpty() {
        var manager = BuildTenantManager();

        var ids = await manager.GetTenantIdsForUser(Guid.NewGuid(), CancellationToken.None);

        Assert.IsFalse(ids.Any());
    }

    // -------------------------------------------------------------------------
    // CanSignIn
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task CanSignInAsync_ActiveUserActiveTenant_ShouldReturnTrue() {
        var manager = BuildTenantManager();
        var user = await CreateUserAsync();
        var tenant = await CreateTenantAsync(manager);
        await manager.AddUser(user, tenant, CancellationToken.None);

        try {
            var canSignIn = await manager.ApplicationUserCanSignIn(user.Id, tenant.Id, CancellationToken.None);
            Assert.IsTrue(canSignIn);
        } finally {
            await manager.RemoveUser(user, tenant, CancellationToken.None);
            await manager.Delete(tenant, CancellationToken.None);
            await DeleteUserAsync(user);
        }
    }

    [TestMethod]
    public async Task CanSignInAsync_ActiveUserLockedTenant_ShouldReturnFalse() {
        var manager = BuildTenantManager();
        var user = await CreateUserAsync();
        var tenant = await CreateTenantAsync(manager);
        await manager.AddUser(user, tenant, CancellationToken.None);
        await manager.Lock(tenant, CancellationToken.None);

        try {
            var canSignIn = await manager.ApplicationUserCanSignIn(user.Id, tenant.Id, CancellationToken.None);
            Assert.IsFalse(canSignIn);
        } finally {
            await manager.RemoveUser(user, tenant, CancellationToken.None);
            await manager.Delete(tenant, CancellationToken.None);
            await DeleteUserAsync(user);
        }
    }

    [TestMethod]
    public async Task CanSignInAsync_UserNotAssignedToTenant_ShouldReturnFalse() {
        var manager = BuildTenantManager();
        var user = await CreateUserAsync();
        var tenant = await CreateTenantAsync(manager);

        try {
            var canSignIn = await manager.ApplicationUserCanSignIn(user.Id, tenant.Id, CancellationToken.None);
            Assert.IsFalse(canSignIn);
        } finally {
            await manager.Delete(tenant, CancellationToken.None);
            await DeleteUserAsync(user);
        }
    }

    [TestMethod]
    public async Task CanSignInAsync_EmptyUserId_ShouldThrow() {
        var manager = BuildTenantManager();

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
            () => manager.ApplicationUserCanSignIn(Guid.Empty, Guid.NewGuid(), CancellationToken.None));
    }

    [TestMethod]
    public async Task CanSignInAsync_EmptyTenantId_ShouldThrow() {
        var manager = BuildTenantManager();

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
            () => manager.ApplicationUserCanSignIn(Guid.NewGuid(), Guid.Empty, CancellationToken.None));
    }
}
