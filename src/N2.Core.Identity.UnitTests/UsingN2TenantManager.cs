using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;

using N2.Core.Commands;
using N2.Core.Identity.Data;
using N2.Core.Identity.Services;

namespace N2.Core.Identity.UnitTests;

[TestClass]
public class UsingN2TenantManager {
    private readonly ServiceProvider serviceProvider;

    public UsingN2TenantManager() {
        ServiceCollection serviceCollection = new();
        TestContext.ConfigureServices(serviceCollection);
        serviceProvider = serviceCollection.BuildServiceProvider();
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private ITenantManager BuildTenantManager() {
        var config = serviceProvider.GetRequiredService<IConfiguration>();
        var factory = serviceProvider.GetRequiredService<IIdentityContextFactory>();
        return new N2TenantManager(factory, config, "IdentityDb", NullLogger<N2TenantManager>.Instance);
    }

    private IUserManager<ApplicationUser> BuildUserManager() {
        var config = serviceProvider.GetRequiredService<IConfiguration>();
        var factory = serviceProvider.GetRequiredService<IIdentityContextFactory>();
        var hasher = serviceProvider.GetRequiredService<IPasswordHasher<ApplicationUser>>();
        var rateLimiter = serviceProvider.GetRequiredService<IRateLimiter>();
        return new N2UserManager(factory, config, rateLimiter, hasher, "IdentityDb", NullLogger<N2UserManager>.Instance);
    }

    private static ApplicationTenant NewTenant(string name = "Acme Corp", string email = "admin@acme.com") => new() {
        Id = Guid.NewGuid(),
        Name = name,
        AdminEmail = email
    };

    private async Task<ApplicationTenant> CreateTenantAsync(string name, string email = "admin@acme.com") {
        var tenant = NewTenant(name, email);
        var manager = BuildTenantManager();
        var result = await manager.CreateAsync(tenant, CancellationToken.None);
        if (!result.Status.IsSuccess()) {
            throw new InvalidOperationException($"Failed to seed tenant: {result.Message}");
        }
        // Return the normalized version that was persisted
        tenant.NormalizedName = name.Trim().ToUpperInvariant();
        tenant.NormalizedEmail = email.Trim().ToUpperInvariant();
        return tenant;
    }

    private async Task<ApplicationUser> CreateUserAsync(string userName) {
        using var userManager = BuildUserManager();
        ApplicationUser user = new() {
            UserName = userName,
            Email = $"{userName}@test.com"
        };
        var result = await userManager.CreateAsync(user, "TestPassword1!", CancellationToken.None);
        if (!result.Status.IsSuccess()) {
            throw new InvalidOperationException($"Failed to seed user: {result.Message}");
        }
        var found = await userManager.FindByNameAsync(userName, CancellationToken.None);
        return found.Value ?? throw new InvalidOperationException("Failed to retrieve created user.");
    }

    // -------------------------------------------------------------------------
    // CreateAsync
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task CreateAsync_NewTenant_ShouldSucceed() {
        var manager = BuildTenantManager();
        var tenant = NewTenant($"New Tenant {Guid.NewGuid()}");

        var result = await manager.CreateAsync(tenant, CancellationToken.None);

        Assert.IsTrue(result.Status.IsSuccess());
    }

    [TestMethod]
    public async Task CreateAsync_NormalizesNameAndEmail() {
        var uniqueName = $"Norm Tenant {Guid.NewGuid()}";
        var manager = BuildTenantManager();
        var tenant = NewTenant(uniqueName, "  Admin@NormTest.com  ");
        tenant.Name = $"  {uniqueName}  "; // add whitespace to test trimming

        var result = await manager.CreateAsync(tenant, CancellationToken.None);

        Assert.IsTrue(result.Status.IsSuccess());
        var found = await manager.FindByNameAsync(uniqueName, CancellationToken.None);
        Assert.IsNotNull(found);
        Assert.AreEqual(uniqueName.ToUpperInvariant(), found!.NormalizedName);
        Assert.AreEqual("ADMIN@NORMTEST.COM", found.NormalizedEmail);
    }

    [TestMethod]
    public async Task CreateAsync_DuplicateTenant_ShouldFail() {
        var tenant = await CreateTenantAsync($"Dup Tenant {Guid.NewGuid()}");
        var manager = BuildTenantManager();

        // Use the same normalized name
        var duplicate = NewTenant(tenant.Name!);
        duplicate.NormalizedName = tenant.NormalizedName;
        var result = await manager.CreateAsync(duplicate, CancellationToken.None);

        Assert.AreEqual(ResponseStatus.NotAcceptable, result.Status);
    }

    // -------------------------------------------------------------------------
    // DeleteAsync
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task DeleteAsync_ExistingTenant_ShouldSucceed() {
        var tenant = await CreateTenantAsync($"Delete Me {Guid.NewGuid()}");
        var manager = BuildTenantManager();

        var result = await manager.DeleteAsync(tenant, CancellationToken.None);

        Assert.IsTrue(result.Status.IsSuccess());
        var found = await manager.FindByIdAsync(tenant.Id, CancellationToken.None);
        Assert.IsNull(found);
    }

    [TestMethod]
    public async Task DeleteAsync_NonExistentTenant_ShouldFail() {
        var manager = BuildTenantManager();
        var ghost = NewTenant("Ghost");
        // Id not seeded in DB

        var result = await manager.DeleteAsync(ghost, CancellationToken.None);

        Assert.AreEqual(ResponseStatus.NotFound, result.Status);
    }

    [TestMethod]
    public async Task DeleteAsync_EmptyId_ShouldThrow() {
        var manager = BuildTenantManager();
        var badTenant = NewTenant("Bad");
        badTenant.Id = Guid.Empty;

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
            () => manager.DeleteAsync(badTenant, CancellationToken.None));
    }

    // -------------------------------------------------------------------------
    // UpdateAsync
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task UpdateAsync_ExistingTenant_ShouldPersistChanges() {
        var tenant = await CreateTenantAsync($"Before Update {Guid.NewGuid()}");
        var manager = BuildTenantManager();

        tenant.Name = "After Update";
        tenant.AdminEmail = "new@email.com";
        tenant.ContactInfo = "updated contact";

        var result = await manager.UpdateAsync(tenant, CancellationToken.None);

        Assert.IsTrue(result.Status.IsSuccess());
        var found = await manager.FindByIdAsync(tenant.Id, CancellationToken.None);
        Assert.IsNotNull(found);
        Assert.AreEqual("After Update", found!.Name);
        Assert.AreEqual("AFTER UPDATE", found.NormalizedName);
        Assert.AreEqual("new@email.com", found.AdminEmail);
        Assert.AreEqual("NEW@EMAIL.COM", found.NormalizedEmail);
        Assert.AreEqual("updated contact", found.ContactInfo);
    }

    [TestMethod]
    public async Task UpdateAsync_NonExistentTenant_ShouldFail() {
        var manager = BuildTenantManager();
        var ghost = NewTenant("Ghost");

        var result = await manager.UpdateAsync(ghost, CancellationToken.None);

        Assert.AreEqual(ResponseStatus.NotFound, result.Status);
    }

    [TestMethod]
    public async Task UpdateAsync_EmptyName_ShouldThrow() {
        var tenant = await CreateTenantAsync($"Has Name {Guid.NewGuid()}");
        var manager = BuildTenantManager();
        tenant.Name = "  "; // whitespace only

        await Assert.ThrowsAsync<ArgumentException>(
            () => manager.UpdateAsync(tenant, CancellationToken.None));
    }

    // -------------------------------------------------------------------------
    // FindByIdAsync
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task FindByIdAsync_ExistingTenant_ShouldReturn() {
        var manager = BuildTenantManager();

        var found = await manager.FindByIdAsync(TestContext.TenantGuid, CancellationToken.None);

        Assert.IsNotNull(found);
        Assert.AreEqual(TestContext.TenantGuid, found!.Id);
    }

    [TestMethod]
    public async Task FindByIdAsync_UnknownId_ShouldReturnNull() {
        var manager = BuildTenantManager();

        var found = await manager.FindByIdAsync(Guid.NewGuid(), CancellationToken.None);

        Assert.IsNull(found);
    }

    [TestMethod]
    public async Task FindByIdAsync_EmptyId_ShouldThrow() {
        var manager = BuildTenantManager();

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
            () => manager.FindByIdAsync(Guid.Empty, CancellationToken.None));
    }

    // -------------------------------------------------------------------------
    // FindByNameAsync
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task FindByNameAsync_ExistingTenant_ShouldReturn() {
        var manager = BuildTenantManager();

        var found = await manager.FindByNameAsync("Test Tenant", CancellationToken.None);

        Assert.IsNotNull(found);
        Assert.AreEqual(TestContext.TenantGuid, found!.Id);
    }

    [TestMethod]
    public async Task FindByNameAsync_NormalizesInput_ShouldFindWithMixedCase() {
        var manager = BuildTenantManager();

        var found = await manager.FindByNameAsync("  test tenant  ", CancellationToken.None);

        Assert.IsNotNull(found);
        Assert.AreEqual(TestContext.TenantGuid, found!.Id);
    }

    [TestMethod]
    public async Task FindByNameAsync_UnknownName_ShouldReturnNull() {
        var manager = BuildTenantManager();

        var found = await manager.FindByNameAsync("Does Not Exist XYZ", CancellationToken.None);

        Assert.IsNull(found);
    }

    // -------------------------------------------------------------------------
    // FindByEmailAsync
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task FindByEmailAsync_ExistingEmail_ShouldReturn() {
        var manager = BuildTenantManager();

        var found = await manager.FindByEmailAsync("admin@testtenant.com", CancellationToken.None);

        Assert.IsNotNull(found);
        Assert.AreEqual(TestContext.TenantGuid, found!.Id);
    }

    [TestMethod]
    public async Task FindByEmailAsync_NormalizesInput_ShouldFindWithMixedCase() {
        var manager = BuildTenantManager();

        var found = await manager.FindByEmailAsync("  ADMIN@TestTenant.COM  ", CancellationToken.None);

        Assert.IsNotNull(found);
        Assert.AreEqual(TestContext.TenantGuid, found!.Id);
    }

    [TestMethod]
    public async Task FindByEmailAsync_UnknownEmail_ShouldReturnNull() {
        var manager = BuildTenantManager();

        var found = await manager.FindByEmailAsync("nobody@nowhere.com", CancellationToken.None);

        Assert.IsNull(found);
    }

    // -------------------------------------------------------------------------
    // GetTenantsAsync
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task GetTenantsAsync_ShouldReturnSeededTenants() {
        var manager = BuildTenantManager();

        var list = await manager.GetTenantsAsync(CancellationToken.None);

        Assert.IsNotNull(list);
        Assert.IsGreaterThanOrEqualTo(2, list.Count, "At least the two seeded tenants should be returned");
    }

    // -------------------------------------------------------------------------
    // LockAsync / UnlockAsync
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task LockAsync_UnlockedTenant_ShouldSetIsLockedTrue() {
        var tenant = await CreateTenantAsync($"To Lock {Guid.NewGuid()}");
        var manager = BuildTenantManager();

        var result = await manager.LockAsync(tenant, CancellationToken.None);

        Assert.IsTrue(result.Status.IsSuccess());
        var found = await manager.FindByIdAsync(tenant.Id, CancellationToken.None);
        Assert.IsTrue(found!.IsLocked);
    }

    [TestMethod]
    public async Task LockAsync_NonExistentTenant_ShouldFail() {
        var manager = BuildTenantManager();

        var result = await manager.LockAsync(NewTenant("Ghost"), CancellationToken.None);

        Assert.AreEqual(ResponseStatus.NotFound, result.Status);
    }

    [TestMethod]
    public async Task UnlockAsync_LockedTenant_ShouldSetIsLockedFalse() {
        var manager = BuildTenantManager();
        var lockedTenant = await manager.FindByIdAsync(TestContext.LockedTenantGuid, CancellationToken.None);
        Assert.IsNotNull(lockedTenant);
        Assert.IsTrue(lockedTenant!.IsLocked);

        var result = await manager.UnlockAsync(lockedTenant, CancellationToken.None);

        Assert.IsTrue(result.Status.IsSuccess());
        var found = await manager.FindByIdAsync(TestContext.LockedTenantGuid, CancellationToken.None);
        Assert.IsFalse(found!.IsLocked);
    }

    [TestMethod]
    public async Task UnlockAsync_NonExistentTenant_ShouldFail() {
        var manager = BuildTenantManager();

        var result = await manager.UnlockAsync(NewTenant("Ghost"), CancellationToken.None);

        Assert.AreEqual(ResponseStatus.NotFound, result.Status);
    }

    // -------------------------------------------------------------------------
    // AddUserAsync / RemoveUserAsync
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task AddUserAsync_NewAssignment_ShouldSucceed() {
        var user = await CreateUserAsync($"tenant.new.{Guid.NewGuid()}");
        var tenant = await CreateTenantAsync($"Add User Tenant {Guid.NewGuid()}");
        var manager = BuildTenantManager();

        var result = await manager.AddUserAsync(user, tenant, CancellationToken.None);

        Assert.IsTrue(result.Status.IsSuccess());
        var ids = await manager.GetTenantIdsForUserAsync(user.Id, CancellationToken.None);
        Assert.IsTrue(ids.Contains(tenant.Id));
    }

    [TestMethod]
    public async Task AddUserAsync_AlreadyAssigned_ShouldBeIdempotent() {
        var user = await CreateUserAsync($"tenant.idem.{Guid.NewGuid()}");
        var tenant = await CreateTenantAsync($"Idempotent Tenant {Guid.NewGuid()}");
        var manager = BuildTenantManager();
        await manager.AddUserAsync(user, tenant, CancellationToken.None);

        // Second call — should not error
        var result = await manager.AddUserAsync(user, tenant, CancellationToken.None);

        Assert.IsTrue(result.Status.IsSuccess());
        var users = (await manager.GetUsersForTenantAsync(tenant.Id, CancellationToken.None)).ToList();
        Assert.AreEqual(1, users.Count(u => u == user.UserName));
    }

    [TestMethod]
    public async Task AddUserAsync_NonExistentUser_ShouldFail() {
        var tenant = await CreateTenantAsync($"Ghost User Tenant {Guid.NewGuid()}");
        var manager = BuildTenantManager();
        var ghost = new ApplicationUser { Id = Guid.NewGuid() };

        var result = await manager.AddUserAsync(ghost, tenant, CancellationToken.None);

        Assert.AreEqual(ResponseStatus.NotFound, result.Status);
    }

    [TestMethod]
    public async Task AddUserAsync_NonExistentTenant_ShouldFail() {
        var user = await CreateUserAsync($"tenant.ghost.{Guid.NewGuid()}");
        var manager = BuildTenantManager();

        var result = await manager.AddUserAsync(user, NewTenant("Ghost Tenant"), CancellationToken.None);

        Assert.AreEqual(ResponseStatus.NotFound, result.Status);
    }

    [TestMethod]
    public async Task RemoveUserAsync_ExistingAssignment_ShouldSucceed() {
        var user = await CreateUserAsync($"tenant.remove.{Guid.NewGuid()}");
        var tenant = await CreateTenantAsync($"Remove User Tenant {Guid.NewGuid()}");
        var manager = BuildTenantManager();
        await manager.AddUserAsync(user, tenant, CancellationToken.None);

        var result = await manager.RemoveUserAsync(user, tenant, CancellationToken.None);

        Assert.IsTrue(result.Status.IsSuccess());
        var ids = await manager.GetTenantIdsForUserAsync(user.Id, CancellationToken.None);
        Assert.IsFalse(ids.Contains(tenant.Id));
    }

    [TestMethod]
    public async Task RemoveUserAsync_NotAssigned_ShouldBeIdempotent() {
        var user = await CreateUserAsync($"tenant.notassigned.{Guid.NewGuid()}");
        var tenant = await CreateTenantAsync($"No Assignment Tenant {Guid.NewGuid()}");
        var manager = BuildTenantManager();

        var result = await manager.RemoveUserAsync(user, tenant, CancellationToken.None);

        Assert.IsTrue(result.Status.IsSuccess());
    }

    // -------------------------------------------------------------------------
    // GetUsersForTenantAsync / GetTenantIdsForUserAsync
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task GetUsersForTenantAsync_ShouldReturnAssignedUsers() {
        var manager = BuildTenantManager();

        var users = (await manager.GetUsersForTenantAsync(TestContext.TenantGuid, CancellationToken.None)).ToList();

        Assert.IsTrue(users.Count >= 1, "The seeded admin user should be returned");
        Assert.IsTrue(users.Contains("admin", StringComparer.OrdinalIgnoreCase));
    }

    [TestMethod]
    public async Task GetUsersForTenantAsync_LockedTenant_ShouldReturnEmpty() {
        var manager = BuildTenantManager();

        // TenantUsersAsync skips locked tenants
        var users = await manager.GetUsersForTenantAsync(TestContext.LockedTenantGuid, CancellationToken.None);

        Assert.IsFalse(users.Any());
    }

    [TestMethod]
    public async Task GetTenantIdsForUserAsync_ShouldReturnAssignedTenants() {
        var manager = BuildTenantManager();
        var adminId = Guid.Parse("11111111-1111-1111-1111-111111111111");

        var ids = (await manager.GetTenantIdsForUserAsync(adminId, CancellationToken.None)).ToList();

        Assert.IsTrue(ids.Contains(TestContext.TenantGuid));
        Assert.IsTrue(ids.Contains(TestContext.LockedTenantGuid));
    }

    [TestMethod]
    public async Task GetTenantIdsForUserAsync_UnknownUser_ShouldReturnEmpty() {
        var manager = BuildTenantManager();

        var ids = await manager.GetTenantIdsForUserAsync(Guid.NewGuid(), CancellationToken.None);

        Assert.IsFalse(ids.Any());
    }

    // -------------------------------------------------------------------------
    // CanSignInAsync
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task CanSignInAsync_ActiveUserActiveTenant_ShouldReturnTrue() {
        var manager = BuildTenantManager();
        var adminId = Guid.Parse("11111111-1111-1111-1111-111111111111");

        var canSignIn = await manager.CanSignInAsync(adminId, TestContext.TenantGuid, CancellationToken.None);

        Assert.IsTrue(canSignIn);
    }

    [TestMethod]
    public async Task CanSignInAsync_ActiveUserLockedTenant_ShouldReturnFalse() {
        var manager = BuildTenantManager();
        var adminId = Guid.Parse("11111111-1111-1111-1111-111111111111");

        var canSignIn = await manager.CanSignInAsync(adminId, TestContext.LockedTenantGuid, CancellationToken.None);

        Assert.IsFalse(canSignIn);
    }

    [TestMethod]
    public async Task CanSignInAsync_UserNotAssignedToTenant_ShouldReturnFalse() {
        var user = await CreateUserAsync($"unassigned.{Guid.NewGuid()}");
        var manager = BuildTenantManager();

        var canSignIn = await manager.CanSignInAsync(user.Id, TestContext.TenantGuid, CancellationToken.None);

        Assert.IsFalse(canSignIn);
    }

    [TestMethod]
    public async Task CanSignInAsync_EmptyUserId_ShouldThrow() {
        var manager = BuildTenantManager();

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
            () => manager.CanSignInAsync(Guid.Empty, TestContext.TenantGuid, CancellationToken.None));
    }

    [TestMethod]
    public async Task CanSignInAsync_EmptyTenantId_ShouldThrow() {
        var manager = BuildTenantManager();
        var adminId = Guid.Parse("11111111-1111-1111-1111-111111111111");

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
            () => manager.CanSignInAsync(adminId, Guid.Empty, CancellationToken.None));
    }
}
