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
    // AddUserAsync — isAdmin overload
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task AddUserAsync_WithIsAdminTrue_ShouldSetAdminFlag() {
        var user = await CreateUserAsync($"admin.add.{Guid.NewGuid()}");
        var tenant = await CreateTenantAsync($"Admin Add Tenant {Guid.NewGuid()}");
        var manager = BuildTenantManager();

        await manager.AddUserAsync(user, tenant, isAdmin: true, CancellationToken.None);

        Assert.IsTrue(await manager.IsAdminAsync(user.Id, tenant.Id, CancellationToken.None));
    }

    [TestMethod]
    public async Task AddUserAsync_WithIsAdminFalse_ShouldNotSetAdminFlag() {
        var user = await CreateUserAsync($"member.add.{Guid.NewGuid()}");
        var tenant = await CreateTenantAsync($"Member Add Tenant {Guid.NewGuid()}");
        var manager = BuildTenantManager();

        await manager.AddUserAsync(user, tenant, isAdmin: false, CancellationToken.None);

        Assert.IsFalse(await manager.IsAdminAsync(user.Id, tenant.Id, CancellationToken.None));
    }

    [TestMethod]
    public async Task AddUserAsync_WithoutIsAdminParam_ShouldDefaultToNonAdmin() {
        var user = await CreateUserAsync($"default.add.{Guid.NewGuid()}");
        var tenant = await CreateTenantAsync($"Default Add Tenant {Guid.NewGuid()}");
        var manager = BuildTenantManager();

        await manager.AddUserAsync(user, tenant, CancellationToken.None);

        Assert.IsFalse(await manager.IsAdminAsync(user.Id, tenant.Id, CancellationToken.None));
    }

    [TestMethod]
    public async Task AddUserAsync_AlreadyAssignedAsRegular_PromoteToAdmin_ShouldUpdateFlag() {
        var user = await CreateUserAsync($"promote.{Guid.NewGuid()}");
        var tenant = await CreateTenantAsync($"Promote Tenant {Guid.NewGuid()}");
        var manager = BuildTenantManager();
        await manager.AddUserAsync(user, tenant, isAdmin: false, CancellationToken.None);

        var result = await manager.AddUserAsync(user, tenant, isAdmin: true, CancellationToken.None);

        Assert.IsTrue(result.Status.IsSuccess());
        Assert.IsTrue(await manager.IsAdminAsync(user.Id, tenant.Id, CancellationToken.None));
    }

    [TestMethod]
    public async Task AddUserAsync_AlreadyAssigned_SameIsAdmin_ShouldBeIdempotent() {
        var user = await CreateUserAsync($"idem.admin.{Guid.NewGuid()}");
        var tenant = await CreateTenantAsync($"Idem Admin Tenant {Guid.NewGuid()}");
        var manager = BuildTenantManager();
        await manager.AddUserAsync(user, tenant, isAdmin: true, CancellationToken.None);

        var result = await manager.AddUserAsync(user, tenant, isAdmin: true, CancellationToken.None);

        Assert.IsTrue(result.Status.IsSuccess());
        Assert.IsTrue(await manager.IsAdminAsync(user.Id, tenant.Id, CancellationToken.None));
    }

    // -------------------------------------------------------------------------
    // SetAdminAsync
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task SetAdminAsync_GrantAdmin_ShouldSucceed() {
        var user = await CreateUserAsync($"grant.admin.{Guid.NewGuid()}");
        var tenant = await CreateTenantAsync($"Grant Admin Tenant {Guid.NewGuid()}");
        var manager = BuildTenantManager();
        await manager.AddUserAsync(user, tenant, isAdmin: false, CancellationToken.None);

        var result = await manager.SetAdminAsync(user, tenant, isAdmin: true, CancellationToken.None);

        Assert.IsTrue(result.Status.IsSuccess());
        Assert.IsTrue(await manager.IsAdminAsync(user.Id, tenant.Id, CancellationToken.None));
    }

    [TestMethod]
    public async Task SetAdminAsync_RevokeAdmin_ShouldSucceed() {
        var user = await CreateUserAsync($"revoke.admin.{Guid.NewGuid()}");
        var tenant = await CreateTenantAsync($"Revoke Admin Tenant {Guid.NewGuid()}");
        var manager = BuildTenantManager();
        await manager.AddUserAsync(user, tenant, isAdmin: true, CancellationToken.None);

        var result = await manager.SetAdminAsync(user, tenant, isAdmin: false, CancellationToken.None);

        Assert.IsTrue(result.Status.IsSuccess());
        Assert.IsFalse(await manager.IsAdminAsync(user.Id, tenant.Id, CancellationToken.None));
    }

    [TestMethod]
    public async Task SetAdminAsync_AlreadySameValue_ShouldBeNoOp() {
        var user = await CreateUserAsync($"noop.admin.{Guid.NewGuid()}");
        var tenant = await CreateTenantAsync($"NoOp Admin Tenant {Guid.NewGuid()}");
        var manager = BuildTenantManager();
        await manager.AddUserAsync(user, tenant, isAdmin: true, CancellationToken.None);

        var result = await manager.SetAdminAsync(user, tenant, isAdmin: true, CancellationToken.None);

        Assert.IsTrue(result.Status.IsSuccess());
        Assert.IsTrue(await manager.IsAdminAsync(user.Id, tenant.Id, CancellationToken.None));
    }

    [TestMethod]
    public async Task SetAdminAsync_NonMember_ShouldFail() {
        var user = await CreateUserAsync($"nonmember.admin.{Guid.NewGuid()}");
        var tenant = await CreateTenantAsync($"NonMember Admin Tenant {Guid.NewGuid()}");
        var manager = BuildTenantManager();
        // user is never added to tenant

        var result = await manager.SetAdminAsync(user, tenant, isAdmin: true, CancellationToken.None);

        Assert.AreEqual(ResponseStatus.NotFound, result.Status);
    }

    [TestMethod]
    public async Task SetAdminAsync_EmptyUserId_ShouldThrow() {
        var tenant = await CreateTenantAsync($"SetAdmin Throw Tenant {Guid.NewGuid()}");
        var manager = BuildTenantManager();
        var ghost = new ApplicationUser { Id = Guid.Empty };

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
            () => manager.SetAdminAsync(ghost, tenant, isAdmin: true, CancellationToken.None));
    }

    // -------------------------------------------------------------------------
    // IsAdminAsync
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task IsAdminAsync_AdminUser_ShouldReturnTrue() {
        var adminId = Guid.Parse("11111111-1111-1111-1111-111111111111");
        var manager = BuildTenantManager();

        var isAdmin = await manager.IsAdminAsync(adminId, TestContext.TenantGuid, CancellationToken.None);

        Assert.IsTrue(isAdmin);
    }

    [TestMethod]
    public async Task IsAdminAsync_RegularMember_ShouldReturnFalse() {
        var user = await CreateUserAsync($"regular.check.{Guid.NewGuid()}");
        var tenant = await CreateTenantAsync($"Regular Check Tenant {Guid.NewGuid()}");
        var manager = BuildTenantManager();
        await manager.AddUserAsync(user, tenant, isAdmin: false, CancellationToken.None);

        var isAdmin = await manager.IsAdminAsync(user.Id, tenant.Id, CancellationToken.None);

        Assert.IsFalse(isAdmin);
    }

    [TestMethod]
    public async Task IsAdminAsync_NonMember_ShouldReturnFalse() {
        var user = await CreateUserAsync($"nonmember.check.{Guid.NewGuid()}");
        var tenant = await CreateTenantAsync($"NonMember Check Tenant {Guid.NewGuid()}");
        var manager = BuildTenantManager();
        // user is never added to tenant

        var isAdmin = await manager.IsAdminAsync(user.Id, tenant.Id, CancellationToken.None);

        Assert.IsFalse(isAdmin);
    }

    [TestMethod]
    public async Task IsAdminAsync_AdminInOneTenant_IsNotAdminInAnother() {
        var user = await CreateUserAsync($"cross.tenant.{Guid.NewGuid()}");
        var tenantA = await CreateTenantAsync($"Tenant A {Guid.NewGuid()}");
        var tenantB = await CreateTenantAsync($"Tenant B {Guid.NewGuid()}");
        var manager = BuildTenantManager();
        await manager.AddUserAsync(user, tenantA, isAdmin: true, CancellationToken.None);
        await manager.AddUserAsync(user, tenantB, isAdmin: false, CancellationToken.None);

        Assert.IsTrue(await manager.IsAdminAsync(user.Id, tenantA.Id, CancellationToken.None));
        Assert.IsFalse(await manager.IsAdminAsync(user.Id, tenantB.Id, CancellationToken.None));
    }

    // -------------------------------------------------------------------------
    // GetAdminsForTenantAsync
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task GetAdminsForTenantAsync_ShouldReturnOnlyAdmins() {
        var admin = await CreateUserAsync($"getadmin.admin.{Guid.NewGuid()}");
        var member = await CreateUserAsync($"getadmin.member.{Guid.NewGuid()}");
        var tenant = await CreateTenantAsync($"GetAdmins Tenant {Guid.NewGuid()}");
        var manager = BuildTenantManager();
        await manager.AddUserAsync(admin, tenant, isAdmin: true, CancellationToken.None);
        await manager.AddUserAsync(member, tenant, isAdmin: false, CancellationToken.None);

        var admins = (await manager.GetAdminsForTenantAsync(tenant.Id, CancellationToken.None)).ToList();

        Assert.IsTrue(admins.Contains(admin.Id));
        Assert.IsFalse(admins.Contains(member.Id));
    }

    [TestMethod]
    public async Task GetAdminsForTenantAsync_MultipleAdmins_ShouldReturnAll() {
        var adminA = await CreateUserAsync($"multi.adminA.{Guid.NewGuid()}");
        var adminB = await CreateUserAsync($"multi.adminB.{Guid.NewGuid()}");
        var tenant = await CreateTenantAsync($"Multi Admin Tenant {Guid.NewGuid()}");
        var manager = BuildTenantManager();
        await manager.AddUserAsync(adminA, tenant, isAdmin: true, CancellationToken.None);
        await manager.AddUserAsync(adminB, tenant, isAdmin: true, CancellationToken.None);

        var admins = (await manager.GetAdminsForTenantAsync(tenant.Id, CancellationToken.None)).ToList();

        Assert.IsTrue(admins.Contains(adminA.Id));
        Assert.IsTrue(admins.Contains(adminB.Id));
        Assert.AreEqual(2, admins.Count);
    }

    [TestMethod]
    public async Task GetAdminsForTenantAsync_EmptyTenantId_ShouldThrow() {
        var manager = BuildTenantManager();

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
            () => manager.GetAdminsForTenantAsync(Guid.Empty, CancellationToken.None));
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

        // TenantGetUsers skips locked tenants
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

        var canSignIn = await manager.ApplicationUserCanSignIn(adminId, TestContext.TenantGuid, CancellationToken.None);

        Assert.IsTrue(canSignIn);
    }

    [TestMethod]
    public async Task CanSignInAsync_ActiveUserLockedTenant_ShouldReturnFalse() {
        var manager = BuildTenantManager();
        var adminId = Guid.Parse("11111111-1111-1111-1111-111111111111");

        var canSignIn = await manager.ApplicationUserCanSignIn(adminId, TestContext.LockedTenantGuid, CancellationToken.None);

        Assert.IsFalse(canSignIn);
    }

    [TestMethod]
    public async Task CanSignInAsync_UserNotAssignedToTenant_ShouldReturnFalse() {
        var user = await CreateUserAsync($"unassigned.{Guid.NewGuid()}");
        var manager = BuildTenantManager();

        var canSignIn = await manager.ApplicationUserCanSignIn(user.Id, TestContext.TenantGuid, CancellationToken.None);

        Assert.IsFalse(canSignIn);
    }

    [TestMethod]
    public async Task CanSignInAsync_EmptyUserId_ShouldThrow() {
        var manager = BuildTenantManager();

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
            () => manager.ApplicationUserCanSignIn(Guid.Empty, TestContext.TenantGuid, CancellationToken.None));
    }

    [TestMethod]
    public async Task CanSignInAsync_EmptyTenantId_ShouldThrow() {
        var manager = BuildTenantManager();
        var adminId = Guid.Parse("11111111-1111-1111-1111-111111111111");

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
            () => manager.ApplicationUserCanSignIn(adminId, Guid.Empty, CancellationToken.None));
    }

    // -------------------------------------------------------------------------
    // GetSecretOwner
    // -------------------------------------------------------------------------

    /// <summary>
    /// Creates a tenant and directly injects <paramref name="keyMaterial"/> into
    /// its <c>SecretKeyMaterial</c> column via the identity context.
    /// </summary>
    private async Task<ApplicationTenant> CreateTenantWithKeyMaterialAsync(string name, byte[] keyMaterial) {
        var tenant = await CreateTenantAsync(name);
        var factory = serviceProvider.GetRequiredService<IIdentityContextFactory>();
        using var ctx = await factory.CreateAsync("IdentityDb");
        var record = await ctx.TenantFindRecord(tenant.Id, CancellationToken.None);
        record!.SecretKeyMaterial = keyMaterial;
        await ctx.Complete();
        return tenant;
    }

    [TestMethod]
    public async Task GetSecretOwner_UnknownId_ShouldReturnNull() {
        var manager = BuildTenantManager();

        var owner = await manager.GetSecretOwner(Guid.NewGuid(), CancellationToken.None);

        Assert.IsNull(owner);
    }

    [TestMethod]
    public async Task GetSecretOwner_TenantWithoutKeyMaterial_ShouldThrow() {
        // The seeded tenant has no SecretKeyMaterial set.
        var manager = BuildTenantManager();

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => manager.GetSecretOwner(TestContext.TenantGuid, CancellationToken.None));
    }

    [TestMethod]
    public async Task GetSecretOwner_TenantWithKeyMaterial_ShouldReturnOwner() {
        var keyMaterial = RandomNumberGenerator.GetBytes(32);
        var tenant = await CreateTenantWithKeyMaterialAsync($"SecretTenant {Guid.NewGuid()}", keyMaterial);
        var manager = BuildTenantManager();

        var owner = await manager.GetSecretOwner(tenant.Id, CancellationToken.None);

        Assert.IsNotNull(owner);
        Assert.AreEqual(tenant.Id, owner!.Id);
        Assert.AreEqual(OwnerTypeCode.Tenant, owner.Type);
        Assert.IsTrue(owner.OwnerSecret.ArraysAreEqual(keyMaterial));
    }

    [TestMethod]
    public async Task GetSecretOwner_TenantWithKeyMaterial_TypeShouldBeTenant() {
        var tenant = await CreateTenantWithKeyMaterialAsync($"TypeCheck {Guid.NewGuid()}", RandomNumberGenerator.GetBytes(32));
        var manager = BuildTenantManager();

        var owner = await manager.GetSecretOwner(tenant.Id, CancellationToken.None);

        Assert.AreEqual(OwnerTypeCode.Tenant, owner!.Type);
    }
}
