using Microsoft.AspNetCore.Identity;

using N2.Core.Commands;
using N2.Core.Identity.Data;

namespace N2.Core.Identity.UnitTests;

/// <summary>
/// Tests for actual database functionality using the in-memory provider.
/// Covers CRUD operations, query methods, change logs, and health checks
/// that verify the context behaves correctly as a data layer.
/// </summary>
[TestClass]
public class N2IdentityContextTests : N2IdentityTestsBase {
    private static readonly Guid AdminGuid = Guid.Parse("11111111-1111-1111-1111-111111111111");

    // -------------------------------------------------------------------------
    // User persistence
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task AddApplicationUserAsync_NewUser_ShouldPersistAndBeRetrievable() {
        using var context = await GetIdentityContext();
        var user = new ApplicationUser {
            Id = Guid.NewGuid(),
            UserName = "newuser_ctx",
            NormalizedUserName = "NEWUSER_CTX",
            Email = "newuser_ctx@test.com",
            NormalizedEmail = "NEWUSER_CTX@TEST.COM",
            SecurityStamp = Guid.NewGuid().ToString()
        };

        var count = await context.AddApplicationUserAsync(user, CancellationToken.None);

        Assert.IsTrue(count > 0, "SaveChanges should report at least one row affected.");
        var retrieved = await context.ApplicationUserAsync(user.Id, CancellationToken.None);
        Assert.IsNotNull(retrieved);
        Assert.AreEqual(user.UserName, retrieved.UserName);
    }

    [TestMethod]
    public async Task AddApplicationUserAsync_ExtendedProperties_ShouldRoundTrip() {
        using var context = await GetIdentityContext();
        var user = new ApplicationUser {
            Id = Guid.NewGuid(),
            UserName = "extprops_user",
            NormalizedUserName = "EXTPROPS_USER",
            Email = "extprops@test.com",
            NormalizedEmail = "EXTPROPS@TEST.COM",
            SecurityStamp = Guid.NewGuid().ToString(),
            FirstName = "Jane",
            LastName = "Doe",
            MiddleName = "M",
            DisplayName = "Jane M. Doe",
            ImagePath = "/images/jane.png",
            MfaType = MultiFactorType.Email,
            MfaConfirmed = false
        };

        await context.AddApplicationUserAsync(user, CancellationToken.None);

        var retrieved = await context.ApplicationUserAsync(user.Id, CancellationToken.None);
        Assert.IsNotNull(retrieved);
        Assert.AreEqual("Jane", retrieved.FirstName);
        Assert.AreEqual("Doe", retrieved.LastName);
        Assert.AreEqual("M", retrieved.MiddleName);
        Assert.AreEqual("Jane M. Doe", retrieved.DisplayName);
        Assert.AreEqual("/images/jane.png", retrieved.ImagePath);
        Assert.AreEqual(MultiFactorType.Email, retrieved.MfaType);
        Assert.IsFalse(retrieved.MfaConfirmed);
    }

    [TestMethod]
    public async Task RemoveApplicationUser_ExistingUser_ShouldNotBeRetrievableAfterComplete() {
        using var context = await GetIdentityContext();

        // Add a user to remove
        var user = new ApplicationUser {
            Id = Guid.NewGuid(),
            UserName = "to_remove_user",
            NormalizedUserName = "TO_REMOVE_USER",
            Email = "to_remove@test.com",
            NormalizedEmail = "TO_REMOVE@TEST.COM",
            SecurityStamp = Guid.NewGuid().ToString()
        };
        await context.AddApplicationUserAsync(user, CancellationToken.None);

        context.RemoveApplicationUser(user);
        var (status, _) = await context.Complete();

        Assert.AreEqual(ResponseStatus.Success, status);
        var retrieved = await context.ApplicationUserAsync(user.Id, CancellationToken.None);
        Assert.IsNull(retrieved);
    }

    // -------------------------------------------------------------------------
    // Role persistence
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task AddApplicationRoleAsync_NewRole_ShouldPersistAndBeRetrievable() {
        using var context = await GetIdentityContext();
        var role = new ApplicationRole {
            Id = Guid.NewGuid(),
            Name = "NewRole_ctx",
            NormalizedName = "NEWROLE_CTX"
        };

        var count = await context.AddApplicationRoleAsync(role, CancellationToken.None);

        Assert.IsTrue(count > 0);
        var retrieved = await context.ApplicationRoleAsync("NEWROLE_CTX", CancellationToken.None);
        Assert.IsNotNull(retrieved);
        Assert.AreEqual("NewRole_ctx", retrieved.Name);
    }

    [TestMethod]
    public async Task RemoveApplicationRole_ExistingRole_ShouldNotBeRetrievableAfterComplete() {
        using var context = await GetIdentityContext();
        var role = new ApplicationRole {
            Id = Guid.NewGuid(),
            Name = "ToRemove_role",
            NormalizedName = "TOREMOVE_ROLE"
        };
        await context.AddApplicationRoleAsync(role, CancellationToken.None);

        context.RemoveApplicationRole(role);
        var (status, _) = await context.Complete();

        Assert.AreEqual(ResponseStatus.Success, status);
        var retrieved = await context.ApplicationRoleAsync("TOREMOVE_ROLE", CancellationToken.None);
        Assert.IsNull(retrieved);
    }

    // -------------------------------------------------------------------------
    // User-role assignment
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task AddIdentityUserRoleAsync_ShouldPersistAndBeRetrievable() {
        using var context = await GetIdentityContext();
        var userId = Guid.NewGuid();
        var roleId = Guid.NewGuid();

        var user = new ApplicationUser {
            Id = userId,
            UserName = "role_assign_user",
            NormalizedUserName = "ROLE_ASSIGN_USER",
            Email = "role_assign@test.com",
            NormalizedEmail = "ROLE_ASSIGN@TEST.COM",
            SecurityStamp = Guid.NewGuid().ToString()
        };
        var role = new ApplicationRole {
            Id = roleId,
            Name = "RoleAssignTest",
            NormalizedName = "ROLEASSIGNTEST"
        };
        await context.AddApplicationUserAsync(user, CancellationToken.None);
        await context.AddApplicationRoleAsync(role, CancellationToken.None);

        var userRole = new IdentityUserRole<Guid> { UserId = userId, RoleId = roleId };
        var count = await context.AddIdentityUserRoleAsync(userRole, CancellationToken.None);

        Assert.IsTrue(count > 0);
        var retrieved = await context.IdentityUserRoleAsync(userId, roleId, CancellationToken.None);
        Assert.IsNotNull(retrieved);
        Assert.AreEqual(userId, retrieved.UserId);
        Assert.AreEqual(roleId, retrieved.RoleId);
    }

    [TestMethod]
    public async Task RemoveApplicationUserRole_ShouldNotBeRetrievableAfterComplete() {
        using var context = await GetIdentityContext();
        var userId = Guid.NewGuid();
        var roleId = Guid.NewGuid();

        var user = new ApplicationUser {
            Id = userId,
            UserName = "role_remove_user",
            NormalizedUserName = "ROLE_REMOVE_USER",
            Email = "role_remove@test.com",
            NormalizedEmail = "ROLE_REMOVE@TEST.COM",
            SecurityStamp = Guid.NewGuid().ToString()
        };
        var role = new ApplicationRole {
            Id = roleId,
            Name = "RoleRemoveTest",
            NormalizedName = "ROLEREMOVETEST"
        };
        await context.AddApplicationUserAsync(user, CancellationToken.None);
        await context.AddApplicationRoleAsync(role, CancellationToken.None);

        var userRole = new IdentityUserRole<Guid> { UserId = userId, RoleId = roleId };
        await context.AddIdentityUserRoleAsync(userRole, CancellationToken.None);

        context.RemoveApplicationUserRole(userRole);
        await context.Complete();

        var retrieved = await context.IdentityUserRoleAsync(userId, roleId, CancellationToken.None);
        Assert.IsNull(retrieved);
    }

    // -------------------------------------------------------------------------
    // Lookup queries on seeded data
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task ApplicationUserAsync_ByNormalizedName_SeededAdmin_ShouldReturn() {
        using var context = await GetIdentityContext();

        var user = await context.ApplicationUserAsync("ADMIN", CancellationToken.None);

        Assert.IsNotNull(user);
        Assert.AreEqual("admin", user.UserName);
    }

    [TestMethod]
    public async Task ApplicationUserAsync_ByGuid_SeededAdmin_ShouldReturn() {
        using var context = await GetIdentityContext();

        var user = await context.ApplicationUserAsync(AdminGuid, CancellationToken.None);

        Assert.IsNotNull(user);
        Assert.AreEqual("admin", user.UserName);
    }

    [TestMethod]
    public async Task ApplicationUserByEmailAsync_SeededAdmin_ShouldReturn() {
        using var context = await GetIdentityContext();

        var user = await context.ApplicationUserByEmailAsync("ADMIN@EMAIL.COM", CancellationToken.None);

        Assert.IsNotNull(user);
        Assert.AreEqual("admin", user.UserName);
    }

    [TestMethod]
    public async Task ApplicationRoleAsync_SeededSysAdmin_ShouldReturn() {
        using var context = await GetIdentityContext();

        var role = await context.ApplicationRoleAsync("SYSADMIN", CancellationToken.None);

        Assert.IsNotNull(role);
        Assert.AreEqual("SysAdmin", role.Name);
    }

    [TestMethod]
    public async Task FindByNameAsync_SeededAdmin_ShouldReturnSuccess() {
        using var context = await GetIdentityContext();

        var result = await context.FindByNameAsync("ADMIN", CancellationToken.None);

        Assert.AreEqual(ResponseStatus.Success, result.Status);
        Assert.IsNotNull(result.Value);
        Assert.AreEqual(AdminGuid, result.Value.Id);
    }

    [TestMethod]
    public async Task FindByNameAsync_NonExistentUser_ShouldReturnNotFound() {
        using var context = await GetIdentityContext();

        var result = await context.FindByNameAsync("DOESNOTEXIST", CancellationToken.None);

        Assert.AreNotEqual(ResponseStatus.Success, result.Status);
    }

    [TestMethod]
    public async Task FindByIdAsync_SeededAdmin_ShouldReturn() {
        using var context = await GetIdentityContext();

        var user = await context.FindByIdAsync(AdminGuid, CancellationToken.None);

        Assert.IsNotNull(user);
        Assert.AreEqual("admin", user.UserName);
    }

    [TestMethod]
    public async Task FindByEmailAsync_SeededAdmin_ShouldReturn() {
        using var context = await GetIdentityContext();

        var user = await context.FindByEmailAsync("ADMIN@EMAIL.COM", CancellationToken.None);

        Assert.IsNotNull(user);
        Assert.AreEqual(AdminGuid, user.Id);
    }

    // -------------------------------------------------------------------------
    // Sign-in eligibility
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task CanSignInAsync_ActiveUser_ShouldReturnTrue() {
        using var context = await GetIdentityContext();

        var canSignIn = await context.CanSignInAsync(AdminGuid);

        Assert.IsTrue(canSignIn);
    }

    [TestMethod]
    public async Task CanSignInAsync_LockedOutUser_ShouldReturnFalse() {
        using var context = await GetIdentityContext();
        var lockedOutUser = await context.ApplicationUserAsync("LOCKEDOUT", CancellationToken.None);
        Assert.IsNotNull(lockedOutUser, "Seeded locked-out user must exist.");

        var canSignIn = await context.CanSignInAsync(lockedOutUser.Id);

        Assert.IsFalse(canSignIn);
    }

    [TestMethod]
    public async Task CanSignInAsync_UnknownUser_ShouldReturnFalse() {
        using var context = await GetIdentityContext();

        var canSignIn = await context.CanSignInAsync(Guid.NewGuid());

        Assert.IsFalse(canSignIn);
    }

    [TestMethod]
    public async Task CanSignInTenantAsync_ActiveUserInActiveTenant_ShouldReturnTrue() {
        using var context = await GetIdentityContext();

        var canSignIn = await context.CanSignInTenantAsync(AdminGuid, TestContext.TenantGuid);

        Assert.IsTrue(canSignIn);
    }

    [TestMethod]
    public async Task CanSignInTenantAsync_ActiveUserInLockedTenant_ShouldReturnFalse() {
        using var context = await GetIdentityContext();

        var canSignIn = await context.CanSignInTenantAsync(AdminGuid, TestContext.LockedTenantGuid);

        Assert.IsFalse(canSignIn);
    }

    [TestMethod]
    public async Task CanSignInTenantAsync_ActiveUserNotLinkedToTenant_ShouldReturnFalse() {
        using var context = await GetIdentityContext();

        var canSignIn = await context.CanSignInTenantAsync(AdminGuid, Guid.NewGuid());

        Assert.IsFalse(canSignIn);
    }

    [TestMethod]
    public async Task CanSignInTenantAsync_LockedOutUser_ShouldReturnFalse() {
        using var context = await GetIdentityContext();
        var lockedOutUser = await context.ApplicationUserAsync("LOCKEDOUT", CancellationToken.None);
        Assert.IsNotNull(lockedOutUser, "Seeded locked-out user must exist.");

        var canSignIn = await context.CanSignInTenantAsync(lockedOutUser.Id, TestContext.TenantGuid);

        Assert.IsFalse(canSignIn);
    }

    [TestMethod]
    public async Task CanSignInTenantAsync_UnknownUser_ShouldReturnFalse() {
        using var context = await GetIdentityContext();

        var canSignIn = await context.CanSignInTenantAsync(Guid.NewGuid(), TestContext.TenantGuid);

        Assert.IsFalse(canSignIn);
    }

    // -------------------------------------------------------------------------
    // Role membership queries
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task UserRolesAsync_SeededAdminWithSysAdmin_ShouldContainRole() {
        using var context = await GetIdentityContext();

        var roles = await context.UserRolesAsync(AdminGuid);

        Assert.IsTrue(roles.Any(r => r == "SysAdmin"), "Admin should have the SysAdmin role.");
    }

    [TestMethod]
    public async Task UserRolesAsync_UserWithNoRoles_ShouldReturnEmpty() {
        using var context = await GetIdentityContext();
        var userId = Guid.NewGuid();
        var user = new ApplicationUser {
            Id = userId,
            UserName = "noroles_user",
            NormalizedUserName = "NOROLES_USER",
            Email = "noroles@test.com",
            NormalizedEmail = "NOROLES@TEST.COM",
            SecurityStamp = Guid.NewGuid().ToString()
        };
        await context.AddApplicationUserAsync(user, CancellationToken.None);

        var roles = await context.UserRolesAsync(userId);

        Assert.IsFalse(roles.Any());
    }

    // -------------------------------------------------------------------------
    // Display name resolution
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task GetNameForUserAsync_SeededAdmin_ShouldReturnNonEmptyName() {
        using var context = await GetIdentityContext();

        var name = await context.GetNameForUserAsync(AdminGuid);

        Assert.IsFalse(string.IsNullOrWhiteSpace(name));
    }

    // -------------------------------------------------------------------------
    // Select-list helpers
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task RolesAsync_ShouldReturnSeededRoles() {
        using var context = await GetIdentityContext();

        var roles = await context.RolesAsync();

        Assert.IsNotNull(roles);
        Assert.IsTrue(roles.Any(), "At least the seeded roles should be present.");
    }

    [TestMethod]
    public async Task UsersAsync_ShouldReturnSeededUsers() {
        using var context = await GetIdentityContext();

        var users = await context.UsersAsync();

        Assert.IsNotNull(users);
        Assert.IsTrue(users.Any(), "At least the seeded users should be present.");
    }

    // -------------------------------------------------------------------------
    // Change log
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task AddChangeLog_ShouldAppearInChangeLogs() {
        using var context = await GetIdentityContext();
        var entry = new QueueLogEntry {
            LogRecordId = Guid.NewGuid(),
            ReferenceId = Guid.NewGuid(),
            Message = "Test change",
            CreatedBy = AdminGuid,
            CreatedByName = "admin",
            TableName = nameof(ApplicationUser),
            Created = DateTime.UtcNow
        };

        context.AddChangeLog(entry);

        Assert.IsTrue(context.ChangeLogs.Any(l => l.Message == "Test change"));
    }

    [TestMethod]
    public async Task AddChangeLog_Generic_ShouldAppearInChangeLogs() {
        using var context = await GetIdentityContext();

        context.AddChangeLog<ApplicationUser>(Guid.NewGuid(), "Generic log entry", AdminGuid, "admin");

        Assert.IsTrue(context.ChangeLogs.Any(l => l.Message == "Generic log entry"));
    }

    [TestMethod]
    public async Task ChangeLogs_MaxLogSize_ShouldNotExceedConfiguredLimit() {
        using var context = await GetIdentityContext();
        context.MaxLogSize = 5;

        for (var i = 0; i < 10; i++) {
            context.AddChangeLog(new QueueLogEntry {
                LogRecordId = Guid.NewGuid(),
                ReferenceId = Guid.NewGuid(),
                Message = $"Entry {i}",
                CreatedBy = AdminGuid,
                CreatedByName = "admin",
                TableName = nameof(ApplicationUser),
                Created = DateTime.UtcNow
            });
        }

        Assert.IsTrue(context.ChangeLogs.Count() <= context.MaxLogSize,
            "Change log must not exceed the configured MaxLogSize.");
    }

    // -------------------------------------------------------------------------
    // Health check
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task Health_InMemoryDatabase_ShouldReturnSuccess() {
        using var context = await GetIdentityContext();

        var health = context.Health();

        Assert.IsNotNull(health);
        Assert.AreEqual((int)ResponseStatus.Success, health.StatusCode);
    }

    // -------------------------------------------------------------------------
    // Complete / unit-of-work
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task Complete_WithPendingChanges_ShouldReturnSuccess() {
        using var context = await GetIdentityContext();
        var role = new ApplicationRole {
            Id = Guid.NewGuid(),
            Name = "CompleteTestRole",
            NormalizedName = "COMPLETETESTROLE"
        };
        await context.AddApplicationRoleAsync(role, CancellationToken.None);

        // Mutate directly to produce a pending change for Complete()
        var retrieved = await context.ApplicationRoleAsync("COMPLETETESTROLE", CancellationToken.None);
        Assert.IsNotNull(retrieved);
        retrieved.Name = "CompleteTestRole_Updated";

        var (status, message) = await context.Complete();

        Assert.AreEqual(ResponseStatus.Success, status);
        Assert.IsNotNull(message);
    }
}
