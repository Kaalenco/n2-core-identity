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
public class UsingN2IdentityContext : N2IdentityTestsBase {
    private static readonly Guid AdminGuid = Guid.Parse("11111111-1111-1111-1111-111111111111");

    // -------------------------------------------------------------------------
    // User persistence
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task ApplicationUserAdd_NewUser_ShouldPersistAndBeRetrievable() {
        using var context = await GetIdentityContext();
        var user = new ApplicationUser {
            Id = Guid.NewGuid(),
            UserName = "newuser_ctx",
            NormalizedUserName = "NEWUSER_CTX",
            Email = "newuser_ctx@test.com",
            NormalizedEmail = "NEWUSER_CTX@TEST.COM",
            SecurityStamp = Guid.NewGuid().ToString()
        };

        var count = await context.UserAdd(user, CancellationToken.None);

        Assert.IsTrue(count > 0, "SaveChanges should report at least one row affected.");
        var retrieved = await context.UserFindRecord(user.Id, CancellationToken.None);
        Assert.IsNotNull(retrieved);
        Assert.AreEqual(user.UserName, retrieved.UserName);
    }

    [TestMethod]
    public async Task ApplicationUserAdd_ExtendedProperties_ShouldRoundTrip() {
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

        await context.UserAdd(user, CancellationToken.None);

        var retrieved = await context.UserFindRecord(user.Id, CancellationToken.None);
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
        await context.UserAdd(user, CancellationToken.None);

        context.UserDelete(user);
        var (status, _) = await context.Complete();

        Assert.AreEqual(ResponseStatus.Success, status);
        var retrieved = await context.UserFindRecord(user.Id, CancellationToken.None);
        Assert.IsNull(retrieved);
    }

    // -------------------------------------------------------------------------
    // Role persistence
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task ApplicationRoleAdd_NewRole_ShouldPersistAndBeRetrievable() {
        using var context = await GetIdentityContext();
        var role = new ApplicationRole {
            Id = Guid.NewGuid(),
            Name = "NewRole_ctx",
            NormalizedName = "NEWROLE_CTX"
        };

        var count = await context.RoleAdd(role, CancellationToken.None);

        Assert.IsTrue(count > 0);
        var retrieved = await context.RoleFindRecord("NEWROLE_CTX", CancellationToken.None);
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
        await context.RoleAdd(role, CancellationToken.None);

        context.RoleDelete(role);
        var (status, _) = await context.Complete();

        Assert.AreEqual(ResponseStatus.Success, status);
        var retrieved = await context.RoleFindRecord("TOREMOVE_ROLE", CancellationToken.None);
        Assert.IsNull(retrieved);
    }

    // -------------------------------------------------------------------------
    // User-role assignment
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task ApplicationUserRoleAdd_ShouldPersistAndBeRetrievable() {
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
        await context.UserAdd(user, CancellationToken.None);
        await context.RoleAdd(role, CancellationToken.None);

        var userRole = new IdentityUserRole<Guid> { UserId = userId, RoleId = roleId };
        var count = await context.UserRoleAdd(userRole, CancellationToken.None);

        Assert.IsTrue(count > 0);
        var retrieved = await context.UserRoleFindRecord(userId, roleId, CancellationToken.None);
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
        await context.UserAdd(user, CancellationToken.None);
        await context.RoleAdd(role, CancellationToken.None);

        var userRole = new IdentityUserRole<Guid> { UserId = userId, RoleId = roleId };
        await context.UserRoleAdd(userRole, CancellationToken.None);

        context.UserRoleDelete(userRole);
        await context.Complete();

        var retrieved = await context.UserRoleFindRecord(userId, roleId, CancellationToken.None);
        Assert.IsNull(retrieved);
    }

    // -------------------------------------------------------------------------
    // Tenant persistence
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task ApplicationTenantAdd_NewTenant_ShouldPersistAndBeRetrievable() {
        using var context = await GetIdentityContext();
        var tenant = new ApplicationTenant {
            Id = Guid.NewGuid(),
            Name = "NewTenant_ctx",
            AdminEmail = "new@tenant.com"
        };

        var count = await context.TenantAdd(tenant, CancellationToken.None);

        Assert.IsTrue(count > 0);
        var retrieved = await context.TenantFindRecord("NEWTENANT_CTX", CancellationToken.None);
        Assert.IsNotNull(retrieved);
        Assert.AreEqual("NewTenant_ctx", retrieved.Name);
    }

    [TestMethod]
    public async Task RemoveApplicationTenant_ExistingTenant_ShouldNotBeRetrievableAfterComplete() {
        using var context = await GetIdentityContext();
        var tenant = new ApplicationTenant {
            Id = Guid.NewGuid(),
            Name = "ToRemove_tenant",
            AdminEmail = "remove@tenant.com"
        };
        await context.TenantAdd(tenant, CancellationToken.None);

        context.TenantDelete(tenant);
        var (status, _) = await context.Complete();

        Assert.AreEqual(ResponseStatus.Success, status);
        var retrieved = await context.TenantFindRecord("TOREMOVE_TENANT", CancellationToken.None);
        Assert.IsNull(retrieved);
    }

    // -------------------------------------------------------------------------
    // User-tenant assignment
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task ApplicationUserTenantAdd_ShouldPersistAndBeRetrievable() {
        using var context = await GetIdentityContext();
        var userId = Guid.NewGuid();
        var tenantId = Guid.NewGuid();

        var user = new ApplicationUser {
            Id = userId,
            UserName = "tenant_assign_user",
            NormalizedUserName = "TENANT_ASSIGN_USER",
            Email = "tenant_assign@test.com",
            NormalizedEmail = "TENANT_ASSIGN@TEST.COM",
            SecurityStamp = Guid.NewGuid().ToString(),
            EmailConfirmed = true
        };
        var tenant = new ApplicationTenant {
            Id = tenantId,
            Name = "TenantAssignTest",
            AdminEmail = "assign@tenant.com"
        };
        await context.UserAdd(user, CancellationToken.None);
        await context.TenantAdd(tenant, CancellationToken.None);

        var userTenant = new ApplicationUserTenant { Id = Guid.NewGuid(), ApplicationUserId = userId, ApplicationTenantId = tenantId };
        var count = await context.UserTenantAdd(userTenant, CancellationToken.None);

        Assert.IsTrue(count > 0);
        var canSignIn = await context.UserCanSignInTenant(userId, tenantId, CancellationToken.None);
        Assert.IsTrue(canSignIn, "User should be able to sign in after being linked to the tenant.");
    }

    // -------------------------------------------------------------------------
    // Lookup queries on seeded data
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task ApplicationUserFindRecord_ByNormalizedName_SeededAdmin_ShouldReturn() {
        using var context = await GetIdentityContext();

        var user = await context.UserFindRecord("ADMIN", CancellationToken.None);

        Assert.IsNotNull(user);
        Assert.AreEqual("admin", user.UserName);
    }

    [TestMethod]
    public async Task ApplicationUserFindRecord_ByGuid_SeededAdmin_ShouldReturn() {
        using var context = await GetIdentityContext();

        var user = await context.UserFindRecord(AdminGuid, CancellationToken.None);

        Assert.IsNotNull(user);
        Assert.AreEqual("admin", user.UserName);
    }

    [TestMethod]
    public async Task ApplicationUserFindRecordByEmail_SeededAdmin_ShouldReturn() {
        using var context = await GetIdentityContext();

        var user = await context.UserFindRecordByEmail("ADMIN@EMAIL.COM", CancellationToken.None);

        Assert.IsNotNull(user);
        Assert.AreEqual("admin", user.UserName);
    }

    [TestMethod]
    public async Task ApplicationRoleFindRecord_SeededSysAdmin_ShouldReturn() {
        using var context = await GetIdentityContext();

        var role = await context.RoleFindRecord("SYSADMIN", CancellationToken.None);

        Assert.IsNotNull(role);
        Assert.AreEqual("SysAdmin", role.Name);
    }

    [TestMethod]
    public async Task ApplicationTenantFindRecord_ByNormalizedName_SeededTenant_ShouldReturn() {
        using var context = await GetIdentityContext();

        var tenant = await context.TenantFindRecord("TEST TENANT", CancellationToken.None);

        Assert.IsNotNull(tenant);
        Assert.AreEqual("Test Tenant", tenant.Name);
    }

    [TestMethod]
    public async Task ApplicationTenantFindRecord_SeededTenant_ShouldReturn() {
        using var context = await GetIdentityContext();

        var tenant = await context.TenantFindRecord(TestContext.TenantGuid, CancellationToken.None);

        Assert.IsNotNull(tenant);
        Assert.AreEqual(TestContext.TenantGuid, tenant.Id);
    }

    [TestMethod]
    public async Task ApplicationTenantFindRecordByEmail_SeededTenant_ShouldReturn() {
        using var context = await GetIdentityContext();

        var tenant = await context.TenantFindRecordByEmail("ADMIN@TESTTENANT.COM", CancellationToken.None);

        Assert.IsNotNull(tenant);
        Assert.AreEqual(TestContext.TenantGuid, tenant.Id);
    }

    [TestMethod]
    public async Task ApplicationTenantFindRecord_UnknownTenant_ShouldReturnNull() {
        using var context = await GetIdentityContext();

        var tenant = await context.TenantFindRecord(Guid.NewGuid(), CancellationToken.None);

        Assert.IsNull(tenant);
    }

    [TestMethod]
    public async Task FindByNameAsync_SeededAdmin_ShouldReturnSuccess() {
        using var context = await GetIdentityContext();

        var result = await context.UserFind("ADMIN", CancellationToken.None);

        Assert.AreEqual(ResponseStatus.Success, result.Status);
        Assert.IsNotNull(result.Value);
        Assert.AreEqual(AdminGuid, result.Value.Id);
    }

    [TestMethod]
    public async Task FindByNameAsync_NonExistentUser_ShouldReturnNotFound() {
        using var context = await GetIdentityContext();

        var result = await context.UserFind("DOESNOTEXIST", CancellationToken.None);

        Assert.AreNotEqual(ResponseStatus.Success, result.Status);
    }

    [TestMethod]
    public async Task FindByIdAsync_SeededAdmin_ShouldReturn() {
        using var context = await GetIdentityContext();

        var user = await context.UserFindRecord(AdminGuid, CancellationToken.None);

        Assert.IsNotNull(user);
        Assert.AreEqual("admin", user.UserName);
    }

    [TestMethod]
    public async Task FindByEmailAsync_SeededAdmin_ShouldReturn() {
        using var context = await GetIdentityContext();

        var user = await context.UserFindRecordByEmail("ADMIN@EMAIL.COM", CancellationToken.None);

        Assert.IsNotNull(user);
        Assert.AreEqual(AdminGuid, user.Id);
    }

    // -------------------------------------------------------------------------
    // Sign-in eligibility
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task CanSignInAsync_ActiveUser_ShouldReturnTrue() {
        using var context = await GetIdentityContext();

        var canSignIn = await context.UserCanSignIn(AdminGuid, CancellationToken.None);

        Assert.IsTrue(canSignIn);
    }

    [TestMethod]
    public async Task CanSignInAsync_LockedOutUser_ShouldReturnFalse() {
        using var context = await GetIdentityContext();
        var lockedOutUser = await context.UserFindRecord("LOCKEDOUT", CancellationToken.None);
        Assert.IsNotNull(lockedOutUser, "Seeded locked-out user must exist.");

        var canSignIn = await context.UserCanSignIn(lockedOutUser.Id, CancellationToken.None);

        Assert.IsFalse(canSignIn);
    }

    [TestMethod]
    public async Task CanSignInAsync_UnknownUser_ShouldReturnFalse() {
        using var context = await GetIdentityContext();

        var canSignIn = await context.UserCanSignIn(Guid.NewGuid(), CancellationToken.None);

        Assert.IsFalse(canSignIn);
    }

    [TestMethod]
    public async Task CanSignInTenantAsync_ActiveUserInActiveTenant_ShouldReturnTrue() {
        using var context = await GetIdentityContext();

        var canSignIn = await context.UserCanSignInTenant(AdminGuid, TestContext.TenantGuid, CancellationToken.None);

        Assert.IsTrue(canSignIn);
    }

    [TestMethod]
    public async Task CanSignInTenantAsync_ActiveUserInLockedTenant_ShouldReturnFalse() {
        using var context = await GetIdentityContext();

        var canSignIn = await context.UserCanSignInTenant(AdminGuid, TestContext.LockedTenantGuid, CancellationToken.None);

        Assert.IsFalse(canSignIn);
    }

    [TestMethod]
    public async Task CanSignInTenantAsync_ActiveUserNotLinkedToTenant_ShouldReturnFalse() {
        using var context = await GetIdentityContext();

        var canSignIn = await context.UserCanSignInTenant(AdminGuid, Guid.NewGuid(), CancellationToken.None);

        Assert.IsFalse(canSignIn);
    }

    [TestMethod]
    public async Task CanSignInTenantAsync_LockedOutUser_ShouldReturnFalse() {
        using var context = await GetIdentityContext();
        var lockedOutUser = await context.UserFindRecord("LOCKEDOUT", CancellationToken.None);
        Assert.IsNotNull(lockedOutUser, "Seeded locked-out user must exist.");

        var canSignIn = await context.UserCanSignInTenant(lockedOutUser.Id, TestContext.TenantGuid, CancellationToken.None);

        Assert.IsFalse(canSignIn);
    }

    [TestMethod]
    public async Task CanSignInTenantAsync_UnknownUser_ShouldReturnFalse() {
        using var context = await GetIdentityContext();

        var canSignIn = await context.UserCanSignInTenant(Guid.NewGuid(), TestContext.TenantGuid, CancellationToken.None);

        Assert.IsFalse(canSignIn);
    }

    // -------------------------------------------------------------------------
    // Role membership queries
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task ApplicationUserGetRoles_SeededAdminWithSysAdmin_ShouldContainRole() {
        using var context = await GetIdentityContext();

        var roles = await context.UserGetRoles(AdminGuid, CancellationToken.None);

        Assert.IsTrue(roles.Any(r => r == "SysAdmin"), "Admin should have the SysAdmin role.");
    }

    [TestMethod]
    public async Task ApplicationUserGetRoles_UserWithNoRoles_ShouldReturnEmpty() {
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
        await context.UserAdd(user, CancellationToken.None);

        var roles = await context.UserGetRoles(userId, CancellationToken.None);

        Assert.IsFalse(roles.Any());
    }

    // -------------------------------------------------------------------------
    // Display name resolution
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task ApplicationUserGetName_SeededAdmin_ShouldReturnNonEmptyName() {
        using var context = await GetIdentityContext();

        var name = await context.UserGetName(AdminGuid, CancellationToken.None);

        Assert.IsFalse(string.IsNullOrWhiteSpace(name));
    }

    [TestMethod]
    public async Task ApplicationTenantGetName_SeededTenant_ShouldReturnNonEmptyName() {
        using var context = await GetIdentityContext();

        var name = await context.TenantGetName(TestContext.TenantGuid, CancellationToken.None);

        Assert.IsFalse(string.IsNullOrWhiteSpace(name));
    }

    [TestMethod]
    public async Task ApplicationTenantGetName_UnknownTenant_ShouldReturnUnknown() {
        using var context = await GetIdentityContext();

        var name = await context.TenantGetName(Guid.NewGuid(), CancellationToken.None);

        Assert.AreEqual("Unknown", name);
    }

    // -------------------------------------------------------------------------
    // Select-list helpers
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task RolesAsync_ShouldReturnSeededRoles() {
        using var context = await GetIdentityContext();

        var roles = await context.RoleGetSelectList(CancellationToken.None);

        Assert.IsNotNull(roles);
        Assert.IsTrue(roles.Any(), "At least the seeded roles should be present.");
    }

    [TestMethod]
    public async Task UsersAsync_ShouldReturnSeededUsers() {
        using var context = await GetIdentityContext();

        var users = await context.UserGetSelectList(CancellationToken.None);

        Assert.IsNotNull(users);
        Assert.IsTrue(users.Any(), "At least the seeded users should be present.");
    }

    [TestMethod]
    public async Task TenantsAsync_ShouldReturnSeededTenants() {
        using var context = await GetIdentityContext();

        var tenants = await context.TenantGetSelectList(CancellationToken.None);

        Assert.IsNotNull(tenants);
        Assert.IsTrue(tenants.Any(), "At least the seeded tenant should be present.");
    }

    // -------------------------------------------------------------------------
    // Tenant membership queries
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task ApplicationTenantGetUsers_SeededTenantWithAdmin_ShouldContainUser() {
        using var context = await GetIdentityContext();

        var users = await context.TenantGetUsers(TestContext.TenantGuid, CancellationToken.None);

        Assert.IsTrue(users.Any(u => u == "admin"), "Admin should be listed as a user of the seeded tenant.");
    }

    [TestMethod]
    public async Task ApplicationTenantGetUsers_TenantWithNoUsers_ShouldReturnEmpty() {
        using var context = await GetIdentityContext();
        var tenant = new ApplicationTenant {
            Id = Guid.NewGuid(),
            Name = "EmptyTenant_ctx",
            AdminEmail = "empty@tenant.com"
        };
        await context.TenantAdd(tenant, CancellationToken.None);

        var users = await context.TenantGetUsers(tenant.Id, CancellationToken.None);

        Assert.IsFalse(users.Any());
    }

    [TestMethod]
    public async Task ApplicationTenantGetUsers_UnknownTenant_ShouldReturnEmpty() {
        using var context = await GetIdentityContext();

        var users = await context.TenantGetUsers(Guid.NewGuid(), CancellationToken.None);

        Assert.IsFalse(users.Any());
    }

    // -------------------------------------------------------------------------
    // Application secrets
    // -------------------------------------------------------------------------

    private static ApplicationSecret NewSecret(Guid ownerId, string hashedToken, string? name = null, DateTime? expiration = null) => new() {
        Id = Guid.NewGuid(),
        ReferenceId = ownerId,
        ReferenceType = "test",
        HashedToken = hashedToken,
        Name = name,
        NormalizedName = name?.ToUpperInvariant(),
        Expiration = expiration ?? DateTime.UtcNow.AddDays(30)
    };

    [TestMethod]
    public async Task SecretAdd_NewSecret_ShouldPersistAndBeRetrievable() {
        using var context = await GetIdentityContext();
        var secret = NewSecret(Guid.NewGuid(), $"hash_{Guid.NewGuid():N}");

        var count = await context.SecretAdd(secret, CancellationToken.None);

        Assert.IsTrue(count > 0);
        var retrieved = await context.SecretFindRecord(secret.Id, CancellationToken.None);
        Assert.IsNotNull(retrieved);
        Assert.AreEqual(secret.HashedToken, retrieved.HashedToken);
    }

    [TestMethod]
    public async Task SecretFindRecord_ByHashedToken_ShouldReturn() {
        using var context = await GetIdentityContext();
        var hashedToken = $"hash_{Guid.NewGuid():N}";
        var secret = NewSecret(Guid.NewGuid(), hashedToken);
        await context.SecretAdd(secret, CancellationToken.None);

        var retrieved = await context.SecretFindRecord(hashedToken, CancellationToken.None);

        Assert.IsNotNull(retrieved);
        Assert.AreEqual(secret.Id, retrieved.Id);
    }

    [TestMethod]
    public async Task SecretFindRecord_UnknownId_ShouldReturnNull() {
        using var context = await GetIdentityContext();

        var result = await context.SecretFindRecord(Guid.NewGuid(), CancellationToken.None);

        Assert.IsNull(result);
    }

    [TestMethod]
    public async Task SecretFindRecord_UnknownHashedToken_ShouldReturnNull() {
        using var context = await GetIdentityContext();

        var result = await context.SecretFindRecord("nonexistent_hash", CancellationToken.None);

        Assert.IsNull(result);
    }

    [TestMethod]
    public async Task SecretDelete_ExistingSecret_ShouldNotBeRetrievableAfterComplete() {
        using var context = await GetIdentityContext();
        var secret = NewSecret(Guid.NewGuid(), $"hash_{Guid.NewGuid():N}");
        await context.SecretAdd(secret, CancellationToken.None);

        context.SecretDelete(secret);
        await context.Complete();

        var retrieved = await context.SecretFindRecord(secret.Id, CancellationToken.None);
        Assert.IsNull(retrieved);
    }

    [TestMethod]
    public async Task SecretGetSelectList_WithActiveSecret_ShouldReturnEntry() {
        using var context = await GetIdentityContext();
        var ownerId = Guid.NewGuid();
        var secret = NewSecret(ownerId, $"hash_{Guid.NewGuid():N}", "My Token", DateTime.UtcNow.AddDays(30));
        await context.SecretAdd(secret, CancellationToken.None);

        var list = await context.SecretGetSelectList(ownerId, "test", CancellationToken.None);

        Assert.IsTrue(list.Any(i => i.Key == secret.Id));
    }

    [TestMethod]
    public async Task SecretGetSelectList_ExpiredSecret_ShouldNotReturnEntry() {
        using var context = await GetIdentityContext();
        var ownerId = Guid.NewGuid();
        var secret = NewSecret(ownerId, $"hash_{Guid.NewGuid():N}", "Expired Token", DateTime.UtcNow.AddDays(-1));
        await context.SecretAdd(secret, CancellationToken.None);

        var list = await context.SecretGetSelectList(ownerId, "test", CancellationToken.None);

        Assert.IsFalse(list.Any(i => i.Key == secret.Id));
    }

    [TestMethod]
    public async Task SecretGetSelectList_UnknownOwner_ShouldReturnEmpty() {
        using var context = await GetIdentityContext();

        var list = await context.SecretGetSelectList(Guid.NewGuid(), "test", CancellationToken.None);

        Assert.IsFalse(list.Any());
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
        await context.RoleAdd(role, CancellationToken.None);

        // Mutate directly to produce a pending change for Complete()
        var retrieved = await context.RoleFindRecord("COMPLETETESTROLE", CancellationToken.None);
        Assert.IsNotNull(retrieved);
        retrieved.Name = "CompleteTestRole_Updated";

        var (status, message) = await context.Complete();

        Assert.AreEqual(ResponseStatus.Success, status);
        Assert.IsNotNull(message);
    }
}
