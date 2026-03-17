using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;

using Moq;

using N2.Core.Commands;
using N2.Core.Entity;
using N2.Core.Identity.Data;

namespace N2.Core.Identity.UnitTests;

// ── Abstract base — shared test logic ─────────────────────────────────────────

/// <summary>
/// Provider-agnostic integration tests for <see cref="N2IdentityContext"/>.
/// Subclasses supply the target <see cref="Provider"/> and <see cref="ConnectionName"/>;
/// every <c>[TestMethod]</c> defined here is discovered and executed by each subclass.
/// </summary>
public abstract class N2IdentityContextIntegrationTestsBase {
    protected abstract DatabaseProvider Provider { get; }
    protected abstract string ConnectionName { get; }

    private static IConfiguration BuildConfiguration() =>
        new ConfigurationBuilder()
            .AddUserSecrets<N2IdentityContextIntegrationTestsBase>()
            .AddEnvironmentVariables()   // CI injects ConnectionStrings__UserDb*Test etc.
            .Build();

    private static Mock<IConnectionStringService> BuildMock(IConfiguration configuration) {
        var mock = new Mock<IConnectionStringService>();
        mock.Setup(s => s.GetConnectionString(It.IsAny<string>()))
            .Returns((string name) => configuration.GetConnectionString(name) ?? string.Empty);
        return mock;
    }

    protected async Task<N2IdentityContext> CreateAndPrepareAsync() {
        var factory = new N2IdentityContextFactory(BuildMock(BuildConfiguration()).Object);
        var context = (N2IdentityContext)await factory.CreateAsync(Provider, ConnectionName);
        await context.Database.MigrateAsync();
        return context;
    }

    // ── Migration verification ────────────────────────────────────────────────

    protected async Task MigrateAsync_ShouldHaveNoPendingMigrationsCore() {
        var factory = new N2IdentityContextFactory(BuildMock(BuildConfiguration()).Object);
        using var context = (N2IdentityContext)await factory.CreateAsync(Provider, ConnectionName);

        await context.Database.MigrateAsync();

        var pending = (await context.Database.GetPendingMigrationsAsync()).ToList();
        Assert.AreEqual(0, pending.Count,
            $"Unexpected pending migrations: {string.Join(", ", pending)}");
    }

    // ── User persistence ──────────────────────────────────────────────────────

    [TestMethod]
    public async Task ApplicationUserAdd_NewUser_ShouldPersistAndBeRetrievable() {
        using var context = await CreateAndPrepareAsync();
        var userId = Guid.NewGuid();
        var uniqueName = $"intg_{userId:N}";
        var user = new ApplicationUser {
            Id = userId,
            UserName = uniqueName,
            NormalizedUserName = uniqueName.ToUpperInvariant(),
            Email = $"{uniqueName}@test.com",
            NormalizedEmail = $"{uniqueName}@test.com".ToUpperInvariant(),
            SecurityStamp = Guid.NewGuid().ToString()
        };

        var count = await context.UserAdd(user, CancellationToken.None);

        try {
            Assert.IsTrue(count > 0, "SaveChanges should report at least one row affected.");
            var retrieved = await context.UserFindRecord(userId, CancellationToken.None);
            Assert.IsNotNull(retrieved);
            Assert.AreEqual(uniqueName, retrieved.UserName);
        } finally {
            context.UserDelete(user);
            await context.Complete();
        }
    }

    [TestMethod]
    public async Task ApplicationUserAdd_ExtendedProperties_ShouldRoundTrip() {
        using var context = await CreateAndPrepareAsync();
        var userId = Guid.NewGuid();
        var uniqueName = $"ext_{userId:N}";
        var user = new ApplicationUser {
            Id = userId,
            UserName = uniqueName,
            NormalizedUserName = uniqueName.ToUpperInvariant(),
            Email = $"{uniqueName}@test.com",
            NormalizedEmail = $"{uniqueName}@test.com".ToUpperInvariant(),
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

        try {
            using var verifyContext = await CreateAndPrepareAsync();
            var retrieved = await verifyContext.UserFindRecord(userId, CancellationToken.None);
            Assert.IsNotNull(retrieved);
            Assert.AreEqual("Jane", retrieved.FirstName);
            Assert.AreEqual("Doe", retrieved.LastName);
            Assert.AreEqual("M", retrieved.MiddleName);
            Assert.AreEqual("Jane M. Doe", retrieved.DisplayName);
            Assert.AreEqual("/images/jane.png", retrieved.ImagePath);
            Assert.AreEqual(MultiFactorType.Email, retrieved.MfaType);
            Assert.IsFalse(retrieved.MfaConfirmed);
        } finally {
            context.UserDelete(user);
            await context.Complete();
        }
    }

    [TestMethod]
    public async Task RemoveApplicationUser_ShouldNotBeRetrievableAfterComplete() {
        using var context = await CreateAndPrepareAsync();
        var userId = Guid.NewGuid();
        var uniqueName = $"del_{userId:N}";
        var user = new ApplicationUser {
            Id = userId,
            UserName = uniqueName,
            NormalizedUserName = uniqueName.ToUpperInvariant(),
            Email = $"{uniqueName}@test.com",
            NormalizedEmail = $"{uniqueName}@test.com".ToUpperInvariant(),
            SecurityStamp = Guid.NewGuid().ToString()
        };
        await context.UserAdd(user, CancellationToken.None);

        context.UserDelete(user);
        var (status, _) = await context.Complete();

        Assert.AreEqual(ResponseStatus.Success, status);
        var retrieved = await context.UserFindRecord(userId, CancellationToken.None);
        Assert.IsNull(retrieved);
    }

    // ── Role persistence ──────────────────────────────────────────────────────

    [TestMethod]
    public async Task ApplicationRoleAdd_NewRole_ShouldPersistAndBeRetrievable() {
        using var context = await CreateAndPrepareAsync();
        var roleId = Guid.NewGuid();
        var uniqueName = $"Role_{roleId:N}";
        var role = new ApplicationRole {
            Id = roleId,
            Name = uniqueName,
            NormalizedName = uniqueName.ToUpperInvariant()
        };

        var count = await context.RoleAdd(role, CancellationToken.None);

        try {
            Assert.IsTrue(count > 0);
            var retrieved = await context.RoleFindRecord(uniqueName.ToUpperInvariant(), CancellationToken.None);
            Assert.IsNotNull(retrieved);
            Assert.AreEqual(uniqueName, retrieved.Name);
        } finally {
            context.RoleDelete(role);
            await context.Complete();
        }
    }

    [TestMethod]
    public async Task RemoveApplicationRole_ShouldNotBeRetrievableAfterComplete() {
        using var context = await CreateAndPrepareAsync();
        var roleId = Guid.NewGuid();
        var uniqueName = $"DelRole_{roleId:N}";
        var role = new ApplicationRole {
            Id = roleId,
            Name = uniqueName,
            NormalizedName = uniqueName.ToUpperInvariant()
        };
        await context.RoleAdd(role, CancellationToken.None);

        context.RoleDelete(role);
        var (status, _) = await context.Complete();

        Assert.AreEqual(ResponseStatus.Success, status);
        var retrieved = await context.RoleFindRecord(uniqueName.ToUpperInvariant(), CancellationToken.None);
        Assert.IsNull(retrieved);
    }

    // ── User-role assignment ──────────────────────────────────────────────────

    [TestMethod]
    public async Task ApplicationUserRoleAdd_ShouldPersistAndBeRetrievable() {
        using var context = await CreateAndPrepareAsync();
        var userId = Guid.NewGuid();
        var roleId = Guid.NewGuid();
        var (user, role) = await SeedUserAndRoleAsync(context, userId, roleId);

        var userRole = new IdentityUserRole<Guid> { UserId = userId, RoleId = roleId };
        var count = await context.UserRoleAdd(userRole, CancellationToken.None);

        try {
            Assert.IsTrue(count > 0);
            var retrieved = await context.UserRoleFindRecord(userId, roleId, CancellationToken.None);
            Assert.IsNotNull(retrieved);
            Assert.AreEqual(userId, retrieved.UserId);
            Assert.AreEqual(roleId, retrieved.RoleId);
        } finally {
            await CleanupUserRoleAsync(context, user, role, userRole);
        }
    }

    [TestMethod]
    public async Task RemoveApplicationUserRole_ShouldNotBeRetrievableAfterComplete() {
        using var context = await CreateAndPrepareAsync();
        var userId = Guid.NewGuid();
        var roleId = Guid.NewGuid();
        var (user, role) = await SeedUserAndRoleAsync(context, userId, roleId);
        var userRole = new IdentityUserRole<Guid> { UserId = userId, RoleId = roleId };
        await context.UserRoleAdd(userRole, CancellationToken.None);

        context.UserRoleDelete(userRole);
        await context.Complete();

        try {
            var retrieved = await context.UserRoleFindRecord(userId, roleId, CancellationToken.None);
            Assert.IsNull(retrieved);
        } finally {
            await CleanupUserRoleAsync(context, user, role, null);
        }
    }

    // ── Tenant persistence ────────────────────────────────────────────────────

    [TestMethod]
    public async Task ApplicationTenantAdd_NewTenant_ShouldPersistAndBeRetrievable() {
        using var context = await CreateAndPrepareAsync();
        var tenantId = Guid.NewGuid();
        var uniqueName = $"Tenant_{tenantId:N}";
        var tenant = new ApplicationTenant {
            Id = tenantId,
            Name = uniqueName,
            AdminEmail = $"{uniqueName}@test.com"
        };

        var count = await context.TenantAdd(tenant, CancellationToken.None);
        var updates = await context.Complete();

        try {
            Assert.AreEqual(ResponseStatus.Success, updates.status);
            Assert.IsGreaterThan(0, count);
            var retrieved = await context.TenantFindRecord(uniqueName.ToUpperInvariant(), CancellationToken.None);
            Assert.IsNotNull(retrieved);
            Assert.AreEqual(uniqueName, retrieved.Name);
        } finally {
            context.TenantDelete(tenant);
            await context.Complete();
        }
    }

    [TestMethod]
    public async Task RemoveApplicationTenant_ShouldNotBeRetrievableAfterComplete() {
        using var context = await CreateAndPrepareAsync();
        var tenantId = Guid.NewGuid();
        var uniqueName = $"DelTenant_{tenantId:N}";
        var tenant = new ApplicationTenant {
            Id = tenantId,
            Name = uniqueName,
            AdminEmail = $"{uniqueName}@test.com"
        };
        await context.TenantAdd(tenant, CancellationToken.None);

        context.TenantDelete(tenant);
        var (status, _) = await context.Complete();

        Assert.AreEqual(ResponseStatus.Success, status);
        var retrieved = await context.TenantFindRecord(uniqueName.ToUpperInvariant(), CancellationToken.None);
        Assert.IsNull(retrieved);
    }

    // ── User-tenant assignment ────────────────────────────────────────────────

    [TestMethod]
    public async Task ApplicationUserTenantAdd_ShouldPersistAndBeRetrievable() {
        using var context = await CreateAndPrepareAsync();
        var (user, tenant, userTenant) = await SeedUserAndTenantAsync(context, isLocked: false);

        try {
            var canSignIn = await context.UserCanSignInTenant(user.Id, tenant.Id, CancellationToken.None);
            Assert.IsTrue(canSignIn, "User should be linkable to a tenant via ApplicationUserTenantAdd.");
        } finally {
            await CleanupUserTenantAsync(context, user, tenant, userTenant);
        }
    }

    [TestMethod]
    public async Task RemoveApplicationUserTenant_ShouldPreventSignInAfterComplete() {
        using var context = await CreateAndPrepareAsync();
        var (user, tenant, userTenant) = await SeedUserAndTenantAsync(context, isLocked: false);
        context.UserTenantDelete(userTenant);
        await context.Complete();

        try {
            var canSignIn = await context.UserCanSignInTenant(user.Id, tenant.Id, CancellationToken.None);
            Assert.IsFalse(canSignIn, "User should no longer access tenant after the link is removed.");
        } finally {
            context.TenantDelete(tenant);
            context.UserDelete(user);
            await context.Complete();
        }
    }

    // ── Lookup queries ────────────────────────────────────────────────────────

    [TestMethod]
    public async Task ApplicationUserFindRecord_ByNormalizedName_ShouldReturn() {
        using var context = await CreateAndPrepareAsync();
        var (user, _) = await SeedSingleUserAsync(context);

        try {
            var retrieved = await context.UserFindRecord(user.NormalizedUserName!, CancellationToken.None);
            Assert.IsNotNull(retrieved);
            Assert.AreEqual(user.Id, retrieved.Id);
        } finally {
            context.UserDelete(user);
            await context.Complete();
        }
    }

    [TestMethod]
    public async Task ApplicationUserFindRecord_ByGuid_ShouldReturn() {
        using var context = await CreateAndPrepareAsync();
        var (user, _) = await SeedSingleUserAsync(context);

        try {
            var retrieved = await context.UserFindRecord(user.Id, CancellationToken.None);
            Assert.IsNotNull(retrieved);
            Assert.AreEqual(user.UserName, retrieved.UserName);
        } finally {
            context.UserDelete(user);
            await context.Complete();
        }
    }

    [TestMethod]
    public async Task ApplicationUserFindRecordByEmail_ShouldReturn() {
        using var context = await CreateAndPrepareAsync();
        var (user, _) = await SeedSingleUserAsync(context);

        try {
            var retrieved = await context.UserFindRecordByEmail(user.NormalizedEmail!, CancellationToken.None);
            Assert.IsNotNull(retrieved);
            Assert.AreEqual(user.Id, retrieved.Id);
        } finally {
            context.UserDelete(user);
            await context.Complete();
        }
    }

    [TestMethod]
    public async Task FindByNameAsync_ExistingUser_ShouldReturnSuccess() {
        using var context = await CreateAndPrepareAsync();
        var (user, _) = await SeedSingleUserAsync(context);

        try {
            var result = await context.UserFind(user.NormalizedUserName!, CancellationToken.None);
            Assert.AreEqual(ResponseStatus.Success, result.Status);
            Assert.IsNotNull(result.Value);
            Assert.AreEqual(user.Id, result.Value.Id);
        } finally {
            context.UserDelete(user);
            await context.Complete();
        }
    }

    [TestMethod]
    public async Task FindByNameAsync_NonExistentUser_ShouldReturnNotFound() {
        using var context = await CreateAndPrepareAsync();

        var result = await context.UserFind($"GHOST_{Guid.NewGuid():N}", CancellationToken.None);

        Assert.AreNotEqual(ResponseStatus.Success, result.Status);
    }

    [TestMethod]
    public async Task FindByIdAsync_ExistingUser_ShouldReturn() {
        using var context = await CreateAndPrepareAsync();
        var (user, _) = await SeedSingleUserAsync(context);

        try {
            var retrieved = await context.UserFindRecord(user.Id, CancellationToken.None);
            Assert.IsNotNull(retrieved);
            Assert.AreEqual(user.UserName, retrieved.UserName);
        } finally {
            context.UserDelete(user);
            await context.Complete();
        }
    }

    [TestMethod]
    public async Task FindByEmailAsync_ExistingUser_ShouldReturn() {
        using var context = await CreateAndPrepareAsync();
        var (user, _) = await SeedSingleUserAsync(context);

        try {
            var retrieved = await context.UserFindRecordByEmail(user.NormalizedEmail!, CancellationToken.None);
            Assert.IsNotNull(retrieved);
            Assert.AreEqual(user.Id, retrieved.Id);
        } finally {
            context.UserDelete(user);
            await context.Complete();
        }
    }

    [TestMethod]
    public async Task ApplicationRoleFindRecord_ByNormalizedName_ShouldReturn() {
        using var context = await CreateAndPrepareAsync();
        var roleId = Guid.NewGuid();
        var uniqueName = $"LookupRole_{roleId:N}";
        var role = new ApplicationRole { Id = roleId, Name = uniqueName, NormalizedName = uniqueName.ToUpperInvariant() };
        await context.RoleAdd(role, CancellationToken.None);

        try {
            var retrieved = await context.RoleFindRecord(uniqueName.ToUpperInvariant(), CancellationToken.None);
            Assert.IsNotNull(retrieved);
            Assert.AreEqual(uniqueName, retrieved.Name);
        } finally {
            context.RoleDelete(role);
            await context.Complete();
        }
    }

    [TestMethod]
    public async Task ApplicationTenantFindRecord_ByNormalizedName_ShouldReturn() {
        using var context = await CreateAndPrepareAsync();
        var tenantId = Guid.NewGuid();
        var uniqueName = $"LookupTenant_{tenantId:N}";
        var tenant = new ApplicationTenant { Id = tenantId, Name = uniqueName, AdminEmail = $"{uniqueName}@test.com" };
        await context.TenantAdd(tenant, CancellationToken.None);
        var updates = await context.Complete();

        try {
            Assert.AreEqual(ResponseStatus.Success, updates.status);
            var retrieved = await context.TenantFindRecord(uniqueName.ToUpperInvariant(), CancellationToken.None);
            Assert.IsNotNull(retrieved);
            Assert.AreEqual(uniqueName, retrieved.Name);
        } finally {
            context.TenantDelete(tenant);
            await context.Complete();
        }
    }

    [TestMethod]
    public async Task ApplicationTenantFindRecord_ExistingTenant_ShouldReturn() {
        using var context = await CreateAndPrepareAsync();
        var tenantId = Guid.NewGuid();
        var uniqueName = $"IdTenant_{tenantId:N}";
        var tenant = new ApplicationTenant { Id = tenantId, Name = uniqueName, AdminEmail = $"{uniqueName}@test.com" };
        await context.TenantAdd(tenant, CancellationToken.None);

        try {
            var retrieved = await context.TenantFindRecord(tenantId, CancellationToken.None);
            Assert.IsNotNull(retrieved);
            Assert.AreEqual(tenantId, retrieved.Id);
        } finally {
            context.TenantDelete(tenant);
            await context.Complete();
        }
    }

    [TestMethod]
    public async Task ApplicationTenantFindRecord_UnknownId_ShouldReturnNull() {
        using var context = await CreateAndPrepareAsync();

        var retrieved = await context.TenantFindRecord(Guid.NewGuid(), CancellationToken.None);

        Assert.IsNull(retrieved);
    }

    [TestMethod]
    public async Task ApplicationTenantFindRecordByEmail_ExistingTenant_ShouldReturn() {
        using var context = await CreateAndPrepareAsync();
        var tenantId = Guid.NewGuid();
        var uniqueName = $"EmailTenant_{tenantId:N}";
        var tenant = new ApplicationTenant { Id = tenantId, Name = uniqueName, AdminEmail = $"{uniqueName}@test.com" };
        await context.TenantAdd(tenant, CancellationToken.None);

        try {
            var retrieved = await context.TenantFindRecordByEmail(tenant.NormalizedEmail!, CancellationToken.None);
            Assert.IsNotNull(retrieved);
            Assert.AreEqual(tenantId, retrieved.Id);
        } finally {
            context.TenantDelete(tenant);
            await context.Complete();
        }
    }

    // ── Sign-in eligibility ───────────────────────────────────────────────────

    [TestMethod]
    public async Task CanSignInAsync_ActiveUser_ShouldReturnTrue() {
        using var context = await CreateAndPrepareAsync();
        var (user, _) = await SeedSingleUserAsync(context);

        try {
            var canSignIn = await context.UserCanSignIn(user.Id, CancellationToken.None);
            Assert.IsTrue(canSignIn);
        } finally {
            context.UserDelete(user);
            await context.Complete();
        }
    }

    [TestMethod]
    public async Task CanSignInAsync_LockedOutUser_ShouldReturnFalse() {
        using var context = await CreateAndPrepareAsync();
        var userId = Guid.NewGuid();
        var uniqueName = $"locked_{userId:N}";
        var lockedUser = new ApplicationUser {
            Id = userId,
            UserName = uniqueName,
            NormalizedUserName = uniqueName.ToUpperInvariant(),
            Email = $"{uniqueName}@test.com",
            NormalizedEmail = $"{uniqueName}@test.com".ToUpperInvariant(),
            SecurityStamp = Guid.NewGuid().ToString(),
            LockoutEnabled = true,
            LockoutEnd = DateTimeOffset.UtcNow.AddDays(1)
        };
        await context.UserAdd(lockedUser, CancellationToken.None);

        try {
            var canSignIn = await context.UserCanSignIn(userId, CancellationToken.None);
            Assert.IsFalse(canSignIn);
        } finally {
            context.UserDelete(lockedUser);
            await context.Complete();
        }
    }

    [TestMethod]
    public async Task CanSignInAsync_UnknownUser_ShouldReturnFalse() {
        using var context = await CreateAndPrepareAsync();

        var canSignIn = await context.UserCanSignIn(Guid.NewGuid(), CancellationToken.None);

        Assert.IsFalse(canSignIn);
    }

    [TestMethod]
    public async Task CanSignInTenantAsync_ActiveUserInActiveTenant_ShouldReturnTrue() {
        using var context = await CreateAndPrepareAsync();
        var (user, tenant, userTenant) = await SeedUserAndTenantAsync(context, isLocked: false);

        try {
            var canSignIn = await context.UserCanSignInTenant(user.Id, tenant.Id, CancellationToken.None);
            Assert.IsTrue(canSignIn);
        } finally {
            await CleanupUserTenantAsync(context, user, tenant, userTenant);
        }
    }

    [TestMethod]
    public async Task CanSignInTenantAsync_ActiveUserInLockedTenant_ShouldReturnFalse() {
        using var context = await CreateAndPrepareAsync();
        var (user, tenant, userTenant) = await SeedUserAndTenantAsync(context, isLocked: true);

        try {
            var canSignIn = await context.UserCanSignInTenant(user.Id, tenant.Id, CancellationToken.None);
            Assert.IsFalse(canSignIn);
        } finally {
            await CleanupUserTenantAsync(context, user, tenant, userTenant);
        }
    }

    [TestMethod]
    public async Task CanSignInTenantAsync_ActiveUserNotLinkedToTenant_ShouldReturnFalse() {
        using var context = await CreateAndPrepareAsync();
        var (user, _) = await SeedSingleUserAsync(context);

        try {
            var canSignIn = await context.UserCanSignInTenant(user.Id, Guid.NewGuid(), CancellationToken.None);
            Assert.IsFalse(canSignIn);
        } finally {
            context.UserDelete(user);
            await context.Complete();
        }
    }

    [TestMethod]
    public async Task CanSignInTenantAsync_LockedOutUser_ShouldReturnFalse() {
        using var context = await CreateAndPrepareAsync();
        var userId = Guid.NewGuid();
        var uniqueName = $"locked_{userId:N}";
        var lockedUser = new ApplicationUser {
            Id = userId,
            UserName = uniqueName,
            NormalizedUserName = uniqueName.ToUpperInvariant(),
            Email = $"{uniqueName}@test.com",
            NormalizedEmail = $"{uniqueName}@test.com".ToUpperInvariant(),
            SecurityStamp = Guid.NewGuid().ToString(),
            LockoutEnabled = true,
            LockoutEnd = DateTimeOffset.UtcNow.AddDays(1)
        };
        await context.UserAdd(lockedUser, CancellationToken.None);
        var tenantId = Guid.NewGuid();
        var tenant = new ApplicationTenant { Id = tenantId, Name = $"T_{tenantId:N}", AdminEmail = $"t_{tenantId:N}@test.com", IsLocked = false };
        await context.TenantAdd(tenant, CancellationToken.None);
        var userTenant = new ApplicationUserTenant { Id = Guid.NewGuid(), ApplicationUserId = userId, ApplicationTenantId = tenantId };
        await context.UserTenantAdd(userTenant, CancellationToken.None);

        try {
            var canSignIn = await context.UserCanSignInTenant(userId, tenant.Id, CancellationToken.None);
            Assert.IsFalse(canSignIn);
        } finally {
            context.UserTenantDelete(userTenant);
            context.TenantDelete(tenant);
            context.UserDelete(lockedUser);
            await context.Complete();
        }
    }

    [TestMethod]
    public async Task CanSignInTenantAsync_UnknownUser_ShouldReturnFalse() {
        using var context = await CreateAndPrepareAsync();

        var canSignIn = await context.UserCanSignInTenant(Guid.NewGuid(), Guid.NewGuid(), CancellationToken.None);

        Assert.IsFalse(canSignIn);
    }

    // ── Role membership queries ───────────────────────────────────────────────

    [TestMethod]
    public async Task ApplicationUserGetRoles_UserWithRole_ShouldContainRole() {
        using var context = await CreateAndPrepareAsync();
        var userId = Guid.NewGuid();
        var roleId = Guid.NewGuid();
        var (user, role) = await SeedUserAndRoleAsync(context, userId, roleId);
        var userRole = new IdentityUserRole<Guid> { UserId = userId, RoleId = roleId };
        await context.UserRoleAdd(userRole, CancellationToken.None);
        await context.Complete();

        try {
            var roles = await context.UserGetRoles(userId, CancellationToken.None);
            Assert.Contains(r => r == role.Name, roles);
        } finally {
            await CleanupUserRoleAsync(context, user, role, userRole);
        }
        await context.Complete();
    }

    [TestMethod]
    public async Task ApplicationUserGetRoles_UserWithNoRoles_ShouldReturnEmpty() {
        using var context = await CreateAndPrepareAsync();
        var (user, _) = await SeedSingleUserAsync(context);

        try {
            var roles = await context.UserGetRoles(user.Id, CancellationToken.None);
            Assert.IsFalse(roles.Any());
        } finally {
            context.UserDelete(user);
            await context.Complete();
        }
    }

    // ── Display name ──────────────────────────────────────────────────────────

    [TestMethod]
    public async Task ApplicationUserGetName_ExistingUser_ShouldReturnNonEmptyName() {
        using var context = await CreateAndPrepareAsync();
        var (user, _) = await SeedSingleUserAsync(context);

        try {
            var name = await context.UserGetName(user.Id, CancellationToken.None);
            Assert.IsFalse(string.IsNullOrWhiteSpace(name));
        } finally {
            context.UserDelete(user);
            await context.Complete();
        }
    }

    [TestMethod]
    public async Task ApplicationTenantGetName_UnknownId_ShouldReturnUnknown() {
        using var context = await CreateAndPrepareAsync();

        var name = await context.TenantGetName(Guid.NewGuid(), CancellationToken.None);

        Assert.AreEqual("Unknown", name);
    }

    [TestMethod]
    public async Task ApplicationTenantGetName_ExistingTenant_ShouldReturnNonEmptyName() {
        using var context = await CreateAndPrepareAsync();
        var tenantId = Guid.NewGuid();
        var uniqueName = $"NameTenant_{tenantId:N}";
        var tenant = new ApplicationTenant { Id = tenantId, Name = uniqueName, AdminEmail = $"{uniqueName}@test.com" };
        await context.TenantAdd(tenant, CancellationToken.None);

        try {
            var name = await context.TenantGetName(tenantId, CancellationToken.None);
            Assert.IsFalse(string.IsNullOrWhiteSpace(name));
        } finally {
            context.TenantDelete(tenant);
            await context.Complete();
        }
    }

    // ── Select-list helpers ───────────────────────────────────────────────────

    [TestMethod]
    public async Task RolesAsync_ShouldReturnAtLeastOneRole() {
        using var context = await CreateAndPrepareAsync();
        var roleId = Guid.NewGuid();
        var uniqueName = $"ListRole_{roleId:N}";
        var role = new ApplicationRole { Id = roleId, Name = uniqueName, NormalizedName = uniqueName.ToUpperInvariant() };
        await context.RoleAdd(role, CancellationToken.None);

        try {
            var roles = await context.RoleGetSelectList(CancellationToken.None);
            Assert.IsTrue(roles.Any());
        } finally {
            context.RoleDelete(role);
            await context.Complete();
        }
    }

    [TestMethod]
    public async Task UsersAsync_ShouldReturnAtLeastOneUser() {
        using var context = await CreateAndPrepareAsync();
        var (user, _) = await SeedSingleUserAsync(context);

        try {
            var users = await context.UserGetSelectList(CancellationToken.None);
            Assert.IsTrue(users.Any());
        } finally {
            context.UserDelete(user);
            await context.Complete();
        }
    }

    [TestMethod]
    public async Task TenantsAsync_ShouldReturnAtLeastOneTenant() {
        using var context = await CreateAndPrepareAsync();
        var tenantId = Guid.NewGuid();
        var uniqueName = $"ListTenant_{tenantId:N}";
        var tenant = new ApplicationTenant { Id = tenantId, Name = uniqueName, AdminEmail = $"{uniqueName}@test.com" };
        await context.TenantAdd(tenant, CancellationToken.None);

        try {
            var tenants = await context.TenantGetSelectList(CancellationToken.None);
            Assert.IsTrue(tenants.Any());
        } finally {
            context.TenantDelete(tenant);
            await context.Complete();
        }
    }

    // ── Tenant membership queries ─────────────────────────────────────────────

    [TestMethod]
    public async Task ApplicationTenantGetUsers_TenantWithUser_ShouldContainUser() {
        using var context = await CreateAndPrepareAsync();
        var (user, tenant, userTenant) = await SeedUserAndTenantAsync(context, isLocked: false);

        try {
            var users = await context.TenantGetUsers(tenant.Id, CancellationToken.None);
            Assert.IsTrue(users.Any(u => u == user.UserName));
        } finally {
            await CleanupUserTenantAsync(context, user, tenant, userTenant);
        }
    }

    [TestMethod]
    public async Task ApplicationTenantGetUsers_TenantWithNoUsers_ShouldReturnEmpty() {
        using var context = await CreateAndPrepareAsync();
        var tenantId = Guid.NewGuid();
        var uniqueName = $"NoUserTenant_{tenantId:N}";
        var tenant = new ApplicationTenant { Id = tenantId, Name = uniqueName, AdminEmail = $"{uniqueName}@test.com" };
        await context.TenantAdd(tenant, CancellationToken.None);

        try {
            var users = await context.TenantGetUsers(tenantId, CancellationToken.None);
            Assert.IsFalse(users.Any());
        } finally {
            context.TenantDelete(tenant);
            await context.Complete();
        }
    }

    [TestMethod]
    public async Task ApplicationTenantGetUsers_UnknownTenant_ShouldReturnEmpty() {
        using var context = await CreateAndPrepareAsync();

        var users = await context.TenantGetUsers(Guid.NewGuid(), CancellationToken.None);

        Assert.IsFalse(users.Any());
    }

    // ── Health check ──────────────────────────────────────────────────────────

    [TestMethod]
    public async Task Health_RealDatabase_ShouldReturnSuccess() {
        using var context = await CreateAndPrepareAsync();

        var health = context.Health();

        Assert.IsNotNull(health);
        Assert.AreEqual((int)ResponseStatus.Success, health.StatusCode);
    }

    // ── Complete / unit-of-work ───────────────────────────────────────────────

    [TestMethod]
    public async Task Complete_WithMutation_ShouldReturnSuccessAndPersist() {
        using var context = await CreateAndPrepareAsync();
        var roleId = Guid.NewGuid();
        var originalName = $"MutRole_{roleId:N}";
        var role = new ApplicationRole { Id = roleId, Name = originalName, NormalizedName = originalName.ToUpperInvariant() };
        await context.RoleAdd(role, CancellationToken.None);

        try {
            role.Name = originalName + "_v2";
            var (status, message) = await context.Complete();

            Assert.AreEqual(ResponseStatus.Success, status);
            Assert.IsNotNull(message);

            using var verifyContext = await CreateAndPrepareAsync();
            var updated = await verifyContext.RoleFindRecord(originalName.ToUpperInvariant(), CancellationToken.None);
            Assert.IsNotNull(updated);
            Assert.AreEqual(originalName + "_v2", updated.Name);
        } finally {
            context.RoleDelete(role);
            await context.Complete();
        }
    }

    // ── ApplicationDefinition persistence ───────────────────────────────────────────────

    [TestMethod]
    public async Task ApplicationAdd_NewApp_ShouldPersistAndBeRetrievable() {
        using var context = await CreateAndPrepareAsync();
        var tenantId = Guid.NewGuid();
        var tName = $"AppTenant_{tenantId:N}";
        var tenant = new ApplicationTenant { Id = tenantId, Name = tName, AdminEmail = $"{tName}@test.com" };
        await context.TenantAdd(tenant, CancellationToken.None);
        var app = new ApplicationDefinition { Id = Guid.NewGuid(), Name = $"App_{Guid.NewGuid():N}", ApplicationTenantId = tenantId };

        var count = await context.ApplicationAdd(app, CancellationToken.None);

        try {
            Assert.IsGreaterThan(0, count);
            var retrieved = await context.ApplicationFindRecord(app.Id, CancellationToken.None);
            Assert.IsNotNull(retrieved);
            Assert.AreEqual(app.Name, retrieved.Name);
            Assert.AreEqual(tenantId, retrieved.ApplicationTenantId);
        } finally {
            context.ApplicationDelete(app);
            context.TenantDelete(tenant);
            await context.Complete();
        }
    }

    [TestMethod]
    public async Task RemoveApplication_ShouldNotBeRetrievableAfterComplete() {
        using var context = await CreateAndPrepareAsync();
        var tenantId = Guid.NewGuid();
        var tName = $"DelAppTenant_{tenantId:N}";
        var tenant = new ApplicationTenant { Id = tenantId, Name = tName, AdminEmail = $"{tName}@test.com" };
        await context.TenantAdd(tenant, CancellationToken.None);
        var app = new ApplicationDefinition { Id = Guid.NewGuid(), Name = $"DelApp_{Guid.NewGuid():N}", ApplicationTenantId = tenantId };
        await context.ApplicationAdd(app, CancellationToken.None);

        context.ApplicationDelete(app);
        var (status, _) = await context.Complete();

        try {
            Assert.AreEqual(ResponseStatus.Success, status);
            var retrieved = await context.ApplicationFindRecord(app.Id, CancellationToken.None);
            Assert.IsNull(retrieved);
        } finally {
            context.TenantDelete(tenant);
            await context.Complete();
        }
    }

    [TestMethod]
    public async Task ApplicationAsync_ByTenantAndName_ShouldReturn() {
        using var context = await CreateAndPrepareAsync();
        var tenantId = Guid.NewGuid();
        var tName = $"NameAppTenant_{tenantId:N}";
        var appName = $"NamedApp_{Guid.NewGuid():N}";
        var tenant = new ApplicationTenant { Id = tenantId, Name = tName, AdminEmail = $"{tName}@test.com" };
        await context.TenantAdd(tenant, CancellationToken.None);
        var app = new ApplicationDefinition { Id = Guid.NewGuid(), Name = appName, ApplicationTenantId = tenantId };
        await context.ApplicationAdd(app, CancellationToken.None);
        await context.Complete();

        try {
            var retrieved = await context.ApplicationFindRecord(tenantId, appName, CancellationToken.None);
            Assert.IsNotNull(retrieved);
            Assert.AreEqual(app.Id, retrieved.Id);
        } finally {
            context.ApplicationDelete(app);
            context.TenantDelete(tenant);
            await context.Complete();
        }
    }

    [TestMethod]
    public async Task ApplicationAsync_SameNameDifferentTenants_ShouldReturnCorrectOne() {
        using var context = await CreateAndPrepareAsync();
        const string sharedName = "SharedAppName";
        var tenant1Id = Guid.NewGuid();
        var tenant2Id = Guid.NewGuid();
        var tenant1 = new ApplicationTenant { Id = tenant1Id, Name = $"T1_{tenant1Id:N}", AdminEmail = $"t1_{tenant1Id:N}@test.com" };
        var tenant2 = new ApplicationTenant { Id = tenant2Id, Name = $"T2_{tenant2Id:N}", AdminEmail = $"t2_{tenant2Id:N}@test.com" };
        await context.TenantAdd(tenant1, CancellationToken.None);
        await context.TenantAdd(tenant2, CancellationToken.None);
        var app1 = new ApplicationDefinition { Id = Guid.NewGuid(), Name = sharedName, ApplicationTenantId = tenant1Id };
        var app2 = new ApplicationDefinition { Id = Guid.NewGuid(), Name = sharedName, ApplicationTenantId = tenant2Id };
        await context.ApplicationAdd(app1, CancellationToken.None);
        await context.ApplicationAdd(app2, CancellationToken.None);

        try {
            var r1 = await context.ApplicationFindRecord(tenant1Id, sharedName, CancellationToken.None);
            var r2 = await context.ApplicationFindRecord(tenant2Id, sharedName, CancellationToken.None);
            Assert.IsNotNull(r1);
            Assert.IsNotNull(r2);
            Assert.AreNotEqual(r1.Id, r2.Id);
        } finally {
            context.ApplicationDelete(app1);
            context.ApplicationDelete(app2);
            context.TenantDelete(tenant1);
            context.TenantDelete(tenant2);
            await context.Complete();
        }
    }

    [TestMethod]
    public async Task ApplicationFindRecord_UnknownId_ShouldReturnNull() {
        using var context = await CreateAndPrepareAsync();

        var retrieved = await context.ApplicationFindRecord(Guid.NewGuid(), CancellationToken.None);

        Assert.IsNull(retrieved);
    }

    [TestMethod]
    public async Task ApplicationGetName_ExistingApp_ShouldReturnName() {
        using var context = await CreateAndPrepareAsync();
        var tenantId = Guid.NewGuid();
        var tName = $"NameTenant_{tenantId:N}";
        var appName = $"AppName_{Guid.NewGuid():N}";
        var tenant = new ApplicationTenant { Id = tenantId, Name = tName, AdminEmail = $"{tName}@test.com" };
        await context.TenantAdd(tenant, CancellationToken.None);
        var app = new ApplicationDefinition { Id = Guid.NewGuid(), Name = appName, ApplicationTenantId = tenantId };
        await context.ApplicationAdd(app, CancellationToken.None);

        try {
            var name = await context.ApplicationGetName(app.Id, CancellationToken.None);
            Assert.AreEqual(appName, name);
        } finally {
            context.ApplicationDelete(app);
            context.TenantDelete(tenant);
            await context.Complete();
        }
    }

    [TestMethod]
    public async Task ApplicationGetName_UnknownId_ShouldReturnUnknown() {
        using var context = await CreateAndPrepareAsync();

        var name = await context.ApplicationGetName(Guid.NewGuid(), CancellationToken.None);

        Assert.AreEqual("Unknown", name);
    }

    [TestMethod]
    public async Task ApplicationAdd_NullApp_ShouldReturnMinusOne() {
        using var context = await CreateAndPrepareAsync();

        var count = await context.ApplicationAdd(null!, CancellationToken.None);

        Assert.AreEqual(-1, count);
    }

    [TestMethod]
    public async Task ApplicationAsync_WrongTenant_ShouldReturnNull() {
        using var context = await CreateAndPrepareAsync();
        var tenantId = Guid.NewGuid();
        var otherTenantId = Guid.NewGuid();
        var tName = $"WrongT_{tenantId:N}";
        var appName = $"WrongTApp_{Guid.NewGuid():N}";
        var tenant = new ApplicationTenant { Id = tenantId, Name = tName, AdminEmail = $"{tName}@test.com" };
        await context.TenantAdd(tenant, CancellationToken.None);
        var app = new ApplicationDefinition { Id = Guid.NewGuid(), Name = appName, ApplicationTenantId = tenantId };
        await context.ApplicationAdd(app, CancellationToken.None);

        try {
            var retrieved = await context.ApplicationFindRecord(otherTenantId, appName, CancellationToken.None);
            Assert.IsNull(retrieved);
        } finally {
            context.ApplicationDelete(app);
            context.TenantDelete(tenant);
            await context.Complete();
        }
    }

    [TestMethod]
    public async Task ApplicationAsync_UnknownName_ShouldReturnNull() {
        using var context = await CreateAndPrepareAsync();
        var tenantId = Guid.NewGuid();
        var tName = $"UnknownNameT_{tenantId:N}";
        var tenant = new ApplicationTenant { Id = tenantId, Name = tName, AdminEmail = $"{tName}@test.com" };
        await context.TenantAdd(tenant, CancellationToken.None);

        try {
            var retrieved = await context.ApplicationFindRecord(tenantId, $"DoesNotExist_{Guid.NewGuid():N}", CancellationToken.None);
            Assert.IsNull(retrieved);
        } finally {
            context.TenantDelete(tenant);
            await context.Complete();
        }
    }

    [TestMethod]
    public async Task ApplicationGetSelectList_UnknownTenant_ShouldReturnEmpty() {
        using var context = await CreateAndPrepareAsync();

        var list = await context.ApplicationGetSelectList(Guid.NewGuid(), CancellationToken.None);

        Assert.IsFalse(list.Any());
    }

    [TestMethod]
    public async Task ApplicationGetSelectList_LockedApp_ShouldIndicateLockedInDisplayName() {
        using var context = await CreateAndPrepareAsync();
        var tenantId = Guid.NewGuid();
        var tName = $"LockedAppT_{tenantId:N}";
        var tenant = new ApplicationTenant { Id = tenantId, Name = tName, AdminEmail = $"{tName}@test.com" };
        await context.TenantAdd(tenant, CancellationToken.None);
        var app = new ApplicationDefinition { Id = Guid.NewGuid(), Name = $"LockMe_{Guid.NewGuid():N}", ApplicationTenantId = tenantId, IsLocked = true };
        await context.ApplicationAdd(app, CancellationToken.None);

        try {
            var list = await context.ApplicationGetSelectList(tenantId, CancellationToken.None);
            var item = list.FirstOrDefault(i => i.Key == app.Id);
            Assert.IsNotNull(item, "Locked app should still appear in the list.");
            Assert.IsTrue(item.Value?.RawData?.Contains("(Locked)", StringComparison.OrdinalIgnoreCase));
        } finally {
            context.ApplicationDelete(app);
            context.TenantDelete(tenant);
            await context.Complete();
        }
    }

    [TestMethod]
    public async Task ApplicationGetSelectList_FilteredByTenant_ShouldOnlyReturnTenantApps() {
        using var context = await CreateAndPrepareAsync();
        var tenant1Id = Guid.NewGuid();
        var tenant2Id = Guid.NewGuid();
        var tenant1 = new ApplicationTenant { Id = tenant1Id, Name = $"ListT1_{tenant1Id:N}", AdminEmail = $"t1_{tenant1Id:N}@test.com" };
        var tenant2 = new ApplicationTenant { Id = tenant2Id, Name = $"ListT2_{tenant2Id:N}", AdminEmail = $"t2_{tenant2Id:N}@test.com" };
        await context.TenantAdd(tenant1, CancellationToken.None);
        await context.TenantAdd(tenant2, CancellationToken.None);
        var app1 = new ApplicationDefinition { Id = Guid.NewGuid(), Name = $"ListApp1_{Guid.NewGuid():N}", ApplicationTenantId = tenant1Id };
        var app2 = new ApplicationDefinition { Id = Guid.NewGuid(), Name = $"ListApp2_{Guid.NewGuid():N}", ApplicationTenantId = tenant2Id };
        await context.ApplicationAdd(app1, CancellationToken.None);
        await context.ApplicationAdd(app2, CancellationToken.None);

        try {
            var list = await context.ApplicationGetSelectList(tenant1Id, CancellationToken.None);
            Assert.IsTrue(list.Any(i => i.Key == app1.Id), "Tenant 1 app should appear in its own list.");
            Assert.IsFalse(list.Any(i => i.Key == app2.Id), "Tenant 2 app must not appear in tenant 1's list.");
        } finally {
            context.ApplicationDelete(app1);
            context.ApplicationDelete(app2);
            context.TenantDelete(tenant1);
            context.TenantDelete(tenant2);
            await context.Complete();
        }
    }

    // ── Application secrets ───────────────────────────────────────────────────

    [TestMethod]
    public async Task SecretAdd_NewSecret_ShouldPersistAndBeRetrievable() {
        using var context = await CreateAndPrepareAsync();
        var secret = NewSecret(Guid.NewGuid(), $"hash_{Guid.NewGuid():N}");

        var count = await context.SecretAdd(secret, CancellationToken.None);

        try {
            Assert.IsTrue(count > 0);
            var retrieved = await context.SecretFindRecord(secret.Id, CancellationToken.None);
            Assert.IsNotNull(retrieved);
            Assert.AreEqual(secret.HashedToken, retrieved.HashedToken);
        } finally {
            context.SecretDelete(secret);
            await context.Complete();
        }
    }

    [TestMethod]
    public async Task SecretFindRecord_ByHashedToken_ShouldReturn() {
        using var context = await CreateAndPrepareAsync();
        var hashedToken = $"hash_{Guid.NewGuid():N}";
        var secret = NewSecret(Guid.NewGuid(), hashedToken);
        await context.SecretAdd(secret, CancellationToken.None);

        try {
            var retrieved = await context.SecretFindRecord(hashedToken, CancellationToken.None);
            Assert.IsNotNull(retrieved);
            Assert.AreEqual(secret.Id, retrieved.Id);
        } finally {
            context.SecretDelete(secret);
            await context.Complete();
        }
    }

    [TestMethod]
    public async Task SecretFindRecord_UnknownId_ShouldReturnNull() {
        using var context = await CreateAndPrepareAsync();

        var result = await context.SecretFindRecord(Guid.NewGuid(), CancellationToken.None);

        Assert.IsNull(result);
    }

    [TestMethod]
    public async Task SecretFindRecord_UnknownHashedToken_ShouldReturnNull() {
        using var context = await CreateAndPrepareAsync();

        var result = await context.SecretFindRecord("nonexistent_hash", CancellationToken.None);

        Assert.IsNull(result);
    }

    [TestMethod]
    public async Task SecretDelete_ExistingSecret_ShouldNotBeRetrievableAfterComplete() {
        using var context = await CreateAndPrepareAsync();
        var secret = NewSecret(Guid.NewGuid(), $"hash_{Guid.NewGuid():N}");
        await context.SecretAdd(secret, CancellationToken.None);

        context.SecretDelete(secret);
        await context.Complete();

        var retrieved = await context.SecretFindRecord(secret.Id, CancellationToken.None);
        Assert.IsNull(retrieved);
    }

    [TestMethod]
    public async Task SecretGetSelectList_WithActiveSecret_ShouldReturnEntry() {
        using var context = await CreateAndPrepareAsync();
        var ownerId = Guid.NewGuid();
        var secret = NewSecret(ownerId, $"hash_{Guid.NewGuid():N}", "My Token", DateTime.UtcNow.AddDays(30));
        await context.SecretAdd(secret, CancellationToken.None);

        try {
            var list = await context.SecretGetSelectList(ownerId, CancellationToken.None);
            Assert.IsTrue(list.Any(i => i.Key == secret.Id));
        } finally {
            context.SecretDelete(secret);
            await context.Complete();
        }
    }

    [TestMethod]
    public async Task SecretGetSelectList_ExpiredSecret_ShouldNotReturnEntry() {
        using var context = await CreateAndPrepareAsync();
        var ownerId = Guid.NewGuid();
        var secret = NewSecret(ownerId, $"hash_{Guid.NewGuid():N}", "Expired Token", DateTime.UtcNow.AddDays(-1));
        await context.SecretAdd(secret, CancellationToken.None);

        try {
            var list = await context.SecretGetSelectList(ownerId, CancellationToken.None);
            Assert.IsFalse(list.Any(i => i.Key == secret.Id));
        } finally {
            context.SecretDelete(secret);
            await context.Complete();
        }
    }

    [TestMethod]
    public async Task SecretGetSelectList_UnknownOwner_ShouldReturnEmpty() {
        using var context = await CreateAndPrepareAsync();

        var list = await context.SecretGetSelectList(Guid.NewGuid(), CancellationToken.None);

        Assert.IsFalse(list.Any());
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    private static ApplicationSecret NewSecret(Guid ownerId, string hashedToken, string? name = null, DateTime? expiration = null) => new() {
        Id = Guid.NewGuid(),
        ReferenceId = ownerId,
        ReferenceType = "test",
        HashedToken = hashedToken,
        Name = name,
        NormalizedName = name?.ToUpperInvariant(),
        Expiration = expiration ?? DateTime.UtcNow.AddDays(30)
    };

    private static async Task<(ApplicationUser user, string uniqueName)> SeedSingleUserAsync(N2IdentityContext context) {
        var userId = Guid.NewGuid();
        var uniqueName = $"u_{userId:N}";
        var user = new ApplicationUser {
            Id = userId,
            UserName = uniqueName,
            NormalizedUserName = uniqueName.ToUpperInvariant(),
            Email = $"{uniqueName}@test.com",
            NormalizedEmail = $"{uniqueName}@test.com".ToUpperInvariant(),
            SecurityStamp = Guid.NewGuid().ToString(),
            EmailConfirmed = true
        };
        await context.UserAdd(user, CancellationToken.None);
        return (user, uniqueName);
    }

    private static async Task<(ApplicationUser user, ApplicationRole role)> SeedUserAndRoleAsync(
        N2IdentityContext context, Guid userId, Guid roleId) {
        var uName = $"ur_{userId:N}";
        var rName = $"Role_{roleId:N}";
        var user = new ApplicationUser {
            Id = userId,
            UserName = uName,
            NormalizedUserName = uName.ToUpperInvariant(),
            Email = $"{uName}@test.com",
            NormalizedEmail = $"{uName}@test.com".ToUpperInvariant(),
            SecurityStamp = Guid.NewGuid().ToString(),
            EmailConfirmed = true
        };
        var role = new ApplicationRole { Id = roleId, Name = rName, NormalizedName = rName.ToUpperInvariant() };
        await context.UserAdd(user, CancellationToken.None);
        await context.RoleAdd(role, CancellationToken.None);
        return (user, role);
    }

    private static async Task<(ApplicationUser user, ApplicationTenant tenant, ApplicationUserTenant userTenant)> SeedUserAndTenantAsync(
        N2IdentityContext context, bool isLocked) {
        var (user, _) = await SeedSingleUserAsync(context);
        var tenantId = Guid.NewGuid();
        var tName = $"Tenant_{tenantId:N}";
        var tenant = new ApplicationTenant { Id = tenantId, Name = tName, AdminEmail = $"{tName}@test.com", IsLocked = isLocked };
        await context.TenantAdd(tenant, CancellationToken.None);
        var userTenant = new ApplicationUserTenant { Id = Guid.NewGuid(), ApplicationUserId = user.Id, ApplicationTenantId = tenantId };
        await context.UserTenantAdd(userTenant, CancellationToken.None);
        return (user, tenant, userTenant);
    }

    private static async Task CleanupUserTenantAsync(
        N2IdentityContext context,
        ApplicationUser user,
        ApplicationTenant tenant,
        ApplicationUserTenant userTenant) {
        context.UserTenantDelete(userTenant);
        context.TenantDelete(tenant);
        context.UserDelete(user);
        await context.Complete();
    }

    private static async Task CleanupUserRoleAsync(
        N2IdentityContext context,
        ApplicationUser user,
        ApplicationRole role,
        IdentityUserRole<Guid>? userRole) {
        if (userRole is not null)
            context.UserRoleDelete(userRole);
        context.RoleDelete(role);
        context.UserDelete(user);
        await context.Complete();
    }
}
