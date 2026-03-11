using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;

using Moq;

using N2.Core.Commands;
using N2.Core.Entity;
using N2.Core.Identity.Data;

namespace N2.Core.Identity.UnitTests;

/// <summary>
/// Integration tests that run the same database-functionality scenarios as
/// <see cref="N2IdentityContextTests"/> against real SQL Server and MySQL databases.
/// Connection strings must be present in User Secrets under the keys
/// "ConnectionStrings:UserDbSqlServerTest" and "ConnectionStrings:UserDbMySqlTest".
/// </summary>
[TestClass]
[TestCategory("Integration")]
public class N2IdentityContextIntegrationTests {
    private const string SqlServerConnectionName = "UserDbSqlServerTest";
    private const string MySqlConnectionName = "UserDbMySqlTest";

    private static IConfiguration BuildConfiguration() {
        return new ConfigurationBuilder()
            .AddUserSecrets<N2IdentityContextIntegrationTests>()
            .Build();
    }

    private static Mock<IConnectionStringService> BuildMock(IConfiguration configuration) {
        var mock = new Mock<IConnectionStringService>();
        mock.Setup(s => s.GetConnectionString(It.IsAny<string>()))
            .Returns((string name) => configuration.GetConnectionString(name) ?? string.Empty);
        return mock;
    }

    private static string ConnectionNameFor(DatabaseProvider provider) {
        return provider switch {
            DatabaseProvider.MySql => MySqlConnectionName,
            _ => SqlServerConnectionName
        };
    }

    /// <summary>
    /// Creates a real <see cref="N2IdentityContext"/> and applies all pending migrations.
    /// </summary>
    private static async Task<N2IdentityContext> CreateAndPrepareAsync(DatabaseProvider provider) {
        var factory = new N2IdentityContextFactory(BuildMock(BuildConfiguration()).Object);
        var context = (N2IdentityContext)await factory.CreateAsync(provider, ConnectionNameFor(provider));
        await context.Database.MigrateAsync();
        return context;
    }

    // -------------------------------------------------------------------------
    // Migration verification (SQL Server)
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task SqlServer_MigrateAsync_ShouldHaveNoPendingMigrations() {
        var factory = new N2IdentityContextFactory(BuildMock(BuildConfiguration()).Object);
        using var context = (N2IdentityContext)await factory.CreateAsync(
            DatabaseProvider.SqlServer, SqlServerConnectionName);

        await context.Database.MigrateAsync();

        var pending = (await context.Database.GetPendingMigrationsAsync()).ToList();
        Assert.IsEmpty(pending,
            $"Unexpected pending migrations: {string.Join(", ", pending)}");
    }

    // -------------------------------------------------------------------------
    // Migration verification (MySql)
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task MySql_MigrateAsync_ShouldHaveNoPendingMigrations() {
        var factory = new N2IdentityContextFactory(BuildMock(BuildConfiguration()).Object);
        using var context = (N2IdentityContext)await factory.CreateAsync(
            DatabaseProvider.MySql, MySqlConnectionName);

        await context.Database.MigrateAsync();

        var pending = (await context.Database.GetPendingMigrationsAsync()).ToList();
        Assert.AreEqual(0, pending.Count,
            $"Unexpected pending migrations: {string.Join(", ", pending)}");
    }

    // -------------------------------------------------------------------------
    // User persistence
    // -------------------------------------------------------------------------

    [TestMethod]
    [DataRow(DatabaseProvider.SqlServer)]
    [DataRow(DatabaseProvider.MySql)]
    public async Task AddApplicationUserAsync_NewUser_ShouldPersistAndBeRetrievable(DatabaseProvider provider) {
        using var context = await CreateAndPrepareAsync(provider);
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

        var count = await context.AddApplicationUserAsync(user, CancellationToken.None);

        try {
            Assert.IsTrue(count > 0, "SaveChanges should report at least one row affected.");
            var retrieved = await context.ApplicationUserAsync(userId, CancellationToken.None);
            Assert.IsNotNull(retrieved);
            Assert.AreEqual(uniqueName, retrieved.UserName);
        } finally {
            context.RemoveApplicationUser(user);
            await context.Complete();
        }
    }

    [TestMethod]
    [DataRow(DatabaseProvider.SqlServer)]
    [DataRow(DatabaseProvider.MySql)]
    public async Task AddApplicationUserAsync_ExtendedProperties_ShouldRoundTrip(DatabaseProvider provider) {
        using var context = await CreateAndPrepareAsync(provider);
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

        await context.AddApplicationUserAsync(user, CancellationToken.None);

        try {
            // Use a fresh context to verify data was actually persisted, not just cached
            using var verifyContext = await CreateAndPrepareAsync(provider);
            var retrieved = await verifyContext.ApplicationUserAsync(userId, CancellationToken.None);
            Assert.IsNotNull(retrieved);
            Assert.AreEqual("Jane", retrieved.FirstName);
            Assert.AreEqual("Doe", retrieved.LastName);
            Assert.AreEqual("M", retrieved.MiddleName);
            Assert.AreEqual("Jane M. Doe", retrieved.DisplayName);
            Assert.AreEqual("/images/jane.png", retrieved.ImagePath);
            Assert.AreEqual(MultiFactorType.Email, retrieved.MfaType);
            Assert.IsFalse(retrieved.MfaConfirmed);
        } finally {
            context.RemoveApplicationUser(user);
            await context.Complete();
        }
    }

    [TestMethod]
    [DataRow(DatabaseProvider.SqlServer)]
    [DataRow(DatabaseProvider.MySql)]
    public async Task RemoveApplicationUser_ShouldNotBeRetrievableAfterComplete(DatabaseProvider provider) {
        using var context = await CreateAndPrepareAsync(provider);
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
        await context.AddApplicationUserAsync(user, CancellationToken.None);

        context.RemoveApplicationUser(user);
        var (status, _) = await context.Complete();

        Assert.AreEqual(ResponseStatus.Success, status);
        var retrieved = await context.ApplicationUserAsync(userId, CancellationToken.None);
        Assert.IsNull(retrieved);
    }

    // -------------------------------------------------------------------------
    // Role persistence
    // -------------------------------------------------------------------------

    [TestMethod]
    [DataRow(DatabaseProvider.SqlServer)]
    [DataRow(DatabaseProvider.MySql)]
    public async Task AddApplicationRoleAsync_NewRole_ShouldPersistAndBeRetrievable(DatabaseProvider provider) {
        using var context = await CreateAndPrepareAsync(provider);
        var roleId = Guid.NewGuid();
        var uniqueName = $"Role_{roleId:N}";
        var role = new ApplicationRole {
            Id = roleId,
            Name = uniqueName,
            NormalizedName = uniqueName.ToUpperInvariant()
        };

        var count = await context.AddApplicationRoleAsync(role, CancellationToken.None);

        try {
            Assert.IsTrue(count > 0);
            var retrieved = await context.ApplicationRoleAsync(uniqueName.ToUpperInvariant(), CancellationToken.None);
            Assert.IsNotNull(retrieved);
            Assert.AreEqual(uniqueName, retrieved.Name);
        } finally {
            context.RemoveApplicationRole(role);
            await context.Complete();
        }
    }

    [TestMethod]
    [DataRow(DatabaseProvider.SqlServer)]
    [DataRow(DatabaseProvider.MySql)]
    public async Task RemoveApplicationRole_ShouldNotBeRetrievableAfterComplete(DatabaseProvider provider) {
        using var context = await CreateAndPrepareAsync(provider);
        var roleId = Guid.NewGuid();
        var uniqueName = $"DelRole_{roleId:N}";
        var role = new ApplicationRole {
            Id = roleId,
            Name = uniqueName,
            NormalizedName = uniqueName.ToUpperInvariant()
        };
        await context.AddApplicationRoleAsync(role, CancellationToken.None);

        context.RemoveApplicationRole(role);
        var (status, _) = await context.Complete();

        Assert.AreEqual(ResponseStatus.Success, status);
        var retrieved = await context.ApplicationRoleAsync(uniqueName.ToUpperInvariant(), CancellationToken.None);
        Assert.IsNull(retrieved);
    }

    // -------------------------------------------------------------------------
    // User-role assignment
    // -------------------------------------------------------------------------

    [TestMethod]
    [DataRow(DatabaseProvider.SqlServer)]
    [DataRow(DatabaseProvider.MySql)]
    public async Task AddIdentityUserRoleAsync_ShouldPersistAndBeRetrievable(DatabaseProvider provider) {
        using var context = await CreateAndPrepareAsync(provider);
        var userId = Guid.NewGuid();
        var roleId = Guid.NewGuid();
        var (user, role) = await SeedUserAndRoleAsync(context, userId, roleId);

        var userRole = new IdentityUserRole<Guid> { UserId = userId, RoleId = roleId };
        var count = await context.AddIdentityUserRoleAsync(userRole, CancellationToken.None);

        try {
            Assert.IsTrue(count > 0);
            var retrieved = await context.IdentityUserRoleAsync(userId, roleId, CancellationToken.None);
            Assert.IsNotNull(retrieved);
            Assert.AreEqual(userId, retrieved.UserId);
            Assert.AreEqual(roleId, retrieved.RoleId);
        } finally {
            await CleanupUserRoleAsync(context, user, role, userRole);
        }
    }

    [TestMethod]
    [DataRow(DatabaseProvider.SqlServer)]
    [DataRow(DatabaseProvider.MySql)]
    public async Task RemoveApplicationUserRole_ShouldNotBeRetrievableAfterComplete(DatabaseProvider provider) {
        using var context = await CreateAndPrepareAsync(provider);
        var userId = Guid.NewGuid();
        var roleId = Guid.NewGuid();
        var (user, role) = await SeedUserAndRoleAsync(context, userId, roleId);
        var userRole = new IdentityUserRole<Guid> { UserId = userId, RoleId = roleId };
        await context.AddIdentityUserRoleAsync(userRole, CancellationToken.None);

        context.RemoveApplicationUserRole(userRole);
        await context.Complete();

        try {
            var retrieved = await context.IdentityUserRoleAsync(userId, roleId, CancellationToken.None);
            Assert.IsNull(retrieved);
        } finally {
            await CleanupUserRoleAsync(context, user, role, null);
        }
    }

    // -------------------------------------------------------------------------
    // Lookup queries
    // -------------------------------------------------------------------------

    [TestMethod]
    [DataRow(DatabaseProvider.SqlServer)]
    [DataRow(DatabaseProvider.MySql)]
    public async Task ApplicationUserAsync_ByNormalizedName_ShouldReturn(DatabaseProvider provider) {
        using var context = await CreateAndPrepareAsync(provider);
        var (user, _) = await SeedSingleUserAsync(context);

        try {
            var retrieved = await context.ApplicationUserAsync(user.NormalizedUserName!, CancellationToken.None);
            Assert.IsNotNull(retrieved);
            Assert.AreEqual(user.Id, retrieved.Id);
        } finally {
            context.RemoveApplicationUser(user);
            await context.Complete();
        }
    }

    [TestMethod]
    [DataRow(DatabaseProvider.SqlServer)]
    [DataRow(DatabaseProvider.MySql)]
    public async Task ApplicationUserAsync_ByGuid_ShouldReturn(DatabaseProvider provider) {
        using var context = await CreateAndPrepareAsync(provider);
        var (user, _) = await SeedSingleUserAsync(context);

        try {
            var retrieved = await context.ApplicationUserAsync(user.Id, CancellationToken.None);
            Assert.IsNotNull(retrieved);
            Assert.AreEqual(user.UserName, retrieved.UserName);
        } finally {
            context.RemoveApplicationUser(user);
            await context.Complete();
        }
    }

    [TestMethod]
    [DataRow(DatabaseProvider.SqlServer)]
    [DataRow(DatabaseProvider.MySql)]
    public async Task ApplicationUserByEmailAsync_ShouldReturn(DatabaseProvider provider) {
        using var context = await CreateAndPrepareAsync(provider);
        var (user, _) = await SeedSingleUserAsync(context);

        try {
            var retrieved = await context.ApplicationUserByEmailAsync(user.NormalizedEmail!, CancellationToken.None);
            Assert.IsNotNull(retrieved);
            Assert.AreEqual(user.Id, retrieved.Id);
        } finally {
            context.RemoveApplicationUser(user);
            await context.Complete();
        }
    }

    [TestMethod]
    [DataRow(DatabaseProvider.SqlServer)]
    [DataRow(DatabaseProvider.MySql)]
    public async Task FindByNameAsync_ExistingUser_ShouldReturnSuccess(DatabaseProvider provider) {
        using var context = await CreateAndPrepareAsync(provider);
        var (user, _) = await SeedSingleUserAsync(context);

        try {
            var result = await context.FindByNameAsync(user.NormalizedUserName!, CancellationToken.None);
            Assert.AreEqual(ResponseStatus.Accepted, result.Status);
            Assert.IsNotNull(result.Value);
            Assert.AreEqual(user.Id, result.Value.Id);
        } finally {
            context.RemoveApplicationUser(user);
            await context.Complete();
        }
    }

    [TestMethod]
    [DataRow(DatabaseProvider.SqlServer)]
    [DataRow(DatabaseProvider.MySql)]
    public async Task FindByNameAsync_NonExistentUser_ShouldReturnNotFound(DatabaseProvider provider) {
        using var context = await CreateAndPrepareAsync(provider);

        var result = await context.FindByNameAsync($"GHOST_{Guid.NewGuid():N}", CancellationToken.None);

        Assert.AreNotEqual(ResponseStatus.Success, result.Status);
    }

    [TestMethod]
    [DataRow(DatabaseProvider.SqlServer)]
    [DataRow(DatabaseProvider.MySql)]
    public async Task FindByIdAsync_ExistingUser_ShouldReturn(DatabaseProvider provider) {
        using var context = await CreateAndPrepareAsync(provider);
        var (user, _) = await SeedSingleUserAsync(context);

        try {
            var retrieved = await context.FindByIdAsync(user.Id, CancellationToken.None);
            Assert.IsNotNull(retrieved);
            Assert.AreEqual(user.UserName, retrieved.UserName);
        } finally {
            context.RemoveApplicationUser(user);
            await context.Complete();
        }
    }

    [TestMethod]
    [DataRow(DatabaseProvider.SqlServer)]
    [DataRow(DatabaseProvider.MySql)]
    public async Task FindByEmailAsync_ExistingUser_ShouldReturn(DatabaseProvider provider) {
        using var context = await CreateAndPrepareAsync(provider);
        var (user, _) = await SeedSingleUserAsync(context);

        try {
            var retrieved = await context.FindByEmailAsync(user.NormalizedEmail!, CancellationToken.None);
            Assert.IsNotNull(retrieved);
            Assert.AreEqual(user.Id, retrieved.Id);
        } finally {
            context.RemoveApplicationUser(user);
            await context.Complete();
        }
    }

    [TestMethod]
    [DataRow(DatabaseProvider.SqlServer)]
    [DataRow(DatabaseProvider.MySql)]
    public async Task ApplicationRoleAsync_ByNormalizedName_ShouldReturn(DatabaseProvider provider) {
        using var context = await CreateAndPrepareAsync(provider);
        var roleId = Guid.NewGuid();
        var uniqueName = $"LookupRole_{roleId:N}";
        var role = new ApplicationRole { Id = roleId, Name = uniqueName, NormalizedName = uniqueName.ToUpperInvariant() };
        await context.AddApplicationRoleAsync(role, CancellationToken.None);

        try {
            var retrieved = await context.ApplicationRoleAsync(uniqueName.ToUpperInvariant(), CancellationToken.None);
            Assert.IsNotNull(retrieved);
            Assert.AreEqual(uniqueName, retrieved.Name);
        } finally {
            context.RemoveApplicationRole(role);
            await context.Complete();
        }
    }

    // -------------------------------------------------------------------------
    // Sign-in eligibility
    // -------------------------------------------------------------------------

    [TestMethod]
    [DataRow(DatabaseProvider.SqlServer)]
    [DataRow(DatabaseProvider.MySql)]
    public async Task CanSignInAsync_ActiveUser_ShouldReturnTrue(DatabaseProvider provider) {
        using var context = await CreateAndPrepareAsync(provider);
        var (user, _) = await SeedSingleUserAsync(context);

        try {
            var canSignIn = await context.CanSignInAsync(user.Id);
            Assert.IsTrue(canSignIn);
        } finally {
            context.RemoveApplicationUser(user);
            await context.Complete();
        }
    }

    [TestMethod]
    [DataRow(DatabaseProvider.SqlServer)]
    [DataRow(DatabaseProvider.MySql)]
    public async Task CanSignInAsync_LockedOutUser_ShouldReturnFalse(DatabaseProvider provider) {
        using var context = await CreateAndPrepareAsync(provider);
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
        await context.AddApplicationUserAsync(lockedUser, CancellationToken.None);

        try {
            var canSignIn = await context.CanSignInAsync(userId);
            Assert.IsFalse(canSignIn);
        } finally {
            context.RemoveApplicationUser(lockedUser);
            await context.Complete();
        }
    }

    [TestMethod]
    [DataRow(DatabaseProvider.SqlServer)]
    [DataRow(DatabaseProvider.MySql)]
    public async Task CanSignInAsync_UnknownUser_ShouldReturnFalse(DatabaseProvider provider) {
        using var context = await CreateAndPrepareAsync(provider);

        var canSignIn = await context.CanSignInAsync(Guid.NewGuid());

        Assert.IsFalse(canSignIn);
    }

    // -------------------------------------------------------------------------
    // Role membership queries
    // -------------------------------------------------------------------------

    [TestMethod]
    [DataRow(DatabaseProvider.SqlServer)]
    [DataRow(DatabaseProvider.MySql)]
    public async Task UserRolesAsync_UserWithRole_ShouldContainRole(DatabaseProvider provider) {
        using var context = await CreateAndPrepareAsync(provider);
        var userId = Guid.NewGuid();
        var roleId = Guid.NewGuid();
        var (user, role) = await SeedUserAndRoleAsync(context, userId, roleId);
        var userRole = new IdentityUserRole<Guid> { UserId = userId, RoleId = roleId };
        await context.AddIdentityUserRoleAsync(userRole, CancellationToken.None);
        await context.Complete();

        try {
            var roles = await context.UserRolesAsync(userId);
            Assert.Contains(r => r == role.Name, roles);
        } finally {
            await CleanupUserRoleAsync(context, user, role, userRole);
        }
    }

    [TestMethod]
    [DataRow(DatabaseProvider.SqlServer)]
    [DataRow(DatabaseProvider.MySql)]
    public async Task UserRolesAsync_UserWithNoRoles_ShouldReturnEmpty(DatabaseProvider provider) {
        using var context = await CreateAndPrepareAsync(provider);
        var (user, _) = await SeedSingleUserAsync(context);

        try {
            var roles = await context.UserRolesAsync(user.Id);
            Assert.IsFalse(roles.Any());
        } finally {
            context.RemoveApplicationUser(user);
            await context.Complete();
        }
    }

    // -------------------------------------------------------------------------
    // Display name
    // -------------------------------------------------------------------------

    [TestMethod]
    [DataRow(DatabaseProvider.SqlServer)]
    [DataRow(DatabaseProvider.MySql)]
    public async Task GetNameForUserAsync_ExistingUser_ShouldReturnNonEmptyName(DatabaseProvider provider) {
        using var context = await CreateAndPrepareAsync(provider);
        var (user, _) = await SeedSingleUserAsync(context);

        try {
            var name = await context.GetNameForUserAsync(user.Id);
            Assert.IsFalse(string.IsNullOrWhiteSpace(name));
        } finally {
            context.RemoveApplicationUser(user);
            await context.Complete();
        }
    }

    // -------------------------------------------------------------------------
    // Select-list helpers
    // -------------------------------------------------------------------------

    [TestMethod]
    [DataRow(DatabaseProvider.SqlServer)]
    [DataRow(DatabaseProvider.MySql)]
    public async Task RolesAsync_ShouldReturnAtLeastOneRole(DatabaseProvider provider) {
        using var context = await CreateAndPrepareAsync(provider);
        var roleId = Guid.NewGuid();
        var uniqueName = $"ListRole_{roleId:N}";
        var role = new ApplicationRole { Id = roleId, Name = uniqueName, NormalizedName = uniqueName.ToUpperInvariant() };
        await context.AddApplicationRoleAsync(role, CancellationToken.None);

        try {
            var roles = await context.RolesAsync();
            Assert.IsTrue(roles.Any());
        } finally {
            context.RemoveApplicationRole(role);
            await context.Complete();
        }
    }

    [TestMethod]
    [DataRow(DatabaseProvider.SqlServer)]
    [DataRow(DatabaseProvider.MySql)]
    public async Task UsersAsync_ShouldReturnAtLeastOneUser(DatabaseProvider provider) {
        using var context = await CreateAndPrepareAsync(provider);
        var (user, _) = await SeedSingleUserAsync(context);

        try {
            var users = await context.UsersAsync();
            Assert.IsTrue(users.Any());
        } finally {
            context.RemoveApplicationUser(user);
            await context.Complete();
        }
    }

    // -------------------------------------------------------------------------
    // Health check
    // -------------------------------------------------------------------------

    [TestMethod]
    [DataRow(DatabaseProvider.SqlServer)]
    [DataRow(DatabaseProvider.MySql)]
    public async Task Health_RealDatabase_ShouldReturnSuccess(DatabaseProvider provider) {
        using var context = await CreateAndPrepareAsync(provider);

        var health = context.Health();

        Assert.IsNotNull(health);
        Assert.AreEqual((int)ResponseStatus.Success, health.StatusCode);
    }

    // -------------------------------------------------------------------------
    // Complete / unit-of-work
    // -------------------------------------------------------------------------

    [TestMethod]
    [DataRow(DatabaseProvider.SqlServer)]
    [DataRow(DatabaseProvider.MySql)]
    public async Task Complete_WithMutation_ShouldReturnSuccessAndPersist(DatabaseProvider provider) {
        using var context = await CreateAndPrepareAsync(provider);
        var roleId = Guid.NewGuid();
        var originalName = $"MutRole_{roleId:N}";
        var role = new ApplicationRole { Id = roleId, Name = originalName, NormalizedName = originalName.ToUpperInvariant() };
        await context.AddApplicationRoleAsync(role, CancellationToken.None);

        try {
            role.Name = originalName + "_v2";
            var (status, message) = await context.Complete();

            Assert.AreEqual(ResponseStatus.Success, status);
            Assert.IsNotNull(message);

            using var verifyContext = await CreateAndPrepareAsync(provider);
            var updated = await verifyContext.ApplicationRoleAsync(originalName.ToUpperInvariant(), CancellationToken.None);
            Assert.IsNotNull(updated);
            Assert.AreEqual(originalName + "_v2", updated.Name);
        } finally {
            context.RemoveApplicationRole(role);
            await context.Complete();
        }
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

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
        await context.AddApplicationUserAsync(user, CancellationToken.None);
        return (user, uniqueName);
    }

    private static async Task<(ApplicationUser user, ApplicationRole role)> SeedUserAndRoleAsync(
        N2IdentityContext context, Guid userId, Guid roleId) {
        var uName = $"ur_{userId:N}";
        var rName = $"Role_{roleId:N}";
        var user = new ApplicationUser {
            Id = userId,
            UserName = uName,
            EmailConfirmed = true,
            NormalizedUserName = uName.ToUpperInvariant(),
            Email = $"{uName}@test.com",
            NormalizedEmail = $"{uName}@test.com".ToUpperInvariant(),
            SecurityStamp = Guid.NewGuid().ToString()
        };
        var role = new ApplicationRole { Id = roleId, Name = rName, NormalizedName = rName.ToUpperInvariant() };
        await context.AddApplicationUserAsync(user, CancellationToken.None);
        await context.AddApplicationRoleAsync(role, CancellationToken.None);
        return (user, role);
    }

    private static async Task CleanupUserRoleAsync(
        N2IdentityContext context,
        ApplicationUser user,
        ApplicationRole role,
        IdentityUserRole<Guid>? userRole) {
        if (userRole is not null)
            context.RemoveApplicationUserRole(userRole);
        context.RemoveApplicationRole(role);
        context.RemoveApplicationUser(user);
        await context.Complete();
    }
}
