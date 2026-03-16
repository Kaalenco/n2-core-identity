using N2.Core.Commands;
using N2.Core.Identity.Data;

namespace N2.Core.Identity.UnitTests;

/// <summary>
/// Tests for <see cref="Application"/> CRUD and query operations via <see cref="IIdentityContext"/>.
/// Applications are always scoped to a tenant — name uniqueness is per-tenant, not global.
/// </summary>
[TestClass]
public class UsingApplicationPerTenant : N2IdentityTestsBase {

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private static Application NewApp(Guid tenantId, string name = "My App") {
        return new() {
            Id = Guid.NewGuid(),
            Name = name,
            ApplicationTenantId = tenantId,
            IsLocked = false
        };
    }

    private static async Task<Application> CreateAppAsync(IIdentityContext context, Guid tenantId, string name = "My App") {
        var app = NewApp(tenantId, name);
        var count = await context.AddApplicationAsync(app, CancellationToken.None);
        if (count <= 0) throw new InvalidOperationException($"Failed to seed application '{name}'.");
        return app;
    }

    // -------------------------------------------------------------------------
    // AddApplicationAsync
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task AddApplicationAsync_NewApp_ShouldPersistAndBeRetrievable() {
        using var context = await GetIdentityContext();

        var app = NewApp(TestContext.TenantGuid, $"App {Guid.NewGuid()}");
        var count = await context.AddApplicationAsync(app, CancellationToken.None);

        Assert.IsGreaterThan(0, count, "SaveChanges should report at least one row affected.");
        var retrieved = await context.FindApplicationByIdAsync(app.Id, CancellationToken.None);
        Assert.IsNotNull(retrieved);
        Assert.AreEqual(app.Name, retrieved.Name);
        Assert.AreEqual(TestContext.TenantGuid, retrieved.ApplicationTenantId);
    }

    [TestMethod]
    public async Task AddApplicationAsync_NullApp_ShouldReturnMinusOne() {
        using var context = await GetIdentityContext();

        var count = await context.AddApplicationAsync(null!, CancellationToken.None);

        Assert.AreEqual(-1, count);
    }

    [TestMethod]
    public async Task AddApplicationAsync_SameNameDifferentTenants_ShouldBothPersist() {
        using var context = await GetIdentityContext();
        const string sharedName = "Shared App Name";

        // Seed a second tenant
        var otherTenant = new ApplicationTenant {
            Id = Guid.NewGuid(),
            Name = $"Other Tenant {Guid.NewGuid()}",
            AdminEmail = "other@tenant.com"
        };
        await context.AddApplicationTenantAsync(otherTenant, CancellationToken.None);

        var app1 = await CreateAppAsync(context, TestContext.TenantGuid, sharedName);
        var app2 = await CreateAppAsync(context, otherTenant.Id, sharedName);

        var retrieved1 = await context.ApplicationAsync(TestContext.TenantGuid, sharedName, CancellationToken.None);
        var retrieved2 = await context.ApplicationAsync(otherTenant.Id, sharedName, CancellationToken.None);

        Assert.IsNotNull(retrieved1);
        Assert.IsNotNull(retrieved2);
        Assert.AreNotEqual(retrieved1.Id, retrieved2.Id, "Each tenant should have its own application record.");
    }

    // -------------------------------------------------------------------------
    // RemoveApplication
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task RemoveApplication_ExistingApp_ShouldNotBeRetrievableAfterComplete() {
        using var context = await GetIdentityContext();
        var app = await CreateAppAsync(context, TestContext.TenantGuid, $"To Remove {Guid.NewGuid()}");

        context.RemoveApplication(app);
        var (status, _) = await context.Complete();

        Assert.AreEqual(ResponseStatus.Success, status);
        var retrieved = await context.FindApplicationByIdAsync(app.Id, CancellationToken.None);
        Assert.IsNull(retrieved);
    }

    // -------------------------------------------------------------------------
    // FindApplicationByIdAsync
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task FindApplicationByIdAsync_SeededApp_ShouldReturn() {
        using var context = await GetIdentityContext();

        var app = await context.FindApplicationByIdAsync(TestContext.ApplicationGuid, CancellationToken.None);

        Assert.IsNotNull(app);
        Assert.AreEqual(TestContext.ApplicationGuid, app.Id);
        Assert.AreEqual(TestContext.TenantGuid, app.ApplicationTenantId);
    }

    [TestMethod]
    public async Task FindApplicationByIdAsync_UnknownId_ShouldReturnNull() {
        using var context = await GetIdentityContext();

        var app = await context.FindApplicationByIdAsync(Guid.NewGuid(), CancellationToken.None);

        Assert.IsNull(app);
    }

    // -------------------------------------------------------------------------
    // ApplicationAsync (by tenant + name)
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task ApplicationAsync_SeededApp_ShouldReturn() {
        using var context = await GetIdentityContext();

        var app = await context.ApplicationAsync(TestContext.TenantGuid, "Test App", CancellationToken.None);

        Assert.IsNotNull(app);
        Assert.AreEqual(TestContext.ApplicationGuid, app.Id);
    }

    [TestMethod]
    public async Task ApplicationAsync_WrongTenant_ShouldReturnNull() {
        using var context = await GetIdentityContext();

        // "Test App" exists under TenantGuid but not under LockedTenantGuid
        var app = await context.ApplicationAsync(TestContext.LockedTenantGuid, "Test App", CancellationToken.None);

        Assert.IsNull(app);
    }

    [TestMethod]
    public async Task ApplicationAsync_UnknownName_ShouldReturnNull() {
        using var context = await GetIdentityContext();

        var app = await context.ApplicationAsync(TestContext.TenantGuid, "Does Not Exist", CancellationToken.None);

        Assert.IsNull(app);
    }

    // -------------------------------------------------------------------------
    // GetNameForApplicationAsync
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task GetNameForApplicationAsync_SeededApp_ShouldReturnName() {
        using var context = await GetIdentityContext();

        var name = await context.GetNameForApplicationAsync(TestContext.ApplicationGuid);

        Assert.AreEqual("Test App", name);
    }

    [TestMethod]
    public async Task GetNameForApplicationAsync_UnknownId_ShouldReturnUnknown() {
        using var context = await GetIdentityContext();

        var name = await context.GetNameForApplicationAsync(Guid.NewGuid());

        Assert.AreEqual("Unknown", name);
    }

    // -------------------------------------------------------------------------
    // ApplicationsAsync (select list, scoped to tenant)
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task ApplicationsAsync_SeededTenant_ShouldReturnSeededApp() {
        using var context = await GetIdentityContext();

        var list = await context.ApplicationsAsync(TestContext.TenantGuid);

        Assert.IsNotNull(list);
        Assert.Contains(i => i.Key == TestContext.ApplicationGuid, list,
            "The seeded application should appear in the list for its tenant.");
    }

    [TestMethod]
    public async Task ApplicationsAsync_OtherTenant_ShouldNotReturnAppsFromDifferentTenant() {
        using var context = await GetIdentityContext();

        // LockedTenantGuid has no applications seeded
        var list = await context.ApplicationsAsync(TestContext.LockedTenantGuid);

        Assert.DoesNotContain(i => i.Key == TestContext.ApplicationGuid, list,
            "Applications from a different tenant must not appear.");
    }

    [TestMethod]
    public async Task ApplicationsAsync_UnknownTenant_ShouldReturnEmpty() {
        using var context = await GetIdentityContext();

        var list = await context.ApplicationsAsync(Guid.NewGuid());

        Assert.IsFalse(list.Any());
    }

    [TestMethod]
    public async Task ApplicationsAsync_LockedApp_ShouldIndicateLockedInDisplayName() {
        using var context = await GetIdentityContext();
        var app = await CreateAppAsync(context, TestContext.TenantGuid, $"Lock Me {Guid.NewGuid()}");

        // Lock the app directly
        var retrieved = await context.FindApplicationByIdAsync(app.Id, CancellationToken.None);
        Assert.IsNotNull(retrieved);
        retrieved.IsLocked = true;
        await context.Complete();

        var list = await context.ApplicationsAsync(TestContext.TenantGuid);
        var item = list.FirstOrDefault(i => i.Key == app.Id);

        Assert.IsNotNull(item, "Locked app should still appear in the list.");
        Assert.IsTrue(item.Value?.DisplayName?.Contains("(Locked)", StringComparison.OrdinalIgnoreCase),
            "Display name should indicate the application is locked.");
    }

    // -------------------------------------------------------------------------
    // Application queryable property
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task Application_Queryable_ShouldFilterByTenant() {
        using var context = await GetIdentityContext();

        var apps = context.Application
            .Where(a => a.ApplicationTenantId == TestContext.TenantGuid)
            .ToList();

        Assert.IsTrue(apps.Any(a => a.Id == TestContext.ApplicationGuid));
        Assert.IsTrue(apps.All(a => a.ApplicationTenantId == TestContext.TenantGuid));
    }
}
