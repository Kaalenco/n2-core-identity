using N2.Core.Commands;
using N2.Core.Identity.Data;

namespace N2.Core.Identity.UnitTests;

/// <summary>
/// Tests for <see cref="ApplicationDefinition"/> CRUD and query operations via <see cref="IIdentityContext"/>.
/// Applications are always scoped to a tenant — name uniqueness is per-tenant, not global.
/// </summary>
[TestClass]
public class UsingApplicationPerTenant : N2IdentityTestsBase {

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private static ApplicationDefinition NewApp(Guid tenantId, string name = "My App") {
        return new() {
            Id = Guid.NewGuid(),
            Name = name,
            ApplicationTenantId = tenantId,
            IsLocked = false
        };
    }

    private static async Task<ApplicationDefinition> CreateAppAsync(IIdentityContext context, Guid tenantId, string name = "My App") {
        var app = NewApp(tenantId, name);
        var count = await context.ApplicationAdd(app, CancellationToken.None);
        if (count <= 0) throw new InvalidOperationException($"Failed to seed application '{name}'.");
        return app;
    }

    // -------------------------------------------------------------------------
    // ApplicationAdd
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task ApplicationAdd_NewApp_ShouldPersistAndBeRetrievable() {
        using var context = await GetIdentityContext();

        var app = NewApp(TestContext.TenantGuid, $"App {Guid.NewGuid()}");
        var count = await context.ApplicationAdd(app, CancellationToken.None);

        Assert.IsGreaterThan(0, count, "SaveChanges should report at least one row affected.");
        var retrieved = await context.ApplicationFindRecord(app.Id, CancellationToken.None);
        Assert.IsNotNull(retrieved);
        Assert.AreEqual(app.Name, retrieved.Name);
        Assert.AreEqual(TestContext.TenantGuid, retrieved.ApplicationTenantId);
    }

    [TestMethod]
    public async Task ApplicationAdd_NullApp_ShouldReturnMinusOne() {
        using var context = await GetIdentityContext();

        var count = await context.ApplicationAdd(null!, CancellationToken.None);

        Assert.AreEqual(-1, count);
    }

    [TestMethod]
    public async Task ApplicationAdd_SameNameDifferentTenants_ShouldBothPersist() {
        using var context = await GetIdentityContext();
        const string sharedName = "Shared App Name";

        // Seed a second tenant
        var otherTenant = new ApplicationTenant {
            Id = Guid.NewGuid(),
            Name = $"Other Tenant {Guid.NewGuid()}",
            AdminEmail = "other@tenant.com"
        };
        await context.TenantAdd(otherTenant, CancellationToken.None);

        var app1 = await CreateAppAsync(context, TestContext.TenantGuid, sharedName);
        var app2 = await CreateAppAsync(context, otherTenant.Id, sharedName);

        var retrieved1 = await context.ApplicationFindRecord(TestContext.TenantGuid, sharedName, CancellationToken.None);
        var retrieved2 = await context.ApplicationFindRecord(otherTenant.Id, sharedName, CancellationToken.None);

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

        context.ApplicationDelete(app);
        var (status, _) = await context.Complete();

        Assert.AreEqual(ResponseStatus.Success, status);
        var retrieved = await context.ApplicationFindRecord(app.Id, CancellationToken.None);
        Assert.IsNull(retrieved);
    }

    // -------------------------------------------------------------------------
    // ApplicationFindRecord
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task ApplicationFindRecord_SeededApp_ShouldReturn() {
        using var context = await GetIdentityContext();

        var app = await context.ApplicationFindRecord(TestContext.ApplicationGuid, CancellationToken.None);

        Assert.IsNotNull(app);
        Assert.AreEqual(TestContext.ApplicationGuid, app.Id);
        Assert.AreEqual(TestContext.TenantGuid, app.ApplicationTenantId);
    }

    [TestMethod]
    public async Task ApplicationFindRecord_UnknownId_ShouldReturnNull() {
        using var context = await GetIdentityContext();

        var app = await context.ApplicationFindRecord(Guid.NewGuid(), CancellationToken.None);

        Assert.IsNull(app);
    }

    // -------------------------------------------------------------------------
    // ApplicationAsync (by tenant + name)
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task ApplicationAsync_SeededApp_ShouldReturn() {
        using var context = await GetIdentityContext();

        var app = await context.ApplicationFindRecord(TestContext.TenantGuid, "Test App", CancellationToken.None);

        Assert.IsNotNull(app);
        Assert.AreEqual(TestContext.ApplicationGuid, app.Id);
    }

    [TestMethod]
    public async Task ApplicationAsync_WrongTenant_ShouldReturnNull() {
        using var context = await GetIdentityContext();

        // "Test App" exists under TenantGuid but not under LockedTenantGuid
        var app = await context.ApplicationFindRecord(TestContext.LockedTenantGuid, "Test App", CancellationToken.None);

        Assert.IsNull(app);
    }

    [TestMethod]
    public async Task ApplicationAsync_UnknownName_ShouldReturnNull() {
        using var context = await GetIdentityContext();

        var app = await context.ApplicationFindRecord(TestContext.TenantGuid, "Does Not Exist", CancellationToken.None);

        Assert.IsNull(app);
    }

    // -------------------------------------------------------------------------
    // ApplicationGetName
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task ApplicationGetName_SeededApp_ShouldReturnName() {
        using var context = await GetIdentityContext();

        var name = await context.ApplicationGetName(TestContext.ApplicationGuid, CancellationToken.None);

        Assert.AreEqual("Test App", name);
    }

    [TestMethod]
    public async Task ApplicationGetName_UnknownId_ShouldReturnUnknown() {
        using var context = await GetIdentityContext();

        var name = await context.ApplicationGetName(Guid.NewGuid(), CancellationToken.None);

        Assert.AreEqual("Unknown", name);
    }

    // -------------------------------------------------------------------------
    // ApplicationGetSelectList (select list, scoped to tenant)
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task ApplicationGetSelectList_SeededTenant_ShouldReturnSeededApp() {
        using var context = await GetIdentityContext();

        var list = await context.ApplicationGetSelectList(TestContext.TenantGuid, CancellationToken.None);

        Assert.IsNotNull(list);
        Assert.Contains(i => i.Key == TestContext.ApplicationGuid, list,
            "The seeded application should appear in the list for its tenant.");
    }

    [TestMethod]
    public async Task ApplicationGetSelectList_OtherTenant_ShouldNotReturnAppsFromDifferentTenant() {
        using var context = await GetIdentityContext();

        // LockedTenantGuid has no applications seeded
        var list = await context.ApplicationGetSelectList(TestContext.LockedTenantGuid, CancellationToken.None);

        Assert.DoesNotContain(i => i.Key == TestContext.ApplicationGuid, list,
            "Applications from a different tenant must not appear.");
    }

    [TestMethod]
    public async Task ApplicationGetSelectList_UnknownTenant_ShouldReturnEmpty() {
        using var context = await GetIdentityContext();

        var list = await context.ApplicationGetSelectList(Guid.NewGuid(), CancellationToken.None);

        Assert.IsFalse(list.Any());
    }

    [TestMethod]
    public async Task ApplicationGetSelectList_LockedApp_ShouldIndicateLockedInDisplayName() {
        using var context = await GetIdentityContext();
        var app = await CreateAppAsync(context, TestContext.TenantGuid, $"Lock Me {Guid.NewGuid()}");

        // Lock the app directly
        var retrieved = await context.ApplicationFindRecord(app.Id, CancellationToken.None);
        Assert.IsNotNull(retrieved);
        retrieved.IsLocked = true;
        await context.Complete();

        var list = await context.ApplicationGetSelectList(TestContext.TenantGuid, CancellationToken.None);
        var item = list.FirstOrDefault(i => i.Key == app.Id);

        Assert.IsNotNull(item, "Locked app should still appear in the list.");
        Assert.IsTrue(item.Value?.RawData?.Contains("(Locked)", StringComparison.OrdinalIgnoreCase),
            "Display name should indicate the application is locked.");
    }

    // -------------------------------------------------------------------------
    // ApplicationDefinition queryable property
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
