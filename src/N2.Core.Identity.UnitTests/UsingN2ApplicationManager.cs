using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;

using N2.Core.Commands;
using N2.Core.Identity.Data;
using N2.Core.Identity.Services;

namespace N2.Core.Identity.UnitTests;

[TestClass]
public class UsingN2ApplicationManager {
    private readonly ServiceProvider serviceProvider;

    public UsingN2ApplicationManager() {
        ServiceCollection serviceCollection = new();
        TestContext.ConfigureServices(serviceCollection);
        serviceProvider = serviceCollection.BuildServiceProvider();
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private IApplicationManager BuildApplicationManager() {
        var config = serviceProvider.GetRequiredService<IConfiguration>();
        var factory = serviceProvider.GetRequiredService<IIdentityContextFactory>();
        return new N2ApplicationManager(factory, config, "IdentityDb", NullLogger<N2ApplicationManager>.Instance);
    }

    private static Application NewApp(Guid tenantId, string name = "My App") => new() {
        Id = Guid.NewGuid(),
        Name = name,
        ApplicationTenantId = tenantId,
        IsLocked = false
    };

    private async Task<Application> CreateAppAsync(string name, Guid? tenantId = null) {
        var manager = BuildApplicationManager();
        var app = NewApp(tenantId ?? TestContext.TenantGuid, name);
        var result = await manager.CreateAsync(app.ApplicationTenantId, app, CancellationToken.None);
        if (!result.Status.IsSuccess()) {
            throw new InvalidOperationException($"Failed to seed application: {result.Message}");
        }
        var found = await manager.FindByIdAsync(app.ApplicationTenantId, app.Id, CancellationToken.None);
        return found ?? throw new InvalidOperationException("Failed to retrieve created application.");
    }

    // -------------------------------------------------------------------------
    // CreateAsync
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task CreateAsync_NewApp_ShouldSucceed() {
        var manager = BuildApplicationManager();
        var app = NewApp(TestContext.TenantGuid, $"App {Guid.NewGuid()}");

        var result = await manager.CreateAsync(TestContext.TenantGuid, app, CancellationToken.None);

        Assert.IsTrue(result.Status.IsSuccess());
    }

    [TestMethod]
    public async Task CreateAsync_NormalizesName() {
        var manager = BuildApplicationManager();
        var name = $"  Norm App {Guid.NewGuid()}  ";
        var app = NewApp(TestContext.TenantGuid, name);

        var result = await manager.CreateAsync(TestContext.TenantGuid, app, CancellationToken.None);

        Assert.IsTrue(result.Status.IsSuccess());
        var found = await manager.FindByIdAsync(TestContext.TenantGuid, app.Id, CancellationToken.None);
        Assert.IsNotNull(found);
        Assert.AreEqual(name.Trim().ToUpperInvariant(), found!.NormalizedName);
    }

    [TestMethod]
    public async Task CreateAsync_DuplicateName_ShouldFail() {
        var app = await CreateAppAsync($"Dup App {Guid.NewGuid()}");
        var manager = BuildApplicationManager();

        var duplicate = NewApp(TestContext.TenantGuid, app.Name!);
        var result = await manager.CreateAsync(TestContext.TenantGuid, duplicate, CancellationToken.None);

        Assert.AreEqual(ResponseStatus.NotAcceptable, result.Status);
    }

    [TestMethod]
    public async Task CreateAsync_SameNameDifferentTenant_ShouldSucceed() {
        var sharedName = $"Shared App {Guid.NewGuid()}";
        var manager = BuildApplicationManager();

        var app1 = NewApp(TestContext.TenantGuid, sharedName);
        var app2 = NewApp(TestContext.LockedTenantGuid, sharedName);
        var result1 = await manager.CreateAsync(TestContext.TenantGuid, app1, CancellationToken.None);
        var result2 = await manager.CreateAsync(TestContext.LockedTenantGuid, app2, CancellationToken.None);

        Assert.IsTrue(result1.Status.IsSuccess());
        Assert.IsTrue(result2.Status.IsSuccess());
    }

    [TestMethod]
    public async Task CreateAsync_NonExistentTenant_ShouldFail() {
        var manager = BuildApplicationManager();
        var app = NewApp(Guid.NewGuid(), "Ghost App");

        var result = await manager.CreateAsync(app.ApplicationTenantId, app, CancellationToken.None);

        Assert.AreEqual(ResponseStatus.NotFound, result.Status);
    }

    [TestMethod]
    public async Task CreateAsync_EmptyTenantId_ShouldThrow() {
        var manager = BuildApplicationManager();

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
            () => manager.CreateAsync(Guid.Empty, NewApp(Guid.Empty), CancellationToken.None));
    }

    [TestMethod]
    public async Task CreateAsync_EmptyName_ShouldThrow() {
        var manager = BuildApplicationManager();
        var app = NewApp(TestContext.TenantGuid, "   ");

        await Assert.ThrowsAsync<ArgumentException>(
            () => manager.CreateAsync(TestContext.TenantGuid, app, CancellationToken.None));
    }

    // -------------------------------------------------------------------------
    // DeleteAsync
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task DeleteAsync_ExistingApp_ShouldSucceed() {
        var app = await CreateAppAsync($"To Delete {Guid.NewGuid()}");
        var manager = BuildApplicationManager();

        var result = await manager.DeleteAsync(TestContext.TenantGuid, app, CancellationToken.None);

        Assert.IsTrue(result.Status.IsSuccess());
        var found = await manager.FindByIdAsync(TestContext.TenantGuid, app.Id, CancellationToken.None);
        Assert.IsNull(found);
    }

    [TestMethod]
    public async Task DeleteAsync_NonExistentApp_ShouldFail() {
        var manager = BuildApplicationManager();
        var ghost = NewApp(TestContext.TenantGuid, "Ghost");

        var result = await manager.DeleteAsync(TestContext.TenantGuid, ghost, CancellationToken.None);

        Assert.AreEqual(ResponseStatus.NotFound, result.Status);
    }

    [TestMethod]
    public async Task DeleteAsync_WrongTenant_ShouldFail() {
        var app = await CreateAppAsync($"Wrong Tenant App {Guid.NewGuid()}");
        var manager = BuildApplicationManager();

        var result = await manager.DeleteAsync(TestContext.LockedTenantGuid, app, CancellationToken.None);

        Assert.AreEqual(ResponseStatus.NotFound, result.Status);
    }

    [TestMethod]
    public async Task DeleteAsync_EmptyAppId_ShouldThrow() {
        var manager = BuildApplicationManager();
        var bad = NewApp(TestContext.TenantGuid);
        bad.Id = Guid.Empty;

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
            () => manager.DeleteAsync(TestContext.TenantGuid, bad, CancellationToken.None));
    }

    [TestMethod]
    public async Task DeleteAsync_EmptyTenantId_ShouldThrow() {
        var manager = BuildApplicationManager();

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
            () => manager.DeleteAsync(Guid.Empty, NewApp(Guid.Empty), CancellationToken.None));
    }

    // -------------------------------------------------------------------------
    // UpdateAsync
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task UpdateAsync_ExistingApp_ShouldPersistChanges() {
        var app = await CreateAppAsync($"Before Update {Guid.NewGuid()}");
        var manager = BuildApplicationManager();

        app.Name = $"After Update {Guid.NewGuid()}";
        var result = await manager.UpdateAsync(TestContext.TenantGuid, app, CancellationToken.None);

        Assert.IsTrue(result.Status.IsSuccess());
        var found = await manager.FindByIdAsync(TestContext.TenantGuid, app.Id, CancellationToken.None);
        Assert.IsNotNull(found);
        Assert.AreEqual(app.Name, found!.Name);
        Assert.AreEqual(app.Name.ToUpperInvariant(), found.NormalizedName);
    }

    [TestMethod]
    public async Task UpdateAsync_NonExistentApp_ShouldFail() {
        var manager = BuildApplicationManager();

        var result = await manager.UpdateAsync(TestContext.TenantGuid, NewApp(TestContext.TenantGuid), CancellationToken.None);

        Assert.AreEqual(ResponseStatus.NotFound, result.Status);
    }

    [TestMethod]
    public async Task UpdateAsync_WrongTenant_ShouldFail() {
        var app = await CreateAppAsync($"Wrong Tenant Update {Guid.NewGuid()}");
        var manager = BuildApplicationManager();

        var result = await manager.UpdateAsync(TestContext.LockedTenantGuid, app, CancellationToken.None);

        Assert.AreEqual(ResponseStatus.NotFound, result.Status);
    }

    [TestMethod]
    public async Task UpdateAsync_EmptyName_ShouldThrow() {
        var app = await CreateAppAsync($"Has Name {Guid.NewGuid()}");
        var manager = BuildApplicationManager();
        app.Name = "   ";

        await Assert.ThrowsAsync<ArgumentException>(
            () => manager.UpdateAsync(TestContext.TenantGuid, app, CancellationToken.None));
    }

    // -------------------------------------------------------------------------
    // FindByIdAsync
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task FindByIdAsync_SeededApp_ShouldReturn() {
        var manager = BuildApplicationManager();

        var found = await manager.FindByIdAsync(TestContext.TenantGuid, TestContext.ApplicationGuid, CancellationToken.None);

        Assert.IsNotNull(found);
        Assert.AreEqual(TestContext.ApplicationGuid, found!.Id);
        Assert.AreEqual(TestContext.TenantGuid, found.ApplicationTenantId);
    }

    [TestMethod]
    public async Task FindByIdAsync_UnknownId_ShouldReturnNull() {
        var manager = BuildApplicationManager();

        var found = await manager.FindByIdAsync(TestContext.TenantGuid, Guid.NewGuid(), CancellationToken.None);

        Assert.IsNull(found);
    }

    [TestMethod]
    public async Task FindByIdAsync_WrongTenant_ShouldReturnNull() {
        var manager = BuildApplicationManager();

        // ApplicationGuid belongs to TenantGuid, not LockedTenantGuid
        var found = await manager.FindByIdAsync(TestContext.LockedTenantGuid, TestContext.ApplicationGuid, CancellationToken.None);

        Assert.IsNull(found);
    }

    [TestMethod]
    public async Task FindByIdAsync_EmptyAppId_ShouldThrow() {
        var manager = BuildApplicationManager();

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
            () => manager.FindByIdAsync(TestContext.TenantGuid, Guid.Empty, CancellationToken.None));
    }

    [TestMethod]
    public async Task FindByIdAsync_EmptyTenantId_ShouldThrow() {
        var manager = BuildApplicationManager();

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
            () => manager.FindByIdAsync(Guid.Empty, TestContext.ApplicationGuid, CancellationToken.None));
    }

    // -------------------------------------------------------------------------
    // FindByNameAsync
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task FindByNameAsync_SeededApp_ShouldReturn() {
        var manager = BuildApplicationManager();

        var found = await manager.FindByNameAsync(TestContext.TenantGuid, "Test App", CancellationToken.None);

        Assert.IsNotNull(found);
        Assert.AreEqual(TestContext.ApplicationGuid, found!.Id);
    }

    [TestMethod]
    public async Task FindByNameAsync_CaseInsensitive_ShouldReturn() {
        var manager = BuildApplicationManager();

        var found = await manager.FindByNameAsync(TestContext.TenantGuid, "test app", CancellationToken.None);

        Assert.IsNotNull(found);
        Assert.AreEqual(TestContext.ApplicationGuid, found!.Id);
    }

    [TestMethod]
    public async Task FindByNameAsync_UnknownName_ShouldReturnNull() {
        var manager = BuildApplicationManager();

        var found = await manager.FindByNameAsync(TestContext.TenantGuid, "Does Not Exist XYZ", CancellationToken.None);

        Assert.IsNull(found);
    }

    [TestMethod]
    public async Task FindByNameAsync_EmptyName_ShouldThrow() {
        var manager = BuildApplicationManager();

        await Assert.ThrowsAsync<ArgumentException>(
            () => manager.FindByNameAsync(TestContext.TenantGuid, "", CancellationToken.None));
    }

    [TestMethod]
    public async Task FindByNameAsync_EmptyTenantId_ShouldThrow() {
        var manager = BuildApplicationManager();

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
            () => manager.FindByNameAsync(Guid.Empty, "Test App", CancellationToken.None));
    }

    // -------------------------------------------------------------------------
    // GetApplicationsAsync
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task GetApplicationsAsync_SeededTenant_ShouldReturnSeededApp() {
        var manager = BuildApplicationManager();

        var list = await manager.GetApplicationsAsync(TestContext.TenantGuid, CancellationToken.None);

        Assert.IsNotNull(list);
        Assert.IsTrue(list.Any(i => i.Key == TestContext.ApplicationGuid));
    }

    [TestMethod]
    public async Task GetApplicationsAsync_OtherTenant_ShouldNotReturnAppsFromDifferentTenant() {
        var manager = BuildApplicationManager();

        var list = await manager.GetApplicationsAsync(TestContext.LockedTenantGuid, CancellationToken.None);

        Assert.IsFalse(list.Any(i => i.Key == TestContext.ApplicationGuid));
    }

    [TestMethod]
    public async Task GetApplicationsAsync_EmptyTenantId_ShouldThrow() {
        var manager = BuildApplicationManager();

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
            () => manager.GetApplicationsAsync(Guid.Empty, CancellationToken.None));
    }

    // -------------------------------------------------------------------------
    // LockAsync / UnlockAsync
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task LockAsync_ExistingApp_ShouldSetIsLockedTrue() {
        var app = await CreateAppAsync($"To Lock {Guid.NewGuid()}");
        var manager = BuildApplicationManager();

        var result = await manager.LockAsync(TestContext.TenantGuid, app, CancellationToken.None);

        Assert.IsTrue(result.Status.IsSuccess());
        var found = await manager.FindByIdAsync(TestContext.TenantGuid, app.Id, CancellationToken.None);
        Assert.IsTrue(found!.IsLocked);
    }

    [TestMethod]
    public async Task LockAsync_NonExistentApp_ShouldFail() {
        var manager = BuildApplicationManager();

        var result = await manager.LockAsync(TestContext.TenantGuid, NewApp(TestContext.TenantGuid), CancellationToken.None);

        Assert.AreEqual(ResponseStatus.NotFound, result.Status);
    }

    [TestMethod]
    public async Task LockAsync_WrongTenant_ShouldFail() {
        var app = await CreateAppAsync($"Lock Wrong Tenant {Guid.NewGuid()}");
        var manager = BuildApplicationManager();

        var result = await manager.LockAsync(TestContext.LockedTenantGuid, app, CancellationToken.None);

        Assert.AreEqual(ResponseStatus.NotFound, result.Status);
    }

    [TestMethod]
    public async Task UnlockAsync_LockedApp_ShouldSetIsLockedFalse() {
        var app = await CreateAppAsync($"To Unlock {Guid.NewGuid()}");
        var manager = BuildApplicationManager();
        await manager.LockAsync(TestContext.TenantGuid, app, CancellationToken.None);

        var result = await manager.UnlockAsync(TestContext.TenantGuid, app, CancellationToken.None);

        Assert.IsTrue(result.Status.IsSuccess());
        var found = await manager.FindByIdAsync(TestContext.TenantGuid, app.Id, CancellationToken.None);
        Assert.IsFalse(found!.IsLocked);
    }

    [TestMethod]
    public async Task UnlockAsync_NonExistentApp_ShouldFail() {
        var manager = BuildApplicationManager();

        var result = await manager.UnlockAsync(TestContext.TenantGuid, NewApp(TestContext.TenantGuid), CancellationToken.None);

        Assert.AreEqual(ResponseStatus.NotFound, result.Status);
    }

    [TestMethod]
    public async Task UnlockAsync_WrongTenant_ShouldFail() {
        var app = await CreateAppAsync($"Unlock Wrong Tenant {Guid.NewGuid()}");
        var manager = BuildApplicationManager();
        await manager.LockAsync(TestContext.TenantGuid, app, CancellationToken.None);

        var result = await manager.UnlockAsync(TestContext.LockedTenantGuid, app, CancellationToken.None);

        Assert.AreEqual(ResponseStatus.NotFound, result.Status);
    }
}
