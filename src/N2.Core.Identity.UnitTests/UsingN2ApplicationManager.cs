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

    private static ApplicationDefinition NewApp(Guid tenantId, string name = "My App") => new() {
        Id = Guid.NewGuid(),
        Name = name,
        ApplicationTenantId = tenantId,
        IsLocked = false
    };

    private async Task<ApplicationDefinition> CreateAppAsync(string name, Guid? tenantId = null) {
        var manager = BuildApplicationManager();
        var app = NewApp(tenantId ?? TestContext.TenantGuid, name);
        var result = await manager.CreateAsync(app.ApplicationTenantId, app, CancellationToken.None);
        if (!result.Status.IsSuccess()) {
            throw new InvalidOperationException($"Failed to seed application: {result.Message}");
        }
        var found = await manager.FindByIdAsync(app.ApplicationTenantId, app.Id, CancellationToken.None);
        return found ?? throw new InvalidOperationException("Failed to retrieve created application.");
    }

    /// <summary>
    /// Creates an application and injects <paramref name="keyMaterial"/> directly into its
    /// <c>SecretKeyMaterial</c> column via the identity context.
    /// </summary>
    private async Task<ApplicationDefinition> CreateAppWithKeyMaterialAsync(string name, byte[] keyMaterial) {
        var app = await CreateAppAsync(name);
        var factory = serviceProvider.GetRequiredService<IIdentityContextFactory>();
        using var ctx = await factory.CreateAsync("IdentityDb");
        var record = await ctx.ApplicationFindRecord(app.Id, CancellationToken.None);
        record!.SecretKeyMaterial = keyMaterial;
        await ctx.Complete();
        return app;
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
    // GetApplicationGetSelectList
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task GetApplicationGetSelectList_SeededTenant_ShouldReturnSeededApp() {
        var manager = BuildApplicationManager();

        var list = await manager.GetApplicationGetSelectList(TestContext.TenantGuid, CancellationToken.None);

        Assert.IsNotNull(list);
        Assert.IsTrue(list.Any(i => i.Key == TestContext.ApplicationGuid));
    }

    [TestMethod]
    public async Task GetApplicationGetSelectList_OtherTenant_ShouldNotReturnAppsFromDifferentTenant() {
        var manager = BuildApplicationManager();

        var list = await manager.GetApplicationGetSelectList(TestContext.LockedTenantGuid, CancellationToken.None);

        Assert.IsFalse(list.Any(i => i.Key == TestContext.ApplicationGuid));
    }

    [TestMethod]
    public async Task GetApplicationGetSelectList_EmptyTenantId_ShouldThrow() {
        var manager = BuildApplicationManager();

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
            () => manager.GetApplicationGetSelectList(Guid.Empty, CancellationToken.None));
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

    // -------------------------------------------------------------------------
    // GetSecretOwner
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task GetSecretOwner_UnknownId_ShouldReturnNull() {
        var manager = BuildApplicationManager();

        var owner = await manager.GetSecretOwner(Guid.NewGuid(), CancellationToken.None);

        Assert.IsNull(owner);
    }

    [TestMethod]
    public async Task GetSecretOwner_AppWithoutKeyMaterial_ShouldThrow() {
        // The seeded application has no SecretKeyMaterial set.
        var manager = BuildApplicationManager();

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => manager.GetSecretOwner(TestContext.ApplicationGuid, CancellationToken.None));
    }

    [TestMethod]
    public async Task GetSecretOwner_AppWithKeyMaterial_ShouldReturnOwner() {
        var keyMaterial = RandomNumberGenerator.GetBytes(32);
        var app = await CreateAppWithKeyMaterialAsync($"SecretApp {Guid.NewGuid()}", keyMaterial);
        var manager = BuildApplicationManager();

        var owner = await manager.GetSecretOwner(app.Id, CancellationToken.None);

        Assert.IsNotNull(owner);
        Assert.AreEqual(app.Id, owner!.Id);
        Assert.AreEqual(OwnerTypeCode.Application, owner.Type);
        Assert.IsTrue(owner.OwnerSecret.ArraysAreEqual(keyMaterial));
    }

    [TestMethod]
    public async Task GetSecretOwner_AppWithKeyMaterial_TypeShouldBeApplication() {
        var app = await CreateAppWithKeyMaterialAsync($"TypeCheck {Guid.NewGuid()}", RandomNumberGenerator.GetBytes(32));
        var manager = BuildApplicationManager();

        var owner = await manager.GetSecretOwner(app.Id, CancellationToken.None);

        Assert.AreEqual(OwnerTypeCode.Application, owner!.Type);
    }
}