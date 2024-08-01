using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using N2.Core;
using N2.Core.Entity;
using N2.Core.Identity;
using N2.Identity.Data;
using N2.Identity.Services;

namespace N2.Identity.UnitTests;

[TestClass]
public class N2UserManagerTests
{
    private readonly ServiceProvider serviceProvider;
    private readonly IConnectionStringService connectionStringService = new EntityConnectionService();
    private readonly SettingsService settingsService = new SettingsService();

    public N2UserManagerTests()
    {
        var serviceCollection = new ServiceCollection();
        ConfigureServices(serviceCollection);
        serviceProvider = serviceCollection.BuildServiceProvider();
    }

    [TestMethod]
    public void TestGetAuthenticator()
    {
        var userManager = serviceProvider.GetRequiredService<IUserManager<ApplicationUser>>();
        var disposable = userManager as IDisposable;
        Assert.IsNotNull(userManager);
        Assert.IsNotNull(disposable);
        disposable.Dispose();
    }

    [TestMethod]
    public async Task TestValidateEmailConfirmationAsync()
    {
        string? tokenResult;
        IRequestResult? result=null;
        var token = new CancellationToken();
        var userInfo = settingsService.GetConfigSettings<UserLogin>("AdminUser");
        using var userManager = serviceProvider.GetRequiredService<IUserManager<ApplicationUser>>();
        var user = await userManager.FindByNameAsync(userInfo.Username, token);

        if (user != null)
        {
            tokenResult = await userManager.GenerateEmailConfirmationTokenAsync(user, token);
            if (!string.IsNullOrEmpty(tokenResult))
            {
                result = await userManager.ConfirmEmailAsync(user, tokenResult, token);
            }
        }
        Assert.IsNotNull(result);
        Assert.IsTrue(result.IsSuccessCode);
    }

    [TestMethod]
    public async Task TestFindByEmailAsync()
    {
        var token = new CancellationToken();
        var userInfo = settingsService.GetConfigSettings<UserLogin>("AdminUser");
        var userManager = serviceProvider.GetRequiredService<IUserManager<ApplicationUser>>();
        var user = await userManager.FindByEmailAsync(userInfo.Username, token);
        Assert.IsNotNull(user);
    }

    [TestMethod]
    public async Task TestRoleValidationAsync()
    {
        var isAdmin = false;
        var token = new CancellationToken();
        var userInfo = settingsService.GetConfigSettings<UserLogin>("AdminUser");
        var userManager = serviceProvider.GetRequiredService<IUserManager<ApplicationUser>>();
        var user = await userManager.FindByEmailAsync(userInfo.Username, token);
        if (user != null)
        {
            isAdmin = await userManager.IsInRoleAsync(user, SystemRoles.SysAdmin, token);
        }
        Assert.IsTrue(isAdmin);
    }

    [TestMethod]
    public async Task TestAddRoleToUserAsyncAsync()
    {
        IRequestResult? result=null;
        var token = new CancellationToken();
        var userInfo = settingsService.GetConfigSettings<UserLogin>("AdminUser");
        var userManager = serviceProvider.GetRequiredService<IUserManager<ApplicationUser>>();
        var user = await userManager.FindByEmailAsync(userInfo.Username, token);
        if (user != null)
        {
            var isAdmin = await userManager.IsInRoleAsync(user, SystemRoles.Publisher, token);
            if (isAdmin)
            {
                _ = await userManager.RemoveFromRoleAsync(user, SystemRoles.Publisher, token);
            }

            result = await userManager.AddToRoleAsync(user, SystemRoles.Publisher, token);
        }
        Assert.IsNotNull(result);
        Assert.IsTrue(result.IsSuccessCode);
    }

    [TestMethod]
    public async Task TestRoleExistsAsync() 
    {        
           var token = new CancellationToken();
           var role = SystemRoles.SysAdmin;
           var userManager = serviceProvider.GetRequiredService<IUserManager<ApplicationUser>>();
           var roleExists = await userManager.RoleExistsAsync(role, token);
           Assert.IsTrue(roleExists);
    }

    [TestMethod]
    public async Task TestRoleCreateAndRemoveAsync()
    {
        var token = new CancellationToken();
        var role = "TestRole";
        var userManager = serviceProvider.GetRequiredService<IUserManager<ApplicationUser>>();
        var roleExists = await userManager.RoleExistsAsync(role, token);
        if (roleExists)
        {
            await userManager.RemoveRoleAsync(role, token);
        }
        var roleResult = await userManager.CreateRoleAsync(role, token);
        Assert.IsNotNull(roleResult);
        Assert.IsTrue(roleResult.IsSuccessCode);
    }

    [TestMethod]
    public async Task TestGenerateEmailConfirmationTokenAsync()
    {
        string? tokenResult = null;
        var token = new CancellationToken();
        var userInfo = settingsService.GetConfigSettings<UserLogin>("AdminUser");
        using var userManager = serviceProvider.GetRequiredService<IUserManager<ApplicationUser>>();
        var user = await userManager.FindByNameAsync(userInfo.Username, token);
        if (user != null)
        {
            tokenResult = await userManager.GenerateEmailConfirmationTokenAsync(user, token);
        }
        Assert.IsNotNull(tokenResult);
        Console.WriteLine(tokenResult);
    }

    [TestMethod]
    public async Task TestUserCreateAsync()
    {
        var token = new CancellationToken();
        var userInfo = new UserLogin
        {
            Username = "justin@time.nl",
            Password = "TestPassword1!"
        };
        using var userManager = serviceProvider.GetRequiredService<IUserManager<ApplicationUser>>();
        var user = await userManager.FindByNameAsync(userInfo.Username, token);
        if (user != null)
        {
            await userManager.DeleteAsync(user, token);
        }
        user = new ApplicationUser();
        var setUserNameResult = await userManager.SetUserNameAsync(user, userInfo.Username, token);
        var setEmailNameResult = await userManager.SetEmailAsync(user, userInfo.Username, token);
        var createUserResult = await userManager.CreateAsync(user, userInfo.Password, token);

        Assert.IsNotNull(setUserNameResult);
        Assert.IsNotNull(setEmailNameResult);
        Assert.IsNotNull(createUserResult);

        Assert.IsTrue(setUserNameResult.IsSuccessCode);
        Assert.IsTrue(setEmailNameResult.IsSuccessCode);
        Assert.IsTrue(createUserResult.IsSuccessCode);
    }

    private void ConfigureServices(ServiceCollection serviceCollection)
    {
        serviceCollection.AddLogging(configure =>
        {
            configure.SetMinimumLevel(LogLevel.Debug);
            configure.AddConsole();
        });

        serviceCollection.AddSingleton(settingsService);
        serviceCollection.AddSingleton(connectionStringService);      

        serviceCollection.AddScoped<IUserManager<ApplicationUser>>(
            s => new N2UserManager(s.GetRequiredService<IIdentityContextFactory>(), "UserDbConnection"));
        serviceCollection.AddScoped<IIdentityContextFactory, N2IdentityContextFactory>();
    }
}