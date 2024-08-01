using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using N2.Core.Identity;
using N2.Core.Extensions;
using N2.Identity.Data;
using N2.Identity.Services;
using N2.Core.Entity;
using N2.Core;

namespace N2.Identity.UnitTests;

[TestClass]
public class N2AuthenticatorTests
{
    private readonly ServiceProvider serviceProvider;
    private readonly IConnectionStringService connectionStringService = new EntityConnectionService();
    private readonly SettingsService settingsService = new SettingsService();

    public N2AuthenticatorTests()
    {
        var serviceCollection = new ServiceCollection();
        ConfigureServices(serviceCollection);
        serviceProvider = serviceCollection.BuildServiceProvider();
    }

    [TestMethod]
    public void TestGetAuthenticator()
    {
        var authenticator = serviceProvider.GetRequiredService<IAuthenticator>();
        Assert.IsNotNull(authenticator);
    }

    [TestMethod]
    public async Task TestUserLoginFailureAsync()
    {
        var authenticator = serviceProvider.GetRequiredService<IAuthenticator>();
        var user = await authenticator.AuthenticateAsync(new UserLogin { Password = "admin", Username = "admin" });
        Assert.IsNull(user);
    }

    [TestMethod]
    public async Task TestUserLoginSuccessAsync()
    {
        var userInfo = settingsService.GetConfigSettings<UserLogin>("AdminUser");
        var authenticator = serviceProvider.GetRequiredService<IAuthenticator>();
        var user = await authenticator.AuthenticateAsync(userInfo);
        if (user == null)
        {
            Assert.Fail("User not found");
        }
        else
        {
            Assert.AreEqual(userInfo.Username, user.UserName);
            Console.WriteLine(user.SerializeForView());
        }
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
        serviceCollection.AddScoped<IAuthenticator, N2AuthenticationService>();
    }
}