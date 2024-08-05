using Microsoft.Extensions.DependencyInjection;
using N2.Core.Identity;

namespace N2.Core.Identity.UnitTests;

[TestClass]
public class N2AuthenticatorTests
{
    private readonly ServiceProvider serviceProvider;

    public N2AuthenticatorTests()
    {
        var serviceCollection = new ServiceCollection();
        TestContext.ConfigureServices(serviceCollection);
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
        var userInfo = new UserLogin { Password = "secret", Username = "admin" };
        var authenticator = serviceProvider.GetRequiredService<IAuthenticator>();
        var user = await authenticator.AuthenticateAsync(userInfo);
        if (user == null)
        {
            Assert.Fail("User not found");
        }
        else
        {
            Assert.AreEqual(userInfo.Username, user.UserName);
        }
    }
}