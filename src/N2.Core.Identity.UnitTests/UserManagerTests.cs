using Microsoft.Extensions.DependencyInjection;

using N2.Core.Commands;
using N2.Core.Identity.Data;

namespace N2.Core.Identity.UnitTests;

[TestClass]
public class N2UserManagerTests
{
    private readonly ServiceProvider serviceProvider;

    public N2UserManagerTests()
    {
        ServiceCollection serviceCollection = new();
        TestContext.ConfigureServices(serviceCollection);
        serviceProvider = serviceCollection.BuildServiceProvider();
    }

    [TestMethod]
    public void TestGetAuthenticator()
    {
        IUserManager<ApplicationUser> userManager = serviceProvider.GetRequiredService<IUserManager<ApplicationUser>>();
        IDisposable disposable = userManager;
        Assert.IsNotNull(userManager);
        Assert.IsNotNull(disposable);
        disposable.Dispose();
    }

    [TestMethod]
    public async Task TestValidateEmailConfirmationAsync()
    {
        ICommandResponse? result = null;
        CancellationToken token = new();
        UserLogin userInfo = new() { Password = "secret", Username = "admin" };
        using IUserManager<ApplicationUser> userManager = serviceProvider.GetRequiredService<IUserManager<ApplicationUser>>();
        ICommandResponse<ApplicationUser> userResponse = await userManager.FindByNameAsync(userInfo.Username, token);
        ApplicationUser? user = userResponse.Value;

        if (user != null)
        {
            ICommandResponse<string> tokenResponse = await userManager.GenerateEmailConfirmationTokenAsync(user, token);
            Assert.IsNotNull(tokenResponse);
            string? tokenResult = tokenResponse.Value;
            if (!string.IsNullOrEmpty(tokenResult))
            {
                result = await userManager.ConfirmEmailAsync(user, tokenResult, token);
            }
        }
        Assert.IsNotNull(result);
        Assert.IsTrue(result.Status.IsSuccess());
    }

    [TestMethod]
    public async Task TestFindByEmailAsync()
    {
        CancellationToken token = new();
        UserLogin userInfo = new() { Password = "secret", Username = "admin@email.com" };
        IUserManager<ApplicationUser> userManager = serviceProvider.GetRequiredService<IUserManager<ApplicationUser>>();
        ICommandResponse<ApplicationUser> user = await userManager.FindByEmailAsync(userInfo.Username, token);
        Assert.IsNotNull(user);
    }

    [TestMethod]
    public async Task TestRoleValidationAsync()
    {
        CancellationToken token = new();
        UserLogin userInfo = new() { Password = "secret", Username = "admin@email.com" };
        IUserManager<ApplicationUser> userManager = serviceProvider.GetRequiredService<IUserManager<ApplicationUser>>();
        ICommandResponse<ApplicationUser> userResponse = await userManager.FindByEmailAsync(userInfo.Username, token);
        ApplicationUser? user = userResponse.Value;
        if (user != null)
        {
            ICommandResponse isAdminResponse = await userManager.IsInRoleAsync(user, SystemRoles.SysAdmin, token);
            Assert.AreEqual(ResponseStatus.Success, isAdminResponse.Status);
        }
    }

    [TestMethod]
    public async Task TestAddRoleToUserAsyncAsync()
    {
        ICommandResponse? result = null;
        CancellationToken token = new();
        UserLogin userInfo = new() { Password = "secret", Username = "admin@email.com" };
        IUserManager<ApplicationUser> userManager = serviceProvider.GetRequiredService<IUserManager<ApplicationUser>>();
        ICommandResponse<ApplicationUser> userMessage = await userManager.FindByEmailAsync(userInfo.Username, token);
        ApplicationUser? user = userMessage.Value;
        if (user != null)
        {
            ICommandResponse isAdminResponse = await userManager.IsInRoleAsync(user, SystemRoles.Publisher, token);
            bool isAdmin = isAdminResponse.Status == ResponseStatus.Success;
            if (isAdmin)
            {
                _ = await userManager.RemoveFromRoleAsync(user, SystemRoles.Publisher, token);
            }

            result = await userManager.AddToRoleAsync(user, SystemRoles.Publisher, token);
        }
        Assert.IsNotNull(result);
        Assert.IsTrue(result.Status.IsSuccess());
    }

    [TestMethod]
    public async Task TestRoleExistsAsync()
    {
        CancellationToken token = new();
        string role = SystemRoles.SysAdmin;
        IUserManager<ApplicationUser> userManager = serviceProvider.GetRequiredService<IUserManager<ApplicationUser>>();
        bool roleExists = await userManager.RoleExistsAsync(role, token);
        Assert.IsTrue(roleExists);
    }

    [TestMethod]
    public async Task TestRoleCreateAndRemoveAsync()
    {
        CancellationToken token = new();
        string role = "TestRole";
        IUserManager<ApplicationUser> userManager = serviceProvider.GetRequiredService<IUserManager<ApplicationUser>>();
        bool roleExists = await userManager.RoleExistsAsync(role, token);
        if (roleExists)
        {
            await userManager.RemoveRoleAsync(role, token);
        }
        ICommandResponse roleResult = await userManager.CreateRoleAsync(role, token);
        Assert.IsNotNull(roleResult);
        Assert.IsTrue(roleResult.Status.IsSuccess());
    }

    [TestMethod]
    public async Task TestGenerateEmailConfirmationTokenAsync()
    {
        ICommandResponse<string>? tokenResult = null;
        CancellationToken token = new();
        UserLogin userInfo = new() { Password = "secret", Username = "admin" };
        using IUserManager<ApplicationUser> userManager = serviceProvider.GetRequiredService<IUserManager<ApplicationUser>>();
        ICommandResponse<ApplicationUser> userResponse = await userManager.FindByNameAsync(userInfo.Username, token);
        ApplicationUser? user = userResponse.Value;
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
        CancellationToken token = new();
        UserLogin userInfo = new()
        {
            Username = "justin@time.nl",
            Password = "TestPassword1!"
        };
        using IUserManager<ApplicationUser> userManager = serviceProvider.GetRequiredService<IUserManager<ApplicationUser>>();
        ICommandResponse<ApplicationUser> userResponse = await userManager.FindByNameAsync(userInfo.Username, token);
        ApplicationUser? user = userResponse.Value;
        if (user != null)
        {
            await userManager.DeleteAsync(user, token);
        }
        user = new ApplicationUser();
        ICommandResponse setUserNameResult = await userManager.SetUserNameAsync(user, userInfo.Username, token);
        ICommandResponse setEmailNameResult = await userManager.SetEmailAsync(user, userInfo.Username, token);
        ICommandResponse createUserResult = await userManager.CreateAsync(user, userInfo.Password, token);

        Assert.IsNotNull(setUserNameResult);
        Assert.IsNotNull(setEmailNameResult);
        Assert.IsNotNull(createUserResult);

        Assert.IsTrue(setUserNameResult.Status.IsSuccess());
        Assert.IsTrue(setEmailNameResult.Status.IsSuccess());
        Assert.IsTrue(createUserResult.Status.IsSuccess());
    }
}