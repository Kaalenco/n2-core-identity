namespace N2.Core.Identity.UnitTests;

[TestClass]
public class UsingN2Authenticator : N2IdentityTestsBase {

    [TestMethod]
    public void TestGetAuthenticator() {
        var authenticator = GetAuthenticator();
        Assert.IsNotNull(authenticator);
    }

    [TestMethod]
    public async Task TestUserLoginFailureAsync() {
        var userName = $"testuser_{Guid.NewGuid():N}";
        await CreateTestUser(userName, "secret", MultiFactorType.None);
        var authenticator = GetAuthenticator();
        var user = await authenticator.AuthenticateAsync(new UserLogin { Password = "admin", Username = userName });
        Assert.IsNull(user);
    }

    [TestMethod]
    public async Task TestUserLoginSuccessAsync() {
        var username = $"testuser_{Guid.NewGuid():N}";
        await CreateTestUser(username, "secret", MultiFactorType.None);
        UserLogin userInfo = new() { Password = "secret", Username = username };

        var authenticator = GetAuthenticator();
        var user = await authenticator.AuthenticateAsync(userInfo);

        Assert.IsNotNull(user, "User should be authenticated");
        Assert.AreNotEqual(Guid.Empty, user.PublicId);
        Assert.AreEqual(username, user.Name);
    }

    [TestMethod]
    public async Task ErrorMessages_ShouldNotRevealUserExistence() {
        await CreateTestUser("existinguser", "P@ssword123", MultiFactorType.None);
        var authService = GetAuthenticator();

        var invalidUserResult = await authService.AuthenticateAsync(new UserLogin {
            Username = "nonexistentuser",
            Password = "WrongPassword"
        });

        var invalidPasswordResult = await authService.AuthenticateAsync(new UserLogin {
            Username = "existinguser",
            Password = "WrongPassword"
        });

        Assert.IsNull(invalidUserResult, "Invalid user should return null");
        Assert.IsNull(invalidPasswordResult, "Invalid password should return null");
    }
}
