namespace N2.Core.Identity.UnitTests;
[TestClass]
public class AccountLockoutTests : N2AuthenticatorUnitTestsBase {

    [TestMethod]
    public async Task Authentication_FiveFailedAttempts_ShouldLockAccount() {
        // Arrange
        var userName = $"TestUser-{Guid.NewGuid}";
        var user = await CreateTestUser(userName, "CorrectP@ssw0rd", MultiFactorType.None);
        var wrongPassword = "WrongPassword123";
        var authService = GetAuthenticator();
        var userManager = GetUserManager();

        // Act - Attempt 5 failed logins
        for (var i = 0; i < 5; i++) {
            var result = await authService.AuthenticateAsync(new UserLogin {
                Username = userName,
                Password = wrongPassword
            });
            Assert.IsNull(result, $"Attempt {i + 1} should fail");
        }

        // Assert - 6th attempt should be blocked due to lockout
        var lockedResult = await authService.AuthenticateAsync(new UserLogin {
            Username = "testuser",
            Password = "CorrectP@ssw0rd" // Even correct password should be blocked
        });
        Assert.IsNull(lockedResult, "Account should be locked");

        // Verify lockout state
        var dbUser = await userManager.FindByNameAsync(userName, CancellationToken.None);
        Assert.IsNotNull(dbUser.Value);
        Assert.IsTrue(dbUser.Value.LockoutEnabled);
        Assert.IsNotNull(dbUser.Value.LockoutEnd);
        Assert.IsTrue(dbUser.Value.LockoutEnd > DateTimeOffset.UtcNow);
    }

    [TestMethod]
    public async Task Authentication_SuccessfulLogin_ShouldResetFailedCount() {
        // Arrange
        var userName = $"TestUser-{Guid.NewGuid}";
        var user = await CreateTestUser(userName, "CorrectP@ssw0rd", MultiFactorType.None);
        var authService = GetAuthenticator();
        var userManager = GetUserManager();

        // Act - 3 failed attempts
        for (var i = 0; i < 3; i++) {
            await authService.AuthenticateAsync(new UserLogin {
                Username = userName,
                Password = "WrongPassword"
            });
        }

        // Successful login
        var result = await authService.AuthenticateAsync(new UserLogin {
            Username = userName,
            Password = "CorrectP@ssw0rd"
        });

        // Assert
        Assert.IsNotNull(result);
        var dbUser = await userManager.FindByNameAsync(userName, CancellationToken.None);
        Assert.IsNotNull(dbUser.Value);
        Assert.AreEqual(0, dbUser.Value.AccessFailedCount);
    }

    [TestMethod]
    public async Task Authentication_LockedAccount_ShouldRejectCorrectPassword() {
        // Arrange
        var userName = $"TestUser-{Guid.NewGuid}";
        var user = await CreateTestUser(userName, "CorrectP@ssw0rd", MultiFactorType.None);
        var authService = GetAuthenticator();

        // Lock the account
        for (var i = 0; i < 5; i++) {
            await authService.AuthenticateAsync(new UserLogin {
                Username = userName,
                Password = "WrongPassword"
            });
        }

        // Act - Try with correct password
        var result = await authService.AuthenticateAsync(new UserLogin {
            Username = userName,
            Password = "CorrectP@ssw0rd"
        });

        // Assert
        Assert.IsNull(result, "Locked account should reject even correct password");
    }

    [TestMethod]
    public async Task Authentication_LockoutExpired_ShouldAllowLogin() {
        // Arrange
        var userName = $"TestUser-{Guid.NewGuid}";
        var user = await CreateTestUser(userName, "CorrectP@ssw0rd", MultiFactorType.None);
        var authService = GetAuthenticator();
        var userManager = GetUserManager();
        using var identityContext = await GetIdentityContext();

        // Lock the account
        for (var i = 0; i < 5; i++) {
            await authService.AuthenticateAsync(new UserLogin {
                Username = userName,
                Password = "WrongPassword"
            });
        }

        // Simulate lockout expiration (in real test, might need to adjust lockout time)
        var dbUser = await identityContext.ApplicationUserAsync(userName.ToUpperInvariant(), CancellationToken.None);
        Assert.IsNotNull(dbUser);
        dbUser.LockoutEnd = DateTimeOffset.UtcNow.AddSeconds(-1);
        await identityContext.Complete();

        // Act - Try with correct password after lockout expired
        var result = await authService.AuthenticateAsync(new UserLogin {
            Username = userName,
            Password = "CorrectP@ssw0rd"
        });

        // Assert
        Assert.IsNotNull(result, "Should allow login after lockout expires");
    }
}
