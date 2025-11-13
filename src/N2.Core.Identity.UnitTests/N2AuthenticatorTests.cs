using Microsoft.Extensions.DependencyInjection;

using N2.Core.Commands;
using N2.Core.Identity.Data;

using System.Security.Cryptography;

namespace N2.Core.Identity.UnitTests;

[TestClass]
public class N2AuthenticatorTests {
    private readonly ServiceProvider serviceProvider;

    public N2AuthenticatorTests() {
        ServiceCollection serviceCollection = new();
        TestContext.ConfigureServices(serviceCollection);
        serviceProvider = serviceCollection.BuildServiceProvider();
    }

    [TestMethod]
    public void TestGetAuthenticator() {
        var authenticator = serviceProvider.GetRequiredService<IAuthenticator>();
        Assert.IsNotNull(authenticator);
    }

    [TestMethod]
    public async Task TestUserLoginFailureAsync() {
        var userName = $"testuser_{Guid.NewGuid():N}";
        await CreateTestUser(userName, "secret", MultiFactorType.None);
        var authenticator = serviceProvider.GetRequiredService<IAuthenticator>();
        var user = await authenticator.AuthenticateAsync(new UserLogin { Password = "admin", Username = userName });
        Assert.IsNull(user);
    }

    [TestMethod]
    public async Task TestUserLoginSuccessAsync() {
        var username = $"testuser_{Guid.NewGuid():N}"; // Unique username
        await CreateTestUser(username, "secret", MultiFactorType.None);
        UserLogin userInfo = new() { Password = "secret", Username = username };

        var authenticator = serviceProvider.GetRequiredService<IAuthenticator>();
        var user = await authenticator.AuthenticateAsync(userInfo);

        Assert.IsNotNull(user, "User should be authenticated");
        Assert.AreNotEqual(Guid.Empty, user.PublicId);
        Assert.AreEqual(username, user.Name);
    }

    [TestMethod]
    public async Task Authentication_ValidVsInvalidUser_ShouldHaveConstantTiming() {
        // Arrange
        await CreateTestUser("validuser", "P@ssword123", MultiFactorType.None);
        var iterations = 100;
        var validUserTimes = new List<long>();
        var invalidUserTimes = new List<long>();
        var authService = serviceProvider.GetRequiredService<IAuthenticator>();

        // Act
        for (var i = 0; i < iterations; i++) {
            var sw = System.Diagnostics.Stopwatch.StartNew();
            await authService.AuthenticateAsync(new UserLogin {
                Username = "validuser",
                Password = "WrongPassword"
            });
            validUserTimes.Add(sw.ElapsedMilliseconds);

            sw.Restart();
            await authService.AuthenticateAsync(new UserLogin {
                Username = "nonexistentuser" + i,
                Password = "WrongPassword"
            });
            invalidUserTimes.Add(sw.ElapsedMilliseconds);
        }

        // Assert
        var avgValid = validUserTimes.Average();
        var avgInvalid = invalidUserTimes.Average();
        var percentDiff = Math.Abs(avgValid - avgInvalid) / avgValid * 100;

        Assert.IsLessThan(20,
percentDiff, $"Timing difference should be < 20% to prevent user enumeration, was {percentDiff:F2}%");
    }

    [TestMethod]
    public async Task ArraysAreEqual_DifferentPositions_ShouldHaveConstantTiming() {
        // Arrange
        var baseArray = new byte[32];
        RandomNumberGenerator.Fill(baseArray);
        var iterations = 1000;

        // Act - Test mismatch at different positions
        var firstByteTimes = new List<long>();
        var lastByteTimes = new List<long>();

        for (var i = 0; i < iterations; i++) {
            var testFirst = (byte[])baseArray.Clone();
            testFirst[0] ^= 0xFF; // Flip first byte

            var sw = System.Diagnostics.Stopwatch.StartNew();
            await baseArray.ArraysAreEqual(testFirst);
            firstByteTimes.Add(sw.ElapsedTicks);

            var testLast = (byte[])baseArray.Clone();
            testLast[31] ^= 0xFF; // Flip last byte

            sw.Restart();
            await baseArray.ArraysAreEqual(testLast);
            lastByteTimes.Add(sw.ElapsedTicks);
        }

        // Assert
        var avgFirst = firstByteTimes.Average();
        var avgLast = lastByteTimes.Average();
        var percentDiff = Math.Abs(avgFirst - avgLast) / avgFirst * 100;

        Assert.IsLessThan(5, percentDiff, $"Timing for first vs last byte mismatch should be < 5% different, was {percentDiff:F2}%");
    }

    [TestMethod]
    public async Task MFAValidation_ConstantTimingForInvalidTokens() {
        // Arrange
        var username = $"testuser_{Guid.NewGuid():N}"; // Unique username
        await CreateTestUser(username, "P@ssword123", MultiFactorType.Email);

        var userManager = serviceProvider.GetRequiredService<IUserManager<ApplicationUser>>();
        var userResponse = await userManager.FindByNameAsync(username, CancellationToken.None);
        var user = userResponse.Value!;

        var validTokenResponse = await userManager.GenerateConfirmationTokenAsync(user, CancellationToken.None);
        var validToken = validTokenResponse.Value ?? "";

        var completelyWrongToken = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
        var partiallyWrongToken = string.Concat(validToken.AsSpan(0, validToken.Length - 5), "XXXXX");

        var iterations = 300;
        var wrongTimes = new List<long>();
        var partialTimes = new List<long>();

        // Act
        for (var i = 0; i < iterations; i++) {
            var sw = System.Diagnostics.Stopwatch.StartNew();
            await userManager.ValidateMultifactorAsync(user, completelyWrongToken, CancellationToken.None);
            wrongTimes.Add(sw.ElapsedTicks);

            sw.Restart();
            await userManager.ValidateMultifactorAsync(user, partiallyWrongToken, CancellationToken.None);
            partialTimes.Add(sw.ElapsedTicks);
        }

        // Assert
        var avgWrong = wrongTimes.Average();
        var avgPartial = partialTimes.Average();
        var percentDiff = Math.Abs(avgWrong - avgPartial) / avgWrong * 100;

        Assert.IsLessThan(10, percentDiff, $"MFA validation timing should not leak information, difference was {percentDiff:F2}%");
    }

    [TestMethod]
    public async Task ErrorMessages_ShouldNotRevealUserExistence() {
        // Arrange
        await CreateTestUser("existinguser", "P@ssword123", MultiFactorType.None);
        var authService = serviceProvider.GetRequiredService<IAuthenticator>();

        // Act
        var invalidUserResult = await authService.AuthenticateAsync(new UserLogin {
            Username = "nonexistentuser",
            Password = "WrongPassword"
        });

        var invalidPasswordResult = await authService.AuthenticateAsync(new UserLogin {
            Username = "existinguser",
            Password = "WrongPassword"
        });

        // Assert - Error messages should be identical
        Assert.IsNull(invalidUserResult, "Invalid user should return null");
        Assert.IsNull(invalidPasswordResult, "Invalid password should return null");

        // Verify logs don't distinguish between scenarios in external messages
    }

    private async Task<ApplicationUser> CreateTestUser(string userName, string password, MultiFactorType mfaType) {
        CancellationToken token = new();

        var userManager = serviceProvider.GetRequiredService<IUserManager<ApplicationUser>>();

        // Create user
        ApplicationUser user = new() {
            UserName = userName,
            Email = $"{userName}@test.com",
            MfaType = mfaType
        };

        var createResult = await userManager.CreateAsync(user, password, token);
        if (!createResult.Status.IsSuccess()) {
            throw new InvalidOperationException($"Failed to create user: {createResult.Message}");
        }

        // Retrieve the created user
        var userResponse = await userManager.FindByNameAsync(userName, token);
        if (userResponse.Value == null) {
            throw new InvalidOperationException("Failed to retrieve created user.");
        }

        var createdUser = userResponse.Value;

        if (mfaType != MultiFactorType.None) {
            // Generate and confirm email to allow sign-in
            await userManager.SetMultifactorAsync(createdUser, mfaType, "token", CancellationToken.None);

            var tokenResponse = await userManager.GenerateConfirmationTokenAsync(createdUser, token);
            if (!tokenResponse.Status.IsSuccess() || string.IsNullOrEmpty(tokenResponse.Value)) {
                throw new InvalidOperationException("Failed to generate confirmation token.");
            }

            var confirmResult = await userManager.ConfirmEmailAsync(createdUser, tokenResponse.Value, token);
            if (!confirmResult.Status.IsSuccess()) {
                throw new InvalidOperationException($"Failed to confirm email: {confirmResult.Message}");
            }

            // Retrieve user again to get updated EmailConfirmed status
            userResponse = await userManager.FindByNameAsync(userName, token);
            if (userResponse.Value == null) {
                throw new InvalidOperationException("Failed to retrieve user after email confirmation.");
            }
        }

        return userResponse.Value;
    }
}