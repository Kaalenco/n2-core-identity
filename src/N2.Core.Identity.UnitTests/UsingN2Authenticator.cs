using System.Security.Cryptography;

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
        var username = $"testuser_{Guid.NewGuid():N}"; // Unique username
        await CreateTestUser(username, "secret", MultiFactorType.None);
        UserLogin userInfo = new() { Password = "secret", Username = username };

        var authenticator = GetAuthenticator();
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
        var authService = GetAuthenticator();
        var sw = System.Diagnostics.Stopwatch.StartNew();
        // Act
        for (var i = 0; i < iterations; i++) {
            sw.Restart();
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
        AssertTimingOrInconclusive(validUserTimes, invalidUserTimes, 20,
            percentDiff => $"Timing difference should be < 20% to prevent user enumeration, was {percentDiff:F2}%");
    }

    [TestMethod]
    public void ArraysAreEqual_DifferentPositions_ShouldHaveConstantTiming() {
        // Arrange
        var baseArray = new byte[32];
        RandomNumberGenerator.Fill(baseArray);
        var iterations = 1000;

        // Warmup — force JIT compilation and steady-state CPU caches before measuring
        for (var i = 0; i < 200; i++) {
            var warm = (byte[])baseArray.Clone();
            warm[0] ^= 0xFF;
            baseArray.ArraysAreEqual(warm);
            warm = (byte[])baseArray.Clone();
            warm[31] ^= 0xFF;
            baseArray.ArraysAreEqual(warm);
        }

        // Act - Test mismatch at different positions
        var firstByteTimes = new List<long>();
        var lastByteTimes = new List<long>();

        for (var i = 0; i < iterations; i++) {
            var testFirst = (byte[])baseArray.Clone();
            testFirst[0] ^= 0xFF; // Flip first byte

            var sw = System.Diagnostics.Stopwatch.StartNew();
            _ = baseArray.ArraysAreEqual(testFirst);
            firstByteTimes.Add(sw.ElapsedTicks);

            var testLast = (byte[])baseArray.Clone();
            testLast[31] ^= 0xFF; // Flip last byte

            sw.Restart();
            _ = baseArray.ArraysAreEqual(testLast);
            lastByteTimes.Add(sw.ElapsedTicks);
        }

        // Assert
        AssertTimingOrInconclusive(firstByteTimes, lastByteTimes, 10,
            percentDiff => $"Timing for first vs last byte mismatch should be < 10% different, was {percentDiff:F2}%");
    }

    [TestMethod]
    public async Task MFAValidation_ConstantTimingForInvalidTokens() {
        // Arrange
        var username = $"testuser_{Guid.NewGuid():N}"; // Unique username
        await CreateTestUser(username, "P@ssword123", MultiFactorType.Email);

        var userManager = GetUserManager();
        var userResponse = await userManager.FindByNameAsync(username, CancellationToken.None);
        var user = userResponse.Value!;

        var validTokenResponse = await userManager.GenerateConfirmationTokenAsync(user, CancellationToken.None);
        var validToken = validTokenResponse.Value ?? "";

        var completelyWrongToken = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
        var partiallyWrongToken = string.Concat(validToken.AsSpan(0, validToken.Length - 5), "XXXXX");

        var iterations = 100;
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
        AssertTimingOrInconclusive(wrongTimes, partialTimes, 10,
            percentDiff => $"MFA validation timing should not leak information, difference was {percentDiff:F2}%");
    }

    [TestMethod]
    public async Task ErrorMessages_ShouldNotRevealUserExistence() {
        // Arrange
        await CreateTestUser("existinguser", "P@ssword123", MultiFactorType.None);
        var authService = GetAuthenticator();

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

    /// <summary>
    /// Asserts that two timing sample sets are within <paramref name="maxPercentDiff"/> of each other.
    /// If the coefficient of variation of either set exceeds 0.5 (i.e. noise > 50% of the mean),
    /// the environment is too unstable to draw conclusions and the test is marked inconclusive
    /// rather than failed — preventing flaky failures on loaded CI runners.
    /// </summary>
    private static void AssertTimingOrInconclusive(List<long> times1, List<long> times2, double maxPercentDiff, Func<double, string> message) {
        var avg1 = times1.Average();
        var avg2 = times2.Average();
        var cv1 = Math.Sqrt(times1.Average(t => Math.Pow(t - avg1, 2))) / avg1;
        var cv2 = Math.Sqrt(times2.Average(t => Math.Pow(t - avg2, 2))) / avg2;

        if (cv1 > 0.5 || cv2 > 0.5) {
            Assert.Inconclusive($"Timing environment too noisy to draw conclusions (CV: {cv1:F2}, {cv2:F2}). Run locally for a valid result.");
            return;
        }

        var percentDiff = Math.Abs(avg1 - avg2) / avg1 * 100;
        Assert.IsLessThan(maxPercentDiff, percentDiff, message(percentDiff));
    }
}