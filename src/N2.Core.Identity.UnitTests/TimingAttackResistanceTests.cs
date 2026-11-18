using Microsoft.AspNetCore.Identity;

using N2.Core.Identity.Data;

using System.Security.Cryptography;

namespace N2.Core.Identity.UnitTests;

[TestClass]
[TestCategory("LongRunning")]
public class TimingAttackResistanceTests : N2IdentityTestsBase {

    [TestMethod]
    public async Task Authentication_ValidVsInvalidUser_ShouldHaveConstantTiming() {
        await CreateTestUser("validuser", "P@ssword123", MultiFactorType.None);
        var iterations = 100;
        var validUserTimes = new List<long>();
        var invalidUserTimes = new List<long>();
        var authService = GetAuthenticator();
        var sw = System.Diagnostics.Stopwatch.StartNew();

        for (var i = 0; i < iterations; i++) {
            sw.Restart();
            await authService.Authenticate(new UserLogin {
                Username = "validuser",
                Password = "WrongPassword"
            }, CancellationToken.None);
            validUserTimes.Add(sw.ElapsedMilliseconds);

            sw.Restart();
            await authService.Authenticate(new UserLogin {
                Username = "nonexistentuser" + i,
                Password = "WrongPassword"
            }, CancellationToken.None);
            invalidUserTimes.Add(sw.ElapsedMilliseconds);
        }

        AssertTimingOrInconclusive(validUserTimes, invalidUserTimes, 20,
            percentDiff => $"Timing difference should be < 20% to prevent user enumeration, was {percentDiff:F2}%");
    }

    [TestMethod]
    public void ArraysAreEqual_DifferentPositions_ShouldHaveConstantTiming() {
        var baseArray = new byte[32];
        RandomNumberGenerator.Fill(baseArray);
        var iterations = 1000;

        for (var i = 0; i < 200; i++) {
            var warm = (byte[])baseArray.Clone();
            warm[0] ^= 0xFF;
            baseArray.ArraysAreEqual(warm);
            warm = (byte[])baseArray.Clone();
            warm[31] ^= 0xFF;
            baseArray.ArraysAreEqual(warm);
        }

        var firstByteTimes = new List<long>();
        var lastByteTimes = new List<long>();

        for (var i = 0; i < iterations; i++) {
            var testFirst = (byte[])baseArray.Clone();
            testFirst[0] ^= 0xFF;

            var sw = System.Diagnostics.Stopwatch.StartNew();
            _ = baseArray.ArraysAreEqual(testFirst);
            firstByteTimes.Add(sw.ElapsedTicks);

            var testLast = (byte[])baseArray.Clone();
            testLast[31] ^= 0xFF;

            sw.Restart();
            _ = baseArray.ArraysAreEqual(testLast);
            lastByteTimes.Add(sw.ElapsedTicks);
        }

        AssertTimingOrInconclusive(firstByteTimes, lastByteTimes, 10,
            percentDiff => $"Timing for first vs last byte mismatch should be < 10% different, was {percentDiff:F2}%");
    }

    [TestMethod]
    public async Task MFAValidation_ConstantTimingForInvalidTokens() {
        var username = $"testuser_{Guid.NewGuid():N}";
        await CreateTestUser(username, "P@ssword123", MultiFactorType.Email);

        var userManager = GetUserManager();
        var userResponse = await userManager.FindByName(username, CancellationToken.None);
        var user = userResponse.Value!;

        var validTokenResponse = await userManager.GenerateConfirmationToken(user, CancellationToken.None);
        var validToken = validTokenResponse.Value ?? "";

        var completelyWrongToken = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
        var partiallyWrongToken = string.Concat(validToken.AsSpan(0, validToken.Length - 5), "XXXXX");

        var iterations = 100;
        var wrongTimes = new List<long>();
        var partialTimes = new List<long>();

        for (var i = 0; i < iterations; i++) {
            var sw = System.Diagnostics.Stopwatch.StartNew();
            await userManager.ValidateMultifactor(user, completelyWrongToken, CancellationToken.None);
            wrongTimes.Add(sw.ElapsedTicks);

            sw.Restart();
            await userManager.ValidateMultifactor(user, partiallyWrongToken, CancellationToken.None);
            partialTimes.Add(sw.ElapsedTicks);
        }

        AssertTimingOrInconclusive(wrongTimes, partialTimes, 10,
            percentDiff => $"MFA validation timing should not leak information, difference was {percentDiff:F2}%");
    }

    [TestMethod]
    public void PasswordHashing_ComputationalCost_ShouldBeSufficient() {
        var password = "BenchmarkP@ss789";
        var user = new ApplicationUser { UserName = "testuser" };
        var options = new PasswordHasherOptions {
            CompatibilityMode = PasswordHasherCompatibilityMode.IdentityV3,
            IterationCount = 310000
        };
        var productionHasher = new PasswordHasher<ApplicationUser>(
            Microsoft.Extensions.Options.Options.Create(options));
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        productionHasher.HashPassword(user, password);
        stopwatch.Stop();

        Assert.IsGreaterThanOrEqualTo(100,
            stopwatch.ElapsedMilliseconds,
            $"Password hashing should take >= 100ms (OWASP 2023), took {stopwatch.ElapsedMilliseconds}ms");
    }

    [TestMethod]
    public async Task PasswordVerification_TimingAttackResistance_ShouldBeConstantTime() {
        var user = await CreateUserWithPassword("TestPassword123!");
        var iterations = 100;
        var userManager = GetUserManager();

        await userManager.Validate(user, "WarmupPassword1!", CancellationToken.None);
        await userManager.Validate(user, "WarmupPassword2!", CancellationToken.None);

        var timesFirstChar = new List<long>();
        var timesLastChar = new List<long>();

        for (var i = 0; i < iterations; i++) {
            var wrongFirst = "XestPassword123!";
            var sw = System.Diagnostics.Stopwatch.StartNew();
            await userManager.Validate(user, wrongFirst, CancellationToken.None);
            timesFirstChar.Add(sw.ElapsedTicks);

            var wrongLast = "TestPassword123X";
            sw.Restart();
            await userManager.Validate(user, wrongLast, CancellationToken.None);
            timesLastChar.Add(sw.ElapsedTicks);
        }

        AssertTimingOrInconclusive(timesFirstChar, timesLastChar, 20,
            percentDiff => $"Timing difference should be < 20%, was {percentDiff:F2}%");
    }
}
