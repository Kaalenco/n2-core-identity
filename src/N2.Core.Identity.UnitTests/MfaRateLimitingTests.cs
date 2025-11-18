using N2.Core.Commands;
using N2.Core.Identity.Services;

using OtpNet;

using System.Diagnostics;
using System.Globalization;

namespace N2.Core.Identity.UnitTests;

[TestClass]
public class MfaRateLimitingTests : N2IdentityTestsBase {

    [TestMethod]
    public async Task ValidateMFA_FiveFailedAttempts_ShouldLockout() {
        // Arrange
        var user = await CreateTestUser($"TestUser-{Guid.NewGuid}", "somePassword", MultiFactorType.Totp);
        var invalidCode = "000000";
        var userManager = GetUserManager();

        // Act - 5 failed attempts
        for (var i = 0; i < 5; i++) {
            var result = await userManager.ValidateMultifactorAsync(user, invalidCode, CancellationToken.None);
            Assert.AreEqual(ResponseStatus.Unauthorized, result.Status, $"Attempt {i + 1} should fail");
        }

        // 6th attempt should be blocked due to lockout
        var lockedResult = await userManager.ValidateMultifactorAsync(user, "123456", CancellationToken.None);
        Assert.AreEqual(ResponseStatus.Unauthorized, lockedResult.Status);
        Assert.IsTrue(
            lockedResult != null && lockedResult.Message != null &&
            (lockedResult.Message.Contains("locked", StringComparison.OrdinalIgnoreCase) || lockedResult.Message.Contains("Too many", StringComparison.OrdinalIgnoreCase)),
            "Error message should indicate lockout");
    }

    [TestMethod]
    public async Task ValidateMFA_SuccessfulValidation_ShouldResetFailedCount() {
        // Arrange
        var user = await CreateTestUser($"TestUser-{Guid.NewGuid}", "somePassword", MultiFactorType.Totp);

        Totp otp = new(Convert.FromBase64String(user.MfaSecret ?? string.Empty));
        var validCode = otp.ComputeTotp(DateTime.UtcNow);
        var userManager = GetUserManager();

        // 3 failed attempts
        for (var i = 0; i < 3; i++) {
            await userManager.ValidateMultifactorAsync(user, "000000", CancellationToken.None);
        }

        // Act - Valid code should succeed and reset counter
        var result = await userManager.ValidateMultifactorAsync(user, validCode, CancellationToken.None);

        // Assert
        Assert.AreEqual(ResponseStatus.Success, result.Status);

        // Should be able to fail 5 more times before lockout (counter was reset)
        for (var i = 0; i < 4; i++) {
            var failResult = await userManager.ValidateMultifactorAsync(user, "000000", CancellationToken.None);
            Assert.AreEqual(ResponseStatus.Unauthorized, failResult.Status);
            Assert.IsFalse(
                !string.IsNullOrEmpty(failResult.Message) &&
                failResult.Message.Contains("locked", StringComparison.OrdinalIgnoreCase),
                "Should not be locked yet");
        }
    }

    [TestMethod]
    public async Task ValidateMFA_TOTP_BruteForce_ShouldBlock() {
        // Arrange
        var user = await CreateTestUser($"TestUser-{Guid.NewGuid}", "somePassword", MultiFactorType.Totp);
        var stopwatch = Stopwatch.StartNew();
        var userManager = GetUserManager();
        var attemptCount = 0;

        // Act - Try to brute force (should be stopped by rate limiting)
        for (var code = 0; code < 100; code++) {
            var result = await userManager.ValidateMultifactorAsync(
                user,
                code.ToString("D6", CultureInfo.InvariantCulture),
                CancellationToken.None
            );

            attemptCount++;
            Assert.IsNotNull(result);
            if (!string.IsNullOrEmpty(result.Message)) {
                if (result.Message.Contains("locked", StringComparison.OrdinalIgnoreCase) || result.Message.Contains("Too many", StringComparison.OrdinalIgnoreCase)) {
                    break; // Hit rate limit
                }
            }
        }

        stopwatch.Stop();

        // Assert
        Assert.IsLessThanOrEqualTo(6, attemptCount, $"Should be locked after 5 attempts, but made {attemptCount} attempts");
        Assert.IsLessThan(10, stopwatch.Elapsed.TotalSeconds, "Should hit rate limit quickly, preventing brute force");
    }

    [TestMethod]
    public async Task ValidateMFA_LockoutExpires_ShouldAllowRetry() {
        // Arrange
        var user = await CreateTestUser($"TestUser-{Guid.NewGuid}", "somePassword", MultiFactorType.Totp);
        var userManager = GetUserManager();

        // Lock out the account
        for (var i = 0; i < 5; i++) {
            await userManager.ValidateMultifactorAsync(user, "000000", CancellationToken.None);
        }

        // Verify locked
        var lockedResult = await userManager.ValidateMultifactorAsync(user, "123456", CancellationToken.None);
        Assert.IsNotNull(lockedResult);
        Assert.IsNotNull(lockedResult.Message);
        Assert.IsTrue(
            lockedResult.Message.Contains("locked", StringComparison.OrdinalIgnoreCase) ||
            lockedResult.Message.Contains("Too many", StringComparison.OrdinalIgnoreCase));

        // Wait for lockout to expire (simulate by adjusting tracker) In real implementation, would
        // wait actual time or adjust system clock in test
        var userMgr = userManager as N2UserManager;
        Assert.IsNotNull(userMgr);
        userMgr.UpdateRateLimiter(user.Id, user.NormalizedUserName, DateTime.UtcNow.AddMinutes(-1));

        // Act - Should be able to attempt again
        Totp otp = new(Convert.FromBase64String(user.MfaSecret ?? string.Empty));
        var validCode = otp.ComputeTotp(DateTime.UtcNow);
        var result = await userManager.ValidateMultifactorAsync(user, validCode, CancellationToken.None);

        // Assert
        Assert.AreEqual(ResponseStatus.Success, result.Status);
    }

    [TestMethod]
    public async Task ValidateMFA_Totp_ExpiredToken_ShouldFail() {
        // Arrange
        var user = await CreateTestUser($"TestUser-{Guid.NewGuid}", "somePassword", MultiFactorType.Totp);
        var userManager = GetUserManager();

        // Generate token with short expiration
        Totp otp = new(Convert.FromBase64String(user.MfaSecret ?? string.Empty));
        var expiredToken = otp.ComputeTotp(DateTime.UtcNow.AddMinutes(-20));
        // Act
        var result = await userManager.ValidateMultifactorAsync(user, expiredToken, CancellationToken.None);

        // Assert
        Assert.AreEqual(ResponseStatus.Unauthorized, result.Status);
        Assert.IsNotNull(result.Message);
        Assert.IsTrue(result.Message.Contains("expired", StringComparison.OrdinalIgnoreCase), "Should indicate token expiration");
    }

    [TestMethod]
    public async Task ValidateMFA_Totp_Future_ShouldFail() {
        // Arrange
        var user = await CreateTestUser($"TestUser-{Guid.NewGuid}", "somePassword", MultiFactorType.Totp);
        var userManager = GetUserManager();

        // Generate token with short expiration
        Totp otp = new(Convert.FromBase64String(user.MfaSecret ?? string.Empty));
        var expiredToken = otp.ComputeTotp(DateTime.UtcNow.AddMinutes(20));
        // Act
        var result = await userManager.ValidateMultifactorAsync(user, expiredToken, CancellationToken.None);

        // Assert
        Assert.AreEqual(ResponseStatus.Unauthorized, result.Status);
        Assert.IsNotNull(result.Message);
        Assert.IsTrue(result.Message.Contains("time skew", StringComparison.OrdinalIgnoreCase), "Should indicate token expiration");
    }

    [TestMethod]
    public async Task ValidateMFA_ConcurrentAttempts_ShouldHandleThreadSafety() {
        // Arrange
        var user = await CreateTestUser($"TestUser-{Guid.NewGuid}", "somePassword", MultiFactorType.Totp);
        var tasks = new List<Task<ICommandResponse>>();
        var userManager = GetUserManager();

        // Act - Simulate 10 concurrent invalid attempts
        for (var i = 0; i < 10; i++) {
            var attempt = i; // Capture for closure
            tasks.Add(Task.Run(async () => {
                await Task.Delay(attempt * 10); // Stagger slightly
                var result = await userManager.ValidateMultifactorAsync(
                    user,
                    $"{attempt:D6}",
                    CancellationToken.None
                );
                Assert.IsNotNull(result);
                Assert.IsFalse(result.Status.IsSuccess());
                return result;
            }));
        }

        var results = await Task.WhenAll(tasks);

        // Assert - After 5 attempts, should be locked
        var lockedCount = results.Count(r =>
            r != null && r.Message != null &&
            (r.Message.Contains("locked", StringComparison.OrdinalIgnoreCase) || r.Message.Contains("Too many", StringComparison.OrdinalIgnoreCase)));

        Assert.IsGreaterThanOrEqualTo(5, lockedCount, $"At least 5 attempts should be blocked due to lockout, but only {lockedCount} were blocked");
    }
}