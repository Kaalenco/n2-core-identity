using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;

using Moq;

using N2.Core.Commands;
using N2.Core.Identity.Data;
using N2.Core.Identity.Services;

namespace N2.Core.Identity.UnitTests;

/// <summary>
/// Security state (MFA rate limiter, lockout counter) must be recorded even when the caller
/// cancels its request part-way. The tests cancel the token right after the credential check.
/// </summary>
[TestClass]
public class WithSecurityWritesUnderCancellation : N2IdentityTestsBase {

    private N2UserManager CreateManager(IRateLimiter rateLimiter, IPasswordHasher<ApplicationUser> hasher) =>
        new(
            ServiceProvider.GetRequiredService<IIdentityContextFactory>(),
            ServiceProvider.GetRequiredService<IConfiguration>(),
            rateLimiter,
            hasher,
            "IdentityDb",
            NullLogger<N2UserManager>.Instance);

    [TestMethod]
    public async Task ValidateMultifactor_CancelledDuringPadding_ShouldStillRecordFailedAttempt() {
        // Arrange
        var user = await CreateTestUser($"mfa_cancel_{Guid.NewGuid():N}", "P@ssword1!", MultiFactorType.Totp);
        using var cts = new CancellationTokenSource();
        var rateLimiter = new Mock<IRateLimiter>();
        rateLimiter.Setup(r => r.CheckRateLimit(It.IsAny<Guid>(), It.IsAny<string?>())).Returns((true, 0d));
        // Cancelling inside RecordAttempt means the token is cancelled when the padding wait starts.
        rateLimiter.Setup(r => r.RecordAttempt(user.Id, It.IsAny<string?>(), false)).Callback(() => cts.Cancel());
        using var manager = CreateManager(rateLimiter.Object, ServiceProvider.GetRequiredService<IPasswordHasher<ApplicationUser>>());

        // Act
        await Assert.ThrowsAsync<OperationCanceledException>(
            () => manager.ValidateMultifactor(user, "000000", cts.Token));

        // Assert
        rateLimiter.Verify(r => r.RecordAttempt(user.Id, It.IsAny<string?>(), false), Times.Once);
    }

    [TestMethod]
    public async Task Validate_CancelledAfterPasswordCheck_ShouldStillIncrementAccessFailedCount() {
        // Arrange
        var user = await CreateTestUser($"lock_cancel_{Guid.NewGuid():N}", "P@ssword1!", MultiFactorType.None);
        var factory = ServiceProvider.GetRequiredService<IIdentityContextFactory>();
        var before = await ReadAccessFailedCount(factory, user.Id);

        using var cts = new CancellationTokenSource();
        var hasher = new Mock<IPasswordHasher<ApplicationUser>>();
        hasher.Setup(h => h.VerifyHashedPassword(It.IsAny<ApplicationUser>(), It.IsAny<string>(), It.IsAny<string>()))
            .Callback(() => cts.Cancel())
            .Returns(PasswordVerificationResult.Failed);
        using var manager = CreateManager(ServiceProvider.GetRequiredService<IRateLimiter>(), hasher.Object);

        // Act - the wrong-password path pads with a cancellable wait after the counter write,
        // so the cancelled token surfaces as OperationCanceledException from that wait.
        await Assert.ThrowsAsync<OperationCanceledException>(
            () => manager.Validate(user, "wrong", cts.Token));

        // Assert
        Assert.IsTrue(cts.IsCancellationRequested);
        Assert.AreEqual(before + 1, await ReadAccessFailedCount(factory, user.Id));
    }

    [TestMethod]
    public async Task Validate_WrongPassword_ShouldPadToAuthenticationTime() {
        // Arrange - a hasher that fails instantly, so any elapsed time near the budget comes
        // from the padding wait and not from PBKDF2.
        var user = await CreateTestUser($"pad_wrong_{Guid.NewGuid():N}", "P@ssword1!", MultiFactorType.None);
        var hasher = new Mock<IPasswordHasher<ApplicationUser>>();
        hasher.Setup(h => h.VerifyHashedPassword(It.IsAny<ApplicationUser>(), It.IsAny<string>(), It.IsAny<string>()))
            .Returns(PasswordVerificationResult.Failed);
        using var manager = CreateManager(ServiceProvider.GetRequiredService<IRateLimiter>(), hasher.Object);
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();

        // Act
        var result = await manager.Validate(user, "wrong", CancellationToken.None);
        stopwatch.Stop();

        // Assert - lower bound only; no upper bound, to stay robust on slow machines.
        Assert.AreEqual(ResponseStatus.NotAccepted, result.Status);
        Assert.IsGreaterThanOrEqualTo(PaddingLowerBoundMs, stopwatch.ElapsedMilliseconds);
    }

    [TestMethod]
    public async Task Validate_UnknownUser_ShouldPadToAuthenticationTime() {
        // Arrange
        var unknown = new ApplicationUser { UserName = $"pad_unknown_{Guid.NewGuid():N}" };
        using var manager = CreateManager(
            ServiceProvider.GetRequiredService<IRateLimiter>(),
            ServiceProvider.GetRequiredService<IPasswordHasher<ApplicationUser>>());
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();

        // Act
        var result = await manager.Validate(unknown, "wrong", CancellationToken.None);
        stopwatch.Stop();

        // Assert
        Assert.AreEqual(ResponseStatus.NotAccepted, result.Status);
        Assert.IsGreaterThanOrEqualTo(PaddingLowerBoundMs, stopwatch.ElapsedMilliseconds);
    }

    // N2UserManager pads authentication to 500 ms; allow 20 ms for timer resolution.
    private const long PaddingLowerBoundMs = 480;

    private static async Task<int> ReadAccessFailedCount(IIdentityContextFactory factory, Guid userId) {
        using var ctx = await factory.Create(CancellationToken.None);
        var dbUser = await ctx.UserFindRecord(userId, CancellationToken.None);
        Assert.IsNotNull(dbUser);
        return dbUser.AccessFailedCount;
    }
}
