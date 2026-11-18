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

        // Act
        var result = await manager.Validate(user, "wrong", cts.Token);

        // Assert
        Assert.IsTrue(cts.IsCancellationRequested);
        Assert.AreEqual(ResponseStatus.NotAccepted, result.Status);
        Assert.AreEqual(before + 1, await ReadAccessFailedCount(factory, user.Id));
    }

    private static async Task<int> ReadAccessFailedCount(IIdentityContextFactory factory, Guid userId) {
        using var ctx = await factory.Create(CancellationToken.None);
        var dbUser = await ctx.UserFindRecord(userId, CancellationToken.None);
        Assert.IsNotNull(dbUser);
        return dbUser.AccessFailedCount;
    }
}
