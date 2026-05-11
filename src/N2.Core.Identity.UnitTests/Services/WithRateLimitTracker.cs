using Microsoft.Extensions.Logging;
using Moq;
using N2.Core.Identity.Services;

namespace N2.Core.Identity.UnitTests.Services;

[TestClass]
public sealed class WithRateLimitTracker
{
    private static RateLimitTracker Build(int maxAttempts = 5, int lockoutMinutes = 10) =>
        new(Guid.NewGuid(), "test-item", maxAttempts, lockoutMinutes, Mock.Of<ILogger>());

    // -------------------------------------------------------------------------
    // Initial state
    // -------------------------------------------------------------------------

    [TestMethod]
    public void InitialState_HasZeroFailedAttempts()
    {
        RateLimitTracker tracker = Build();
        Assert.AreEqual(0, tracker.FailedAttempts);
    }

    [TestMethod]
    public void InitialState_IsNotLockedOut()
    {
        RateLimitTracker tracker = Build();
        Assert.IsFalse(tracker.IsLockedOut);
    }

    [TestMethod]
    public void InitialState_WindowIsNotExpired()
    {
        RateLimitTracker tracker = Build();
        Assert.IsFalse(tracker.IsWindowExpired);
    }

    // -------------------------------------------------------------------------
    // RecordFailure
    // -------------------------------------------------------------------------

    [TestMethod]
    public void RecordFailure_IncrementsFailedAttempts()
    {
        RateLimitTracker tracker = Build(maxAttempts: 5);
        tracker.RecordFailure();
        Assert.AreEqual(1, tracker.FailedAttempts);
    }

    [TestMethod]
    public void RecordFailure_AtMaxAttempts_SetsLockout()
    {
        RateLimitTracker tracker = Build(maxAttempts: 3);
        tracker.RecordFailure();
        tracker.RecordFailure();
        tracker.RecordFailure();
        Assert.IsTrue(tracker.IsLockedOut);
        Assert.IsNotNull(tracker.LockoutUntil);
    }

    [TestMethod]
    public void RecordFailure_BelowMaxAttempts_DoesNotLock()
    {
        RateLimitTracker tracker = Build(maxAttempts: 5);
        tracker.RecordFailure();
        tracker.RecordFailure();
        Assert.IsFalse(tracker.IsLockedOut);
    }

    // -------------------------------------------------------------------------
    // RecordAttempt
    // -------------------------------------------------------------------------

    [TestMethod]
    public void RecordAttempt_Success_ResetsFailedAttempts()
    {
        RateLimitTracker tracker = Build();
        tracker.RecordFailure();
        tracker.RecordAttempt(success: true);
        Assert.AreEqual(0, tracker.FailedAttempts);
    }

    [TestMethod]
    public void RecordAttempt_Failure_IncrementsCount()
    {
        RateLimitTracker tracker = Build();
        tracker.RecordAttempt(success: false);
        Assert.AreEqual(1, tracker.FailedAttempts);
    }

    // -------------------------------------------------------------------------
    // Reset
    // -------------------------------------------------------------------------

    [TestMethod]
    public void Reset_ClearsFailedAttemptsAndLockout()
    {
        RateLimitTracker tracker = Build(maxAttempts: 2);
        tracker.RecordFailure();
        tracker.RecordFailure();
        tracker.Reset();
        Assert.AreEqual(0, tracker.FailedAttempts);
        Assert.IsFalse(tracker.IsLockedOut);
    }

    // -------------------------------------------------------------------------
    // CheckRateLimit
    // -------------------------------------------------------------------------

    [TestMethod]
    public void CheckRateLimit_WhenNotLocked_ReturnsSuccess()
    {
        RateLimitTracker tracker = Build();
        (bool success, _) = tracker.CheckRateLimit();
        Assert.IsTrue(success);
    }

    [TestMethod]
    public void CheckRateLimit_WhenLockedOut_ReturnsFailureWithRemainingTime()
    {
        RateLimitTracker tracker = Build(maxAttempts: 2, lockoutMinutes: 10);
        tracker.RecordFailure();
        tracker.RecordFailure();
        (bool success, double remainingTime) = tracker.CheckRateLimit();
        Assert.IsFalse(success);
        Assert.IsTrue(remainingTime > 0);
    }

    [TestMethod]
    public void CheckRateLimit_WhenWindowExpired_ResetsAndReturnsSuccess()
    {
        RateLimitTracker tracker = Build(maxAttempts: 5, lockoutMinutes: 5);
        tracker.SetLockoutEnd(DateTime.UtcNow.AddMinutes(-30));
        (bool success, _) = tracker.CheckRateLimit();
        Assert.IsTrue(success);
    }

    // -------------------------------------------------------------------------
    // SetLockoutEnd
    // -------------------------------------------------------------------------

    [TestMethod]
    public void SetLockoutEnd_FutureDate_SetsLockout()
    {
        RateLimitTracker tracker = Build();
        tracker.SetLockoutEnd(DateTime.UtcNow.AddMinutes(10));
        Assert.IsTrue(tracker.IsLockedOut);
    }

    [TestMethod]
    public void SetLockoutEnd_PastDate_IsNotLockedOut()
    {
        RateLimitTracker tracker = Build(lockoutMinutes: 5);
        tracker.SetLockoutEnd(DateTime.UtcNow.AddMinutes(-1));
        Assert.IsFalse(tracker.IsLockedOut);
    }

    // -------------------------------------------------------------------------
    // IsWindowExpired
    // -------------------------------------------------------------------------

    [TestMethod]
    public void IsWindowExpired_WindowSetInDistantPast_ReturnsTrue()
    {
        RateLimitTracker tracker = Build(lockoutMinutes: 5);
        tracker.SetLockoutEnd(DateTime.UtcNow.AddMinutes(-30));
        Assert.IsTrue(tracker.IsWindowExpired);
    }
}
