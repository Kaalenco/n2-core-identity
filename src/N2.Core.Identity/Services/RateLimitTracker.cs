using Microsoft.Extensions.Logging;

namespace N2.Core.Identity.Services;

public interface IRateLimitPolicy {
    int FailedAttempts { get; }
    DateTime? LockoutUntil { get; }
    DateTime LastAttempt { get; }
    DateTime WindowStart { get; }
    bool IsLockedOut { get; }
    bool IsWindowExpired { get; }
    void Reset();
    void RecordFailure();
    void RecordAttempt(bool success);
    void SetLockoutEnd(DateTime lockoutEnd);
    (bool Success, double RemainingTime) CheckRateLimit();
}

/// <summary>
/// Tracks attempts for rate limiting and lockout.
/// </summary>
public class RateLimitTracker : IRateLimitPolicy {

    private readonly object trackerLock = new();
    private readonly int maxAttempts;
    private readonly int lockoutMinutes;
    private readonly ILogger logger;
    public RateLimitTracker(Guid reference, string itemName, int maxAttempts, int lockoutMinutes, ILogger logger) {
        this.maxAttempts = maxAttempts;
        this.lockoutMinutes = lockoutMinutes;
        this.logger = logger;
        Reference = reference;
        ItemName = itemName;
        WindowStart = DateTime.UtcNow;
        LastAttempt = DateTime.UtcNow;
    }

    public Guid Reference { get; private set; }
    public string ItemName { get; private set; }
    public int FailedAttempts { get; private set; }
    public DateTime? LockoutUntil { get; private set; }
    public DateTime LastAttempt { get; private set; }
    public DateTime WindowStart { get; private set; }


    /// <summary>
    /// Checks if the user is currently locked out from MFA attempts.
    /// </summary>
    public bool IsLockedOut => LockoutUntil.HasValue && LockoutUntil.Value > DateTime.UtcNow;

    /// <summary>
    /// Checks if the current attempt window has expired (15 minutes).
    /// </summary>
    public bool IsWindowExpired => (DateTime.UtcNow - WindowStart).TotalMinutes > 15;

    /// <summary>
    /// Resets the attempt counter and lockout status.
    /// </summary>
    public void Reset() {
        lock (trackerLock) {
            ResetLocked();
        }
    }

    public void ResetLocked() {
        FailedAttempts = 0;
        LockoutUntil = null;
        WindowStart = DateTime.UtcNow;
        LastAttempt = DateTime.UtcNow;
    }

    /// <summary>
    /// Records a failed attempt and applies lockout if threshold exceeded.
    /// </summary>
    public void RecordFailure() {
        lock (trackerLock) {
            RecordFailureLocked();
        }
    }

    private void RecordFailureLocked() {
        FailedAttempts++;
        LastAttempt = DateTime.UtcNow;

        if (FailedAttempts >= maxAttempts) {
            LockoutUntil = DateTime.UtcNow.AddMinutes(lockoutMinutes);
        }
    }

    public void RecordAttempt(bool success) {
        lock (trackerLock) {
            if (success) {
                if (FailedAttempts > 0) {
                    logger.LogResetMfaWarning(
                        Reference,
                        ItemName,
                        FailedAttempts
                    );
                }
                ResetLocked();
            } else {
                RecordFailureLocked();

                if (IsLockedOut) {
                    logger.LogMfaLockoutWarning(
                        Reference,
                        ItemName,
                        FailedAttempts,
                        LockoutUntil
                    );
                } else {
                    logger.LogMfaAttemptsWarning(
                        Reference,
                        ItemName,
                        FailedAttempts,
                        maxAttempts
                    );
                }
            }
        }
    }

    /// <summary>
    /// Checks if user is locked out from MFA attempts and updates tracking.
    /// Returns null if allowed to proceed, or error response if locked out.
    /// </summary>
    public (bool Success, double RemainingTime) CheckRateLimit() {
        lock (trackerLock) {
            // Reset if window expired
            if (IsWindowExpired) {
                Reset();
                return (true, 0);
            }

            // Check lockout status
            if (LockoutUntil != null) {
                var remainingTime = LockoutUntil!.Value - DateTime.UtcNow;
                if (IsLockedOut) {

                    logger.LogMfaValidationBlockedWarning(
                        Reference,
                        ItemName,
                        LockoutUntil.Value,
                        Math.Ceiling(remainingTime.TotalSeconds),
                        FailedAttempts
                    );
                    return (false, Math.Ceiling(remainingTime.TotalMinutes));
                }
            }

            // Check if approaching limit (warn after 3 attempts)
            if (FailedAttempts >= 3 && FailedAttempts < maxAttempts) {
                logger.LogMfaFailedAttemptsWarning(
                    Reference,
                    ItemName,
                    FailedAttempts,
                    maxAttempts - FailedAttempts
                );
            }
            return (true, 0);
        }
    }

    public void SetLockoutEnd(DateTime lockoutEnd) {
        WindowStart = lockoutEnd.AddMinutes(-lockoutMinutes);
        LockoutUntil = lockoutEnd;
    }
}

public static class RateLimiterLoggingExtensions {
    private static readonly Action<ILogger, Guid, string, int, int, Exception?> logMfaAttemptsWarn =
      LoggerMessage.Define<Guid, string, int, int>(
      LogLevel.Warning,
      new EventId(8, nameof(LogMfaFailedAttemptsWarning)),
      "Rate limit failed attempt for [{Reference}] {ItemName}. Total failed attempts: {FailedAttempts}/{MaxAttempts}");

    private static readonly Action<ILogger, Guid, string, int, int, Exception?> logMfaFailedAttemptsWarn =
        LoggerMessage.Define<Guid, string, int, int>(
        LogLevel.Warning,
        new EventId(7, nameof(LogMfaFailedAttemptsWarning)),
        "Rate limit [{Reference}] {ItemName} has {FailedAttempts} failed attempts ({RemainingAttempts} remaining before lockout)");

    private static readonly Action<ILogger, Guid, string, int, DateTime?, Exception?> logMfaLockoutWarn =
        LoggerMessage.Define<Guid, string, int, DateTime?>(
        LogLevel.Warning,
        new EventId(9, nameof(LogMfaLockoutWarning)),
        "Rate limit [{Reference}] {ItemName} locked out from validation after {FailedAttempts} failed attempts. Lockout until {LockoutEnd}");

    private static readonly Action<ILogger, Guid, string, int, Exception?> logMfaResetWarn =
        LoggerMessage.Define<Guid, string, int>(
        LogLevel.Warning,
        new EventId(10, nameof(LogResetMfaWarning)),
        "Validation succeeded for [{Reference}] {ItemName}. Resetting {FailedAttempts} previous failed attempts.");

    private static readonly Action<ILogger, Guid, string, DateTime, double, int, Exception?> logMfaValidationBlockedWarn =
        LoggerMessage.Define<Guid, string, DateTime, double, int>(
        LogLevel.Warning,
        new EventId(6, nameof(LogMfaValidationBlockedWarning)),
        "Validation blocked for [{Reference}] {ItemName} - locked out until {LockoutEnd} ({RemainingSeconds} seconds remaining). Failed attempts: {FailedAttempts}");


    public static void LogMfaAttemptsWarning(this ILogger logger, Guid reference, string itemName, int failedAttempts, int maxAttempts) {
        logMfaAttemptsWarn(logger, reference, itemName, failedAttempts, maxAttempts, null);
    }

    public static void LogMfaFailedAttemptsWarning(this ILogger logger, Guid reference, string itemName, int failedAttempts, int remainingAttempts) {
        logMfaFailedAttemptsWarn(logger, reference, itemName, failedAttempts, remainingAttempts, null);
    }

    public static void LogMfaLockoutWarning(this ILogger logger, Guid reference, string itemName, int failedAttempts, DateTime? lockoutUntil) {
        logMfaLockoutWarn(logger, reference, itemName, failedAttempts, lockoutUntil, null);
    }

    public static void LogMfaValidationBlockedWarning(this ILogger logger, Guid reference, string itemName, DateTime lockoutUntil, double totalSeconds, int failedAttempts) {
        logMfaValidationBlockedWarn(logger, reference, itemName, lockoutUntil, totalSeconds, failedAttempts, null);
    }

    public static void LogResetMfaWarning(this ILogger logger, Guid reference, string itemName, int failedAttempts) {
        logMfaResetWarn(logger, reference, itemName, failedAttempts, null);
    }
}