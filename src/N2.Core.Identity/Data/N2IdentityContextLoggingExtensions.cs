using Microsoft.Extensions.Logging;

namespace N2.Core.Identity.Data;

public static class N2IdentityContextLoggingExtensions {

    private static readonly Action<ILogger, string, Exception?> logAddApplicationRoleFail =
        LoggerMessage.Define<string>(
        LogLevel.Warning,
        new EventId(2, nameof(LogAddApplicationRoleFailed)),
        "AddApplicationRoleAsync failed with {Message}");

    private static readonly Action<ILogger, string, Exception?> logAddApplicationUserFail =
        LoggerMessage.Define<string>(
        LogLevel.Warning,
        new EventId(4, nameof(LogAddApplicationUserFailed)),
        "AddApplicationUserAsync failed with {Message}");

    private static readonly Action<ILogger, string, Exception?> logAddIdentityUserRoleFail =
        LoggerMessage.Define<string>(
        LogLevel.Warning,
        new EventId(3, nameof(LogAddIdentityUserRoleFailed)),
        "AddApplicationRoleAsync failed with {Message}");

    private static readonly Action<ILogger, string, Exception?> logHealthStatusFail =
        LoggerMessage.Define<string>(
        LogLevel.Warning,
        new EventId(1, nameof(LogHealthStatusFailed)),
        "Health Status failed with exception: {Message}");

    private static readonly Action<ILogger, string, int, int, Exception?> logMfaAttemptsWarn =
        LoggerMessage.Define<string, int, int>(
        LogLevel.Warning,
        new EventId(8, nameof(LogMfaFailedAttemptsWarning)),
        "Failed MFA attempt for user {UserName}. Total failed attempts: {FailedAttempts}/{MaxAttempts}");

    private static readonly Action<ILogger, string, int, int, Exception?> logMfaFailedAttemptsWarn =
        LoggerMessage.Define<string, int, int>(
        LogLevel.Warning,
        new EventId(7, nameof(LogMfaFailedAttemptsWarning)),
        "User {UserName} has {FailedAttempts} failed MFA attempts ({RemainingAttempts} remaining before lockout)");

    private static readonly Action<ILogger, string, int, DateTime?, Exception?> logMfaLockoutWarn =
        LoggerMessage.Define<string, int, DateTime?>(
        LogLevel.Warning,
        new EventId(9, nameof(LogMfaLockoutWarning)),
        "User {UserName} locked out from MFA validation after {FailedAttempts} failed attempts. Lockout until {LockoutEnd}");

    private static readonly Action<ILogger, string, int, Exception?> logMfaResetWarn =
        LoggerMessage.Define<string, int>(
        LogLevel.Warning,
        new EventId(10, nameof(LogResetMfaWarning)),
        "MFA validation succeeded for user {UserName}. Resetting {FailedAttempts} previous failed attempts.");

    private static readonly Action<ILogger, string, DateTime, double, int, Exception?> logMfaValidationBlockedWarn =
        LoggerMessage.Define<string, DateTime, double, int>(
        LogLevel.Warning,
        new EventId(6, nameof(LogMfaValidationBlockedWarning)),
        "MFA validation blocked for user {UserName} - locked out until {LockoutEnd} ({RemainingSeconds} seconds remaining). Failed attempts: {FailedAttempts}");

    public static void LogAddApplicationRoleFailed(this ILogger logger, string message, Exception? exception) {
        logAddApplicationRoleFail(logger, message, exception);
    }

    public static void LogAddApplicationUserFailed(this ILogger logger, string message, Exception? exception) {
        logAddApplicationUserFail(logger, message, exception);
    }

    public static void LogAddIdentityUserRoleFailed(this ILogger logger, string message, Exception? exception) {
        logAddIdentityUserRoleFail(logger, message, exception);
    }

    public static void LogHealthStatusFailed(this ILogger logger, string message, Exception? exception) {
        logHealthStatusFail(logger, message, exception);
    }

    public static void LogMfaAttemptsWarning(this ILogger logger, string? userName, int failedAttempts, int maxAttempts) {
        logMfaAttemptsWarn(logger, userName ?? "", failedAttempts, maxAttempts, null);
    }

    public static void LogMfaFailedAttemptsWarning(this ILogger logger, string? userName, int failedAttempts, int remainingAttempts) {
        logMfaFailedAttemptsWarn(logger, userName ?? "", failedAttempts, remainingAttempts, null);
    }

    public static void LogMfaLockoutWarning(this ILogger logger, string? userName, int failedAttempts, DateTime? lockoutUntil) {
        logMfaLockoutWarn(logger, userName ?? "", failedAttempts, lockoutUntil, null);
    }

    public static void LogMfaValidationBlockedWarning(this ILogger logger, string? userName, DateTime lockoutUntil, double totalSeconds, int failedAttempts) {
        logMfaValidationBlockedWarn(logger, userName ?? "", lockoutUntil, totalSeconds, failedAttempts, null);
    }

    public static void LogResetMfaWarning(this ILogger logger, string? userName, int failedAttempts) {
        logMfaResetWarn(logger, userName ?? "", failedAttempts, null);
    }
}