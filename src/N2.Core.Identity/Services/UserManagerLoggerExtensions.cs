using Microsoft.Extensions.Logging;

namespace N2.Core.Identity.Services;

public static class UserManagerLoggerExtensions {

    private static readonly Action<ILogger, string, int, DateTimeOffset?, Exception?> logIncrementAccessFailedCount =
        LoggerMessage.Define<string, int, DateTimeOffset?>(
            LogLevel.Warning,
            new EventId(4, nameof(LogIncrementAccessFailedCount)),
            "Account locked for user {UserName} after {FailedAttempts} failed attempts. Lockout until {LockoutEnd}"
        );

    public static void LogIncrementAccessFailedCount(this ILogger logger, string userName, int failedAttemps, DateTimeOffset? lockoutEnd) {
        logIncrementAccessFailedCount(logger, userName, failedAttemps, lockoutEnd, null);
    }

    private static readonly Action<ILogger, string, Exception?> logIncrementAccessFailedException =
        LoggerMessage.Define<string>(
            LogLevel.Critical,
            new EventId(6, nameof(LogIncrementAccessFailedException)),
            "Error incrementing access failed count for user {UserName}."
        );
    public static void LogIncrementAccessFailedException(this ILogger logger, string userName, Exception ex) {
        logIncrementAccessFailedException(logger, userName, ex);
    }

    private static readonly Action<ILogger, string, Exception?> logMfaSecretNotSet =
        LoggerMessage.Define<string>(
            LogLevel.Critical,
            new EventId(1, nameof(LogMfaSecretNotSet)),
            "MfaSecret is not set for user {UserName}.");

    public static void LogMfaSecretNotSet(this ILogger logger, string userName) {
        logMfaSecretNotSet(logger, userName, null);
    }

    private static readonly Action<ILogger, string, string, string, Exception?> logMfaVerificationWarning =
        LoggerMessage.Define<string, string, string>(
            LogLevel.Warning,
            new EventId(2, nameof(LogMfaVerificationWarning)),
            "Error {Message} while verifying MFA token [{MultifactorCode}] for user [{UserName}].");

    public static void LogMfaVerificationWarning(this ILogger logger, string message, string mfaCode, string userName, Exception ex) {
        logMfaVerificationWarning(logger, message, mfaCode, userName, ex);
    }

    private static readonly Action<ILogger, string, Exception?> logResetAccessCountFailure =
        LoggerMessage.Define<string>(
            LogLevel.Critical,
            new EventId(5, nameof(LogResetAccessCountFailure)),
            "Resetting access failed count for user {UserName}.");

    public static void LogResetAccessCountFailure(this ILogger logger, string userName, Exception ex) {
        logResetAccessCountFailure(logger, userName, ex);
    }

    // Add this LoggerMessage delegate near other LoggerMessage delegates
    private static readonly Action<ILogger, string, int, Exception?> logResetAccessFailedCount =
        LoggerMessage.Define<string, int>(
            LogLevel.Warning,
            new EventId(3, nameof(LogResetAccessFailedCount)),
            "Resetting access failed count for user {UserName} (was {FailedCount}).");

    public static void LogResetAccessFailedCount(this ILogger logger, string userName, int failedCount) {
        logResetAccessFailedCount(logger, userName, failedCount, null);
    }

    private static readonly Action<ILogger, string, DateTimeOffset?, double, Exception?> logUserLockedOut =
         LoggerMessage.Define<string, DateTimeOffset?, double>(
                LogLevel.Warning,
                new EventId(7, nameof(LogUserLockedOut)),
                "Authentication attempt blocked - user {UserName} is locked out until {LockoutEnd} ({RemainingMinutes} minutes remaining)."
            );
    public static void LogUserLockedOut(this ILogger logger, string userName, DateTimeOffset? lockoutEnd, double remainingMinutes) {
        logUserLockedOut(logger, userName, lockoutEnd, remainingMinutes, null);
    }
}

