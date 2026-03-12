using Microsoft.Extensions.Logging;

namespace N2.Core.Identity.Data;

public static class N2IdentityContextLoggingExtensions {

    private static readonly Action<ILogger, string, Exception?> logAddApplicationRoleFail =
        LoggerMessage.Define<string>(
        LogLevel.Warning,
        new EventId(1, nameof(LogAddApplicationRoleFailed)),
        "AddApplicationRoleAsync failed with {Message}");

    private static readonly Action<ILogger, string, Exception?> logAddApplicationUserFail =
        LoggerMessage.Define<string>(
        LogLevel.Warning,
        new EventId(2, nameof(LogAddApplicationUserFailed)),
        "AddApplicationUserAsync failed with {Message}");

    private static readonly Action<ILogger, string, Exception?> logAddIdentityUserRoleFail =
        LoggerMessage.Define<string>(
        LogLevel.Warning,
        new EventId(3, nameof(LogAddIdentityUserRoleFailed)),
        "AddApplicationRoleAsync failed with {Message}");

    private static readonly Action<ILogger, string, Exception?> logAddIdentityUserTenantFail =
        LoggerMessage.Define<string>(
        LogLevel.Warning,
        new EventId(4, nameof(LogAddIdentityUserTenantFailed)),
        "AddIdentityUserTenantAsync failed with {Message}");
    

    private static readonly Action<ILogger, string, Exception?> logHealthStatusFail =
        LoggerMessage.Define<string>(
        LogLevel.Warning,
        new EventId(5, nameof(LogHealthStatusFailed)),
        "Health Status failed with exception: {Message}");


    public static void LogAddApplicationRoleFailed(this ILogger logger, string message, Exception? exception) {
        logAddApplicationRoleFail(logger, message, exception);
    }

    public static void LogAddApplicationUserFailed(this ILogger logger, string message, Exception? exception) {
        logAddApplicationUserFail(logger, message, exception);
    }

    public static void LogAddIdentityUserRoleFailed(this ILogger logger, string message, Exception? exception) {
        logAddIdentityUserRoleFail(logger, message, exception);
    }

    public static void LogAddIdentityUserTenantFailed(this ILogger logger, string message, Exception? exception) {
        logAddIdentityUserTenantFail(logger, message, exception);
    }

    public static void LogHealthStatusFailed(this ILogger logger, string message, Exception? exception) {
        logHealthStatusFail(logger, message, exception);
    }

}