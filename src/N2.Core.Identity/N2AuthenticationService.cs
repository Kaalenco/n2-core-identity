using Microsoft.Extensions.Logging;

using N2.Core.Commands;
using N2.Core.Identity.Data;

namespace N2.Core.Identity;

public sealed class N2AuthenticationService : IAuthenticator {
    private readonly IUserManager<ApplicationUser> userManager;
    private readonly ILogger<N2AuthenticationService> logger;

    private const int TimeForAuthenticationMs = 200;

    public N2AuthenticationService(
        IUserManager<ApplicationUser> userManager,
        ILogger<N2AuthenticationService> logger) {
        this.userManager = userManager;
        this.logger = logger;
    }

    public async Task<IUserContext?> AuthenticateAsync(IUserLogin userLogin) {
        ArgumentNullException.ThrowIfNull(userLogin);
        ArgumentException.ThrowIfNullOrEmpty(userLogin.Username);
        ArgumentException.ThrowIfNullOrEmpty(userLogin.Password);

        CancellationToken token = new();

        var timer = new TimeoutTimer(TimeForAuthenticationMs);

        var userResponse = await userManager.FindByNameAsync(userLogin.Username, token);
        var user = userResponse.Value;
        ICommandResponse? result = null;
        if (user == null) {
            LoginAttempt(logger, userLogin.Username, userNotFoundException);
            await timer.Wait();
            return null;
        }

        result = await userManager.ValidateAsync(user, userLogin.Password, token);
        if (result == null) {
            LoginAttempt(logger, userLogin.Username, unexpectedResult);
            await timer.Wait();
            return null;
        }
        if (!result.Status.IsSuccess()) {
            LoginAttempt(logger, userLogin.Username, loginFailed);
            if (result.Status == ResponseStatus.Locked) {
                LoginAttempt(logger, userLogin.Username, accountLocked);
            } else {
                LoginAttempt(logger, userLogin.Username, loginFailed);
            }
            await timer.Wait();

            return null;
        }

        if (!await userManager.CanSignInAsync(user, token)) {
            LoginAttempt(logger, userLogin.Username, userLockedOutException);
            await timer.Wait();
            return null;
        }

        var roles = await userManager.GetRolesAsync(user, token);
        await timer.Wait();

        if (roles == null || roles.Value == null || roles.Value.Count == 0) {
            return new AspNetUserContext(user, []);
        }

        return new AspNetUserContext(user, [.. roles.Value]);
    }

    private static readonly AuthenticationException userNotFoundException = new("Login attempt with invalid username.");
    private static readonly AuthenticationException userLockedOutException = new("User is locked out.");
    private static readonly AuthenticationException unexpectedResult = new("No result from sign in manager.");
    private static readonly AuthenticationException loginFailed = new("Could not login user.");
    private static readonly AuthenticationException accountLocked = new("Account locked.");

    private static readonly Action<ILogger, string, Exception> LoginAttempt = LoggerMessage.Define<string>(
            LogLevel.Warning,
            new EventId(13, nameof(LoginAttempt)),
            "Login attempt failed: {Message}");
}