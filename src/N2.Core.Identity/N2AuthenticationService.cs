using Microsoft.Extensions.Logging;

using N2.Core.Commands;
using N2.Core.Identity.Data;
using N2.Core.Identity.Services;

namespace N2.Core.Identity;

public sealed class N2AuthenticationService : IAuthenticator {
    private readonly IUserManager<ApplicationUser> userManager;
    private readonly ILogger<N2AuthenticationService> logger;

    // This is the amount of time we want to take for the authentication process, regardless of success or failure,
    // to mitigate timing attacks for user enumeration and password guessing.
    // It should not be too long to cause a poor user experience, but long enough to make brute-force attacks less feasible.
    // 500ms is a common choice for this kind of delay, but it can be adjusted based on the expected load
    // and security requirements of the application. A value of 200 is too short and may not provide sufficient protection,
    // while a value of 1000 may be unnecessarily long for users with valid credentials.
    private const int TimeForAuthenticationMs = 500;
    private const int AlertStorageTimeoutMs = 500;

    public N2AuthenticationService(
        IUserManager<ApplicationUser> userManager,
        ILogger<N2AuthenticationService> logger) {
        this.userManager = userManager;
        this.logger = logger;
    }

    // IAuthenticator does not expose a CancellationToken parameter; use the overload below
    // when calling the concrete type directly so the HTTP request token is honoured.
    public Task<IUserContext?> AuthenticateAsync(IUserLogin userLogin) =>
        AuthenticateAsync(userLogin, CancellationToken.None);

    public async Task<IUserContext?> AuthenticateAsync(IUserLogin userLogin, CancellationToken cancellationToken) {
        ArgumentNullException.ThrowIfNull(userLogin);
        ArgumentException.ThrowIfNullOrEmpty(userLogin.Username);
        ArgumentException.ThrowIfNullOrEmpty(userLogin.Password);

        var timer = new TimeoutTimer(TimeForAuthenticationMs);

        var userResponse = await userManager.FindByNameAsync(userLogin.Username, cancellationToken);
        var user = userResponse.Value;
        ICommandResponse? result = null;
        if (user == null) {
            LoginAttempt(logger, userLogin.Username, userNotFoundException);
            await timer.Wait();
            return null;
        }

        result = await userManager.ValidateAsync(user, userLogin.Password, cancellationToken);
        if (result == null) {
            LoginAttempt(logger, userLogin.Username, unexpectedResult);
            await timer.Wait();
            return null;
        }
        if (!result.Status.IsSuccess()) {
            if (result.Status == ResponseStatus.Locked) {
                LoginAttempt(logger, userLogin.Username, accountLocked);
            } else {
                LoginAttempt(logger, userLogin.Username, loginFailed);
            }
            await timer.Wait();

            return null;
        }

        if (!await userManager.CanSignInAsync(user, cancellationToken)) {
            LoginAttempt(logger, userLogin.Username, userLockedOutException);
            await timer.Wait();
            return null;
        }

        var alerts = user.ApplicationUserAlert.Select(a => new UserAlert(a.Message, a.Priority)).ToList();

        IList<(Guid TenantId, string TenantName, IReadOnlyList<string> Roles)> memberships = [];
        if (userManager is N2UserManager nm) {
            memberships = await nm.GetTenantMembershipsAsync(user, cancellationToken);
        }
        await timer.Wait();

        return new AspNetUserContext(user, memberships, alerts, (a) => StoreUserAlert(user.Id, a, CancellationToken.None));
    }

    private void StoreUserAlert(Guid userId, UserAlert userAlert, CancellationToken token) {
        if (userManager is N2UserManager ctx) {
            var task = ctx.CreateUserAlert(userId, userAlert, token);
            task.Wait(AlertStorageTimeoutMs, token);
        }
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