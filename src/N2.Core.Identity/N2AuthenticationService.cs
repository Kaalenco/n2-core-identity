using Microsoft.Extensions.Logging;

using N2.Core.Commands;
using N2.Core.Identity.Data;

namespace N2.Core.Identity;

public sealed class N2AuthenticationService : IAuthenticator
{
    private readonly IUserManager<ApplicationUser> userManager;
    private readonly ILogger<N2AuthenticationService> logger;

    public N2AuthenticationService(
        IUserManager<ApplicationUser> userManager,
        ILogger<N2AuthenticationService> logger)
    {
        this.userManager = userManager;
        this.logger = logger;
    }

    public async Task<IUserContext?> AuthenticateAsync(IUserLogin userLogin)
    {
        ArgumentNullException.ThrowIfNull(userLogin);
        ArgumentException.ThrowIfNullOrEmpty(userLogin.Username);
        ArgumentException.ThrowIfNullOrEmpty(userLogin.Password);

        CancellationToken token = new();

        ICommandResponse<ApplicationUser> userResponse = await userManager.FindByNameAsync(userLogin.Username, token);
        ApplicationUser? user = userResponse.Value;
        if (user == null)
        {
            LoginAttempt(logger, userLogin.Username, userNotFoundException);
            return null;
        }

        ICommandResponse result = await userManager.ValidateAsync(user, userLogin.Password, token);
        if (result == null)
        {
            LoginAttempt(logger, userLogin.Username, unexpectedResult);
            return null;
        }
        if (!result.Status.IsSuccess())
        {
            LoginAttempt(logger, userLogin.Username, loginFailed);
            return null;
        }

        if (!await userManager.CanSignInAsync(user, token))
        {
            LoginAttempt(logger, userLogin.Username, userLockedOutException);
            return null;
        }

        IListResponse<string> roles = await userManager.GetRolesAsync(user, token);
        if (roles == null || roles.Value == null || roles.Value.Count == 0)
        {
            return new AspNetUserContext(user, []);
        }
        return new AspNetUserContext(user, [.. roles.Value]);
    }

    private static readonly AuthenticationException userNotFoundException = new("Login attempt with invalid username.");
    private static readonly AuthenticationException userLockedOutException = new("User is locked out.");
    private static readonly AuthenticationException unexpectedResult = new("No result from sign in manager.");
    private static readonly AuthenticationException loginFailed = new("Could not login user.");

    private static readonly Action<ILogger, string, Exception> LoginAttempt = LoggerMessage.Define<string>(
            LogLevel.Warning,
            new EventId(13, nameof(LoginAttempt)),
            "Login attempt failed: {Message}");
}