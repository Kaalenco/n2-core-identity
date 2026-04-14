using Microsoft.Extensions.DependencyInjection;

using N2.Core.Commands;
using N2.Core.Identity.Data;
using N2.Core.Identity.Services;

namespace N2.Core.Identity.UnitTests;

public abstract class N2IdentityTestsBase {
    private readonly ServiceProvider _serviceProvider;
    protected ServiceProvider ServiceProvider => _serviceProvider;

    protected N2IdentityTestsBase() {
        ServiceCollection serviceCollection = new();
        TestContext.ConfigureServices(serviceCollection);
        _serviceProvider = serviceCollection.BuildServiceProvider();
    }

    protected IAuthenticator GetAuthenticator() => ServiceProvider.GetRequiredService<IAuthenticator>();
    protected IUserManager<ApplicationUser> GetUserManager() => ServiceProvider.GetRequiredService<IUserManager<ApplicationUser>>();
    protected AuthenticationConfig GetAuthenticationConfig() => ServiceProvider.GetAuthenticationConfig();

    /// <summary>
    /// Decrypts an <see cref="ApplicationUser.MfaSecret"/> value using the configured
    /// <c>MfaTokenSecret</c> (with <c>MfaTokenSecret2</c> as fallback for key rollover).
    /// </summary>
    protected string? DecryptMfaSecret(string? encryptedSecret) {
        var config = GetAuthenticationConfig();
        return MfaSecretEncryption.TryDecrypt(encryptedSecret, config.MfaTokenSecret, config.MfaTokenSecret2);
    }
    protected Task<IIdentityContext> GetIdentityContext() {
        var factory = ServiceProvider.GetRequiredService<IIdentityContextFactory>();
        return factory.CreateAsync();
    }

    protected async Task<ApplicationUser> CreateTestUser(string userName, string password, MultiFactorType mfaType) {
        CancellationToken ct = new();

        var userManager = GetUserManager();

        // Create user
        ApplicationUser user = new() {
            UserName = userName,
            Email = $"{userName}@test.com",
            MfaType = mfaType
        };

        var createResult = await userManager.CreateAsync(user, password, ct);
        if (!createResult.Status.IsSuccess()) {
            throw new InvalidOperationException($"Failed to create user: {createResult.Message}");
        }

        // Retrieve the created user
        var userResponse = await userManager.FindByNameAsync(userName, ct);
        if (userResponse.Value == null) {
            throw new InvalidOperationException("Failed to retrieve created user.");
        }

        var createdUser = userResponse.Value;

        if (mfaType != MultiFactorType.None) {
            // Generate and confirm email to allow sign-in
            await userManager.SetMultifactorAsync(createdUser, mfaType, "token", CancellationToken.None);

            var tokenResponse = await userManager.GenerateConfirmationTokenAsync(createdUser, ct);
            if (!tokenResponse.Status.IsSuccess() || string.IsNullOrEmpty(tokenResponse.Value)) {
                throw new InvalidOperationException("Failed to generate confirmation token.");
            }

            var confirmResult = await userManager.ConfirmEmailAsync(createdUser, tokenResponse.Value, ct);
            if (!confirmResult.Status.IsSuccess()) {
                throw new InvalidOperationException($"Failed to confirm email: {confirmResult.Message}");
            }

            // Retrieve user again to get updated EmailConfirmed status
            userResponse = await userManager.FindByNameAsync(userName, ct);
            if (userResponse.Value == null) {
                throw new InvalidOperationException("Failed to retrieve user after email confirmation.");
            }
        }

        return userResponse.Value;
    }
}
