using System.Security.Claims;

using Microsoft.AspNetCore.Components.Authorization;

namespace N2.Core.Identity;

public sealed class UserContextFactory : IUserContextFactory
{
    private readonly Lazy<Task<IdentityUserContext>> contextTask;

    public UserContextFactory(AuthenticationStateProvider authenticationStateProvider)
    {
        contextTask = new Lazy<Task<IdentityUserContext>>(
            () => InitializeAsync(authenticationStateProvider));
    }

    public async Task<IUserContext> CreateAsync() => await contextTask.Value;

    private static async Task<IdentityUserContext> InitializeAsync(
        AuthenticationStateProvider? provider)
    {
        if (provider == null)
        {
            return new IdentityUserContext(new ClaimsPrincipal(new ClaimsIdentity()));
        }
        var state = await provider.GetAuthenticationStateAsync();
        return new IdentityUserContext(state.User);
    }
}