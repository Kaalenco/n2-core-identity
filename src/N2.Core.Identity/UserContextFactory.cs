using Microsoft.AspNetCore.Components.Authorization;
using System.Security.Claims;

namespace N2.Core.Identity;

public sealed class UserContextFactory : IUserContextFactory
{
    private readonly AuthenticationStateProvider authenticationStateProvider;
    private IdentityUserContext? identityUserContext;
    private readonly object syncRoot = new object();
    public bool Initializing { get; private set; }
    public bool Initialized { get; private set; }

    public UserContextFactory(AuthenticationStateProvider authenticationStateProvider)
    {
        this.authenticationStateProvider = authenticationStateProvider;
        Initializing = false;
        Initialized = false;
    }

    public async Task<IUserContext> CreateAsync()
    {
        var timeOut = 10000;
        IUserContext? result = await UserContextInitAsync();
        if (result != null)
        {
            return result;
        }
        while (result == null && timeOut > 0)
        {
            result = await UserContextInitAsync();
            await Task.Delay(100);
            timeOut -= 100;
        }
        if (result == null)
        {
            throw new TimeoutException("Could not get a user context withing the alloted time");
        }

        return result;
    }

    public async Task<IUserContext?> UserContextInitAsync()
    {
        if (identityUserContext != null)
        {
            return identityUserContext;
        }

        lock (syncRoot)
        {
            if (Initializing)
            {
                return null;
            }

            Initializing = true;
        }

        if (authenticationStateProvider == null)
        {
            identityUserContext = new IdentityUserContext(new ClaimsPrincipal(new ClaimsIdentity()));
        }
        else
        {
            var state = await authenticationStateProvider.GetAuthenticationStateAsync();
            identityUserContext = new IdentityUserContext(state.User);
        }

        lock (syncRoot)
        {
            Initializing = false;
            Initialized = true;
        }
        return identityUserContext;
    }
}