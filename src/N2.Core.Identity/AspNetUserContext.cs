namespace N2.Core.Identity;

public class AspNetUserContext : IUserContext
{
    private readonly IIdentityUser user;
    private readonly string[] roles;

    public AspNetUserContext(IIdentityUser user, IList<string> roles)
    {
        this.user = user;
        this.roles = roles.ToArray();
    }

    private readonly List<UserAlert> alerts = new();
    public Guid UserId => user.Id;
    public string UserName => user.UserName ?? user.Email ?? string.Empty;

#pragma warning disable CA1822 // this is a false positive
    public bool IsAuthenticated => roles.Length > 0;

    public string UserDescription => user.DisplayName ?? user.Email ?? string.Empty;
    public string UserPhone => user.PhoneNumber ?? string.Empty;
    public string UserEmail => user.Email ?? string.Empty;
    public IEnumerable<UserAlert> Alerts => alerts;

    public void Alert(string message, Priority priority) => throw new NotImplementedException();

    public bool CanDesign()
    {
        return roles.Contains(SystemRoles.Designer) || roles.Contains(SystemRoles.Admin);
    }

    public bool CanModifyRights() => throw new NotImplementedException();

    public bool CanPublish() => throw new NotImplementedException();

    public IEnumerable<string> CurrentRoles() => roles;
}