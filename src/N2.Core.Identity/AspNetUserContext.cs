namespace N2.Core.Identity;

public class AspNetUserContext : IUserContext
{
    private readonly string[] roles;
    private readonly bool isAuthenticated;

    public AspNetUserContext(IIdentityUser user, IList<string> roles)
    {
        this.roles = [.. roles];
        if (user != null)
        {
            isAuthenticated = true;
            PublicId = user.Id;
            UserName = user.UserName ?? string.Empty;
            Description = user.DisplayName ?? user.Email ?? string.Empty;
            PhoneNumber = user.PhoneNumber ?? string.Empty;
            Email = user.Email ?? string.Empty;
            Name = user.UserName ?? user.Email ?? string.Empty;
        }
        else
        {
            UserName = "anonymous";
            Name = "anonymous";
            Description = string.Empty;
            PhoneNumber = string.Empty;
            Email = string.Empty;
        }
    }

    private readonly List<UserAlert> alerts = new();
    public Guid PublicId { get; private set; }
    public string UserName { get; private set; }

    public bool IsAuthenticated => isAuthenticated;

    public string Description { get; private set; }
    public string PhoneNumber { get; private set; }
    public string Email { get; private set; }
    public IEnumerable<UserAlert> Alerts => alerts;

    public string Name { get; private set; }
    public string? ProfileImagePath { get; }
    public string? ProfileThumbnailPath { get; }
    public string? ProfileBackgroundImagePath { get; }
    public int PrimaryPartitionKey { get; }

    public void Alert(string message, Priority priority) => throw new NotImplementedException();

    public bool CanDesign()
    {
        return roles.Contains(SystemRoles.Designer) || roles.Contains(SystemRoles.Admin);
    }

    public bool CanModifyRights() => roles.Contains(SystemRoles.Admin) || roles.Contains(SystemRoles.AuthManager);

    public bool CanPublish() => roles.Contains(SystemRoles.Admin) || roles.Contains(SystemRoles.Publisher);

    public IEnumerable<string> CurrentRoles() => roles;
    public bool IsAdmin() => roles.Contains(SystemRoles.Admin);
    public bool IsInRole(string role) => roles.Contains(role);
    public bool HasPolicy(string policy) => throw new NotImplementedException();
    public T? PolicyValue<T>(string policy) => throw new NotImplementedException();
}