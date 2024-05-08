using System.Security.Claims;

namespace N2.Core.Identity;

public sealed class IdentityUserContext : IUserContext
{
    private readonly ClaimsPrincipal user;

    internal IdentityUserContext(ClaimsPrincipal user)
    {
        this.user = user;
        UserId = Guid.Parse(user.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? AnonymousUserId);
        UserName = user.FindFirst(ClaimTypes.Name)?.Value ?? "Anonymous";
        UserDescription = user.FindFirst(ClaimTypes.GivenName)?.Value ?? string.Empty;
        UserPhone = user.FindFirst(ClaimTypes.MobilePhone)?.Value ?? string.Empty;
        UserEmail = user.FindFirst(ClaimTypes.Email)?.Value ?? "noreply@mydomain.com";
    }

    public static string[] SystemRolesSet => [
        SystemRoles.SysAdmin,
        SystemRoles.Admin,
        SystemRoles.Application,
        SystemRoles.AuthManager,
        SystemRoles.Publisher,
        SystemRoles.Designer,
        SystemRoles.User,
        SystemRoles.Visitor,
    ];

    public const string AnonymousUserId = "00000000-0000-0000-0000-000000000000";
    public bool IsAuthenticated => user?.Identity?.IsAuthenticated ?? false;
    public Guid UserId { get; }
    public string UserName { get; } = string.Empty;
    public string UserDescription { get; } = string.Empty;
    public string UserPhone { get; } = string.Empty;
    public string UserEmail { get; } = string.Empty;
    public IEnumerable<UserAlert> Alerts { get; } = new List<UserAlert>();

    public bool CanPublish() => user.CanPublish();

    public bool CanModifyRights() => user.CanModifyRights();

    public bool CanDesign() => user.CanDesign();

    public void Alert(string message, Priority priority) => throw new NotImplementedException();

    public IEnumerable<string> CurrentRoles() => throw new NotImplementedException();
}