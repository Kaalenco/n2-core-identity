using System.Globalization;
using System.Security.Claims;

namespace N2.Core.Identity;

public sealed class IdentityUserContext : IUserContext
{
    private readonly ClaimsPrincipal user;
    private List<UserAlert> alerts = new();
    internal Action<UserAlert>? AlertAction { get; set; }

    internal IdentityUserContext(ClaimsPrincipal user)
    {
        this.user = user;
        PublicId = Guid.Parse(user.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? AnonymousUserId);
        UserName = user.FindFirst(ClaimTypes.Name)?.Value ?? "Anonymous";
        Description = user.FindFirst(ClaimTypes.GivenName)?.Value ?? string.Empty;
        Name = user.FindFirst(ClaimTypes.Surname)?.Value ?? string.Empty;
        PhoneNumber = user.FindFirst(ClaimTypes.MobilePhone)?.Value ?? string.Empty;
        Email = user.FindFirst(ClaimTypes.Email)?.Value ?? "noreply@mydomain.com";
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
    public Guid PublicId { get; }
    public string Name { get; } = string.Empty;
    public string UserName { get; } = string.Empty;
    public string Description { get; } = string.Empty;
    public string PhoneNumber { get; } = string.Empty;
    public string Email { get; } = string.Empty;
    public IEnumerable<UserAlert> Alerts => alerts;
    public string? ProfileImagePath { get; }
    public string? ProfileThumbnailPath { get; }
    public string? ProfileBackgroundImagePath { get; }
    public int PrimaryPartitionKey { get; }

    public bool CanPublish() => user.CanPublish();

    public bool CanModifyRights() => user.CanModifyRights();

    public bool CanDesign() => user.CanDesign();

    public void Alert(string message, Priority priority)
    {
        var alert = new UserAlert(message, priority);
        AlertAction?.Invoke(alert);
        alerts.Add(alert);
    }

    public IEnumerable<string> CurrentRoles() {
        var result = user.Claims
            .Where(m => m.Type == ClaimTypes.Role)
            .Select(m => m.Value)
            .Where(r => SystemRolesSet.Contains(r))
            .ToList();
        return result;
    }

    public bool IsAdmin() => user.IsInRole(SystemRoles.Admin);
    public bool IsInRole(string role) => user.IsInRole(role);
    public bool HasPolicy(string policy) => user.Claims.Any(m => m.ValueType == $"http://schemas.xmlsoap.org/ws/2005/05/identity/policy/{policy}");
    public T? PolicyValue<T>(string policy)
    {
        var claim = user.Claims.FirstOrDefault(m => m.ValueType == $"http://schemas.xmlsoap.org/ws/2005/05/identity/policy/{policy}");
        if (claim == null)
        {
            return default;
        }

        return (T)Convert.ChangeType(claim.Value, typeof(T), CultureInfo.InvariantCulture);
    }
}