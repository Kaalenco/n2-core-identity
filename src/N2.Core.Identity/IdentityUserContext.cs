using System.Globalization;
using System.Security.Claims;

namespace N2.Core.Identity;

public sealed class IdentityUserContext : IUserContext
{
    private readonly ClaimsPrincipal user;
    private List<UserAlert> alerts = new();
    internal Action<UserAlert>? AlertAction { get; set; }

    // tenantId → (tenantName, roles)
    private readonly Dictionary<Guid, (string Name, IReadOnlyList<string> Roles)> tenants;
    private Guid currentTenantId = Guid.Empty;

    internal IdentityUserContext(ClaimsPrincipal user)
    {
        this.user = user;
        PublicId = Guid.Parse(user.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? AnonymousUserId);
        UserName = user.FindFirst(ClaimTypes.Name)?.Value ?? "Anonymous";
        Description = user.FindFirst(ClaimTypes.GivenName)?.Value ?? string.Empty;
        Name = user.FindFirst(ClaimTypes.Surname)?.Value ?? string.Empty;
        PhoneNumber = user.FindFirst(ClaimTypes.MobilePhone)?.Value ?? string.Empty;
        Email = user.FindFirst(ClaimTypes.Email)?.Value ?? "noreply@mydomain.com";

        tenants = BuildTenantIndex(user.Claims);
    }

    private static Dictionary<Guid, (string Name, IReadOnlyList<string> Roles)> BuildTenantIndex(
        IEnumerable<Claim> claims)
    {
        var claimList = claims.ToList();

        var names = claimList
            .Where(c => c.Type == N2ClaimTypes.TenantMembership)
            .Select(c => ParseClaim(c.Value))
            .Where(t => t.id != Guid.Empty)
            .ToDictionary(t => t.id, t => t.value);

        var rolesByTenant = claimList
            .Where(c => c.Type == N2ClaimTypes.TenantRole)
            .Select(c => ParseClaim(c.Value))
            .Where(t => t.id != Guid.Empty)
            .GroupBy(t => t.id)
            .ToDictionary(g => g.Key, g => (IReadOnlyList<string>)g.Select(t => t.value).ToList());

        return names.ToDictionary(
            kvp => kvp.Key,
            kvp => (kvp.Value, rolesByTenant.TryGetValue(kvp.Key, out var r) ? r : (IReadOnlyList<string>)[]));
    }

    /// <summary>Splits a <c>{guid}:{value}</c> claim into its parts.</summary>
    private static (Guid id, string value) ParseClaim(string claimValue)
    {
        var sep = claimValue.IndexOf(':', StringComparison.Ordinal);
        if (sep < 0) return (Guid.Empty, string.Empty);
        return Guid.TryParse(claimValue[..sep], out var id)
            ? (id, claimValue[(sep + 1)..])
            : (Guid.Empty, string.Empty);
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

    // -------------------------------------------------------------------------
    // Tenant context
    // -------------------------------------------------------------------------

    public Guid CurrentTenantId => currentTenantId;

    public string CurrentTenantName =>
        currentTenantId != Guid.Empty && tenants.TryGetValue(currentTenantId, out var t)
            ? t.Name
            : string.Empty;

    public bool SetTenantContext(Guid tenantId)
    {
        if (!tenants.ContainsKey(tenantId)) return false;
        currentTenantId = tenantId;
        return true;
    }

    public bool SetTenantContext(string tenantName)
    {
        var match = tenants.FirstOrDefault(kvp =>
            string.Equals(kvp.Value.Name, tenantName, StringComparison.OrdinalIgnoreCase));
        if (match.Key == Guid.Empty && !tenants.ContainsKey(Guid.Empty)) return false;
        currentTenantId = match.Key;
        return true;
    }

    public bool IsInTenant(Guid tenantId) => tenants.ContainsKey(tenantId);

    public bool IsInTenant(string tenantName) =>
        tenants.Any(kvp => string.Equals(kvp.Value.Name, tenantName, StringComparison.OrdinalIgnoreCase));

    public IEnumerable<(Guid TenantId, string TenantName, IReadOnlyList<string> Roles)> TenantMemberships =>
        tenants.Select(kvp => (kvp.Key, kvp.Value.Name, kvp.Value.Roles));

    // -------------------------------------------------------------------------
    // Role checks — all strictly scoped to the active tenant
    // -------------------------------------------------------------------------

    public IEnumerable<string> CurrentRoles()
    {
        if (currentTenantId == Guid.Empty) return [];
        return tenants.TryGetValue(currentTenantId, out var t) ? t.Roles : [];
    }

    public bool IsInRole(string role)
    {
        if (currentTenantId == Guid.Empty) return false;
        return tenants.TryGetValue(currentTenantId, out var t) &&
               t.Roles.Any(r => string.Equals(r, role, StringComparison.OrdinalIgnoreCase));
    }

    public bool IsAdmin() => IsInRole(SystemRoles.Admin);
    public bool CanPublish() => IsInRole(SystemRoles.Admin) || IsInRole(SystemRoles.Publisher);
    public bool CanModifyRights() => IsInRole(SystemRoles.Admin) || IsInRole(SystemRoles.AuthManager);
    public bool CanDesign() => IsInRole(SystemRoles.Admin) || IsInRole(SystemRoles.Designer);

    // -------------------------------------------------------------------------
    // Alerts and policies
    // -------------------------------------------------------------------------

    public void Alert(string message, Priority priority)
    {
        var alert = new UserAlert(message, priority);
        AlertAction?.Invoke(alert);
        alerts.Add(alert);
    }

    public bool HasPolicy(string policy) =>
        user.Claims.Any(m => m.ValueType == $"http://schemas.xmlsoap.org/ws/2005/05/identity/policy/{policy}");

    public T? PolicyValue<T>(string policy)
    {
        var claim = user.Claims.FirstOrDefault(
            m => m.ValueType == $"http://schemas.xmlsoap.org/ws/2005/05/identity/policy/{policy}");
        if (claim == null) return default;
        return (T)Convert.ChangeType(claim.Value, typeof(T), CultureInfo.InvariantCulture);
    }
}
