namespace N2.Core.Identity;

public class AspNetUserContext : IUserContext
{
    // tenantId → (tenantName, roles)
    private readonly Dictionary<Guid, (string Name, IReadOnlyList<string> Roles)> tenants;
    private Guid currentTenantId = Guid.Empty;

    private readonly bool isAuthenticated;
    private Action<UserAlert>? AlertAction { get; }

    public AspNetUserContext(
        IIdentityUser user,
        IList<(Guid TenantId, string TenantName, IReadOnlyList<string> Roles)> tenantMemberships,
        IList<UserAlert> alerts,
        Action<UserAlert>? alertAction)
    {
        tenants = tenantMemberships.ToDictionary(t => t.TenantId, t => (t.TenantName, t.Roles));
        this.alerts = [.. alerts];
        AlertAction = alertAction;

        if (user != null)
        {
            isAuthenticated = true;
            PublicId = user.Id;
            UserName = user.UserName ?? string.Empty;
            Description = user.DisplayName ?? user.Email ?? string.Empty;
            PhoneNumber = user.PhoneNumber ?? string.Empty;
            Email = user.Email ?? string.Empty;
            Name = user.UserName ?? user.Email ?? string.Empty;
            SecurityStamp = (user as Data.ApplicationUser)?.SecurityStamp;
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

    private readonly List<UserAlert> alerts = [];
    public Guid PublicId { get; private set; }
    public string UserName { get; private set; }
    public bool IsAuthenticated => isAuthenticated;
    public string Description { get; private set; }
    public string PhoneNumber { get; private set; }
    public string Email { get; private set; }
    public IEnumerable<UserAlert> Alerts => alerts;
    public string Name { get; private set; }
    public string? SecurityStamp { get; }
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

    public bool HasPolicy(string policy) => throw new NotImplementedException();
    public T? PolicyValue<T>(string policy) => throw new NotImplementedException();
}
