namespace N2.Core.Identity;

/// <summary>
/// Custom JWT claim type URIs used by this library.
/// These are distinct from the standard <see cref="System.Security.Claims.ClaimTypes"/> to avoid
/// collisions and to make the purpose explicit in token payloads.
/// </summary>
public static class N2ClaimTypes
{
    /// <summary>
    /// Encodes one tenant the user belongs to. The claim value is <c>{tenantId}:{tenantName}</c>.
    /// One claim per tenant membership.
    /// </summary>
    public const string TenantMembership = "urn:n2:tenant";

    /// <summary>
    /// Encodes one role the user holds within a specific tenant.
    /// The claim value is <c>{tenantId}:{roleName}</c>.
    /// One claim per tenant-role pair.
    /// </summary>
    public const string TenantRole = "urn:n2:tenant_role";
}
