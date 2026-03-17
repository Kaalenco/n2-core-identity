using N2.Core.Commands;
using N2.Core.Identity.Data;

using System.Diagnostics.CodeAnalysis;

namespace N2.Core.Identity.Services;

/// <summary>
/// This is the interface for managing tenants in the identity system. It provides methods for creating, updating, and deleting tenants.
/// It is not for authentication or user management, which are handled by <c>IUserManager</c> and related interfaces. In this
/// interface if for creating and managing tenants and for assigning and removing users from tenants.
/// It is intentionally separate from user management to allow for different implementations and to keep concerns separated.
/// </summary>
public interface ITenantManager
{
    // -------------------------------------------------------------------------
    // Tenant lifecycle
    // -------------------------------------------------------------------------

    /// <summary>Creates a new tenant.</summary>
    /// <param name="tenant">The tenant to create.</param>
    /// <param name="token">Cancellation token.</param>
    Task<ICommandResponse> CreateAsync([NotNull] ApplicationTenant tenant, CancellationToken token);

    /// <summary>Deletes a tenant and removes all user-tenant associations.</summary>
    /// <param name="tenant">The tenant to delete.</param>
    /// <param name="token">Cancellation token.</param>
    Task<ICommandResponse> DeleteAsync([NotNull] ApplicationTenant tenant, CancellationToken token);

    /// <summary>Updates mutable tenant properties (name, contact info, image path, etc.).</summary>
    /// <param name="tenant">The tenant with updated values.</param>
    /// <param name="token">Cancellation token.</param>
    Task<ICommandResponse> UpdateAsync([NotNull] ApplicationTenant tenant, CancellationToken token);

    // -------------------------------------------------------------------------
    // Tenant lookup
    // -------------------------------------------------------------------------

    /// <summary>Finds a tenant by its unique identifier.</summary>
    Task<ApplicationTenant?> FindByIdAsync(Guid tenantId, CancellationToken token);

    /// <summary>Finds a tenant by name. The value is normalised internally before lookup.</summary>
    Task<ApplicationTenant?> FindByNameAsync(string name, CancellationToken token);

    /// <summary>Finds a tenant by admin e-mail address. The value is normalised internally before lookup.</summary>
    Task<ApplicationTenant?> FindByEmailAsync(string email, CancellationToken token);

    /// <summary>Returns a select list of all active tenants suitable for UI rendering.</summary>
    Task<SelectItemList<UserSelectItem>> GetTenantsAsync(CancellationToken token);

    // -------------------------------------------------------------------------
    // Tenant status
    // -------------------------------------------------------------------------

    /// <summary>Locks a tenant, preventing all its users from signing in.</summary>
    Task<ICommandResponse> LockAsync([NotNull] ApplicationTenant tenant, CancellationToken token);

    /// <summary>Unlocks a previously locked tenant.</summary>
    Task<ICommandResponse> UnlockAsync([NotNull] ApplicationTenant tenant, CancellationToken token);

    // -------------------------------------------------------------------------
    // User–tenant membership
    // -------------------------------------------------------------------------

    /// <summary>Assigns a user to a tenant.</summary>
    /// <param name="user">The user to assign.</param>
    /// <param name="tenant">The target tenant.</param>
    /// <param name="token">Cancellation token.</param>
    Task<ICommandResponse> AddUserAsync([NotNull] ApplicationUser user, [NotNull] ApplicationTenant tenant, CancellationToken token);

    /// <summary>Removes a user from a tenant.</summary>
    /// <param name="user">The user to remove.</param>
    /// <param name="tenant">The tenant to remove the user from.</param>
    /// <param name="token">Cancellation token.</param>
    Task<ICommandResponse> RemoveUserAsync([NotNull] ApplicationUser user, [NotNull] ApplicationTenant tenant, CancellationToken token);

    /// <summary>Returns the normalised usernames of all users belonging to the given tenant.</summary>
    Task<IEnumerable<string>> GetUsersForTenantAsync(Guid tenantId, CancellationToken token);

    /// <summary>Returns the tenant IDs that the given user belongs to.</summary>
    Task<IEnumerable<Guid>> GetTenantIdsForUserAsync(Guid userId, CancellationToken token);

    /// <summary>
    /// Checks whether the given user is allowed to sign in within the context of the given tenant.
    /// Returns <c>false</c> if either the user or the tenant is locked or removed.
    /// </summary>
    Task<bool> ApplicationUserCanSignIn(Guid userId, Guid tenantId, CancellationToken token);

}

