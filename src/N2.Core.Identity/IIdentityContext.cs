using Microsoft.AspNetCore.Identity;

using N2.Core.Commands;
using N2.Core.Entity;
using N2.Core.Identity.Data;

using System.Data;

using static System.Net.Mime.MediaTypeNames;

namespace N2.Core.Identity;

public interface IIdentityContext : ICoreDataContext, IUnitOfWork
{
    IQueryable<Data.ApplicationDefinition> Application { get; }
    IQueryable<ApplicationSecret> ApplicationSecret { get; }
    int MaxLogSize { get; set; }

    IQueryable<ApplicationRole> Role { get; }

    IQueryable<ApplicationTenant> Tenant { get; }

    Task<ApplicationSecret?> SecretFindRecord(Guid applicationSecretId, CancellationToken ct);
    Task<ApplicationSecret?> SecretFindRecord(string hashedToken, CancellationToken ct);
    void SecretAdd(ApplicationSecret secret);
    void SecretDelete(ApplicationSecret secret);
    Task<SelectItemList<HtmlString>> SecretGetSelectList(Guid ownerId, string ownerType, CancellationToken ct);

    IQueryable<ApplicationUser> User { get; }

    Task<int> UserAlertAdd(ApplicationUserAlert alert, CancellationToken ct);

    IQueryable<IdentityUserRole<Guid>> UserRole { get; }

    IQueryable<ApplicationUserTenant> UserTenant { get; }

    Task<int> ApplicationAdd(ApplicationDefinition application, CancellationToken ct);

    void ApplicationDelete(ApplicationDefinition application);

    Task<ApplicationDefinition?> ApplicationFindRecord(Guid applicationId, CancellationToken ct);

    Task<ApplicationDefinition?> ApplicationFindRecord(Guid tenantId, string name, CancellationToken ct);

    Task<string> ApplicationGetName(Guid applicationId, CancellationToken ct);

    Task<SelectItemList<HtmlString>> ApplicationGetSelectList(Guid tenantId, CancellationToken ct);

    Task<int> RoleAdd(ApplicationRole role, CancellationToken ct);

    void RoleDelete(ApplicationRole role);

    Task<ApplicationRole?> RoleFindRecord(string normalizedName, CancellationToken ct);

    Task<SelectItemList<HtmlString>> RoleGetSelectList(CancellationToken ct);

    Task<int> TenantAdd(ApplicationTenant tenant, CancellationToken ct);

    void TenantDelete(ApplicationTenant tenant);

    Task<ApplicationTenant?> TenantFindRecord(Guid tenantId, CancellationToken ct);

    Task<ApplicationTenant?> TenantFindRecord(string normalizedName, CancellationToken ct);

    Task<ApplicationTenant?> TenantFindRecordByEmail(string normalizedEmail, CancellationToken ct);

    Task<string> TenantGetName(Guid tenantId, CancellationToken ct);

    Task<SelectItemList<UserSelectItem>> TenantGetSelectList(CancellationToken ct);

    Task<IEnumerable<string>> TenantGetUsers(Guid tenantId, CancellationToken ct);

    Task<int> UserAdd(ApplicationUser user, CancellationToken ct);

    Task<bool> UserCanSignIn(Guid userId, CancellationToken ct);

    Task<bool> UserCanSignInTenant(Guid userId, Guid tenantId, CancellationToken ct);

    void UserDelete(ApplicationUser user);

    Task<ICommandResponse<ApplicationUser>> UserFind(string normalizedName, CancellationToken ct);

    Task<ApplicationUser?> UserFindRecord(Guid userId, CancellationToken ct);

    Task<ApplicationUser?> UserFindRecord(string normalizedName, CancellationToken ct);

    Task<ApplicationUser?> UserFindRecordByEmail(string normalizedEmail, CancellationToken ct);

    Task<string> UserGetName(Guid userId, CancellationToken ct);

    Task<IEnumerable<string>> UserGetRoles(Guid userId, CancellationToken ct);

    Task<SelectItemList<UserSelectItem>> UserGetSelectList(CancellationToken ct);
    Task<int> UserRoleAdd(IdentityUserRole<Guid> identityRole, CancellationToken ct);

    void UserRoleDelete(IdentityUserRole<Guid> identityRole);

    Task<IdentityUserRole<Guid>?> UserRoleFindRecord(Guid userId, Guid roleId, CancellationToken ct);

    Task<int> UserTenantAdd(ApplicationUserTenant identityUserTenant, CancellationToken ct);

    void UserTenantDelete(ApplicationUserTenant userTenant);

    /// <summary>Returns <c>true</c> if the user is an admin of the given tenant.</summary>
    Task<bool> UserTenantIsAdmin(Guid userId, Guid tenantId, CancellationToken ct);

    /// <summary>Sets or clears the admin flag on the user's membership row for the given tenant.</summary>
    Task<(ResponseStatus status, string? message)> UserTenantSetAdmin(Guid userId, Guid tenantId, bool isAdmin, CancellationToken ct);

    // ── Refresh tokens ────────────────────────────────────────────────────────

    IQueryable<ApplicationRefreshToken> RefreshToken { get; }

    /// <summary>Looks up a refresh token by its raw value. Returns <c>null</c> when not found.</summary>
    Task<ApplicationRefreshToken?> RefreshTokenFind(string token, CancellationToken ct);

    /// <summary>Adds a new refresh token to the context. Call <see cref="IUnitOfWork.Complete"/> to persist.</summary>
    void RefreshTokenAdd(ApplicationRefreshToken token);

    /// <summary>
    /// Marks a refresh token as revoked. Call <see cref="IUnitOfWork.Complete"/> to persist.
    /// </summary>
    void RefreshTokenRevoke(ApplicationRefreshToken token);

    /// <summary>Removes all expired and revoked tokens for <paramref name="userId"/>.</summary>
    Task<int> RefreshTokenPurgeStale(Guid userId, CancellationToken ct);

    /// <summary>
    /// Asynchronously removes all expired refresh tokens from the data store. This method can
    /// be called periodically (e.g., via a scheduled background job) to clean up stale tokens
    /// and prevent unbounded growth of the token store.
    /// </summary>
    /// <param name="ct">A cancellation token that can be used to cancel the operation.</param>
    /// <returns>A task that represents the asynchronous operation. The task result contains the number of refresh tokens that
    /// were removed.</returns>
    Task<int> RefreshTokenPurgeExpired(CancellationToken ct);

    /// <summary>
    /// Marks all active (non-revoked) refresh tokens for <paramref name="userId"/> as revoked.
    /// Call <see cref="IUnitOfWork.Complete"/> to persist. Typically called when a security stamp
    /// mismatch is detected to invalidate all outstanding sessions for the user.
    /// </summary>
    Task RefreshTokenRevokeAll(Guid userId, CancellationToken ct);
}

public interface IIdentityContextFactory : ICoreDataContextFactory<IIdentityContext> {
    /// <summary>
    /// Creates an identity context using the default connection name and the specified database provider.
    /// </summary>
    Task<IIdentityContext> CreateAsync(DatabaseProvider provider);

    /// <summary>
    /// Creates an identity context using the specified database provider and named connection string.
    /// </summary>
    Task<IIdentityContext> CreateAsync(DatabaseProvider provider, string connectionName);
}
