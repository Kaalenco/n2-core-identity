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

    Task<ApplicationSecret?> SecretFindRecord(Guid applicationSecretId, CancellationToken token);
    Task<ApplicationSecret?> SecretFindRecord(string hashedToken, CancellationToken token);
    Task<int> SecretAdd(ApplicationSecret secret, CancellationToken token);
    void SecretDelete(ApplicationSecret secret);
    Task<SelectItemList<HtmlString>> SecretGetSelectList(Guid ownerId, CancellationToken token);

    IQueryable<ApplicationUser> User { get; }

    IQueryable<IdentityUserRole<Guid>> UserRole { get; }

    IQueryable<ApplicationUserTenant> UserTenant { get; }

    Task<int> ApplicationAdd(ApplicationDefinition application, CancellationToken token);

    void ApplicationDelete(ApplicationDefinition application);

    Task<ApplicationDefinition?> ApplicationFindRecord(Guid applicationId, CancellationToken token);

    Task<ApplicationDefinition?> ApplicationFindRecord(Guid tenantId, string name, CancellationToken token);

    Task<string> ApplicationGetName(Guid applicationId, CancellationToken token);

    Task<SelectItemList<HtmlString>> ApplicationGetSelectList(Guid tenantId, CancellationToken token);

    Task<int> RoleAdd(ApplicationRole role, CancellationToken token);

    void RoleDelete(ApplicationRole role);

    Task<ApplicationRole?> RoleFindRecord(string normalizedName, CancellationToken token);

    Task<SelectItemList<HtmlString>> RoleGetSelectList(CancellationToken token);

    Task<int> TenantAdd(ApplicationTenant tenant, CancellationToken token);

    void TenantDelete(ApplicationTenant tenant);

    Task<ApplicationTenant?> TenantFindRecord(Guid tenantId, CancellationToken token);

    Task<ApplicationTenant?> TenantFindRecord(string normalizedName, CancellationToken token);

    Task<ApplicationTenant?> TenantFindRecordByEmail(string normalizedEmail, CancellationToken token);

    Task<string> TenantGetName(Guid tenantId, CancellationToken token);

    Task<SelectItemList<UserSelectItem>> TenantGetSelectList(CancellationToken token);

    Task<IEnumerable<string>> TenantGetUsers(Guid tenantId, CancellationToken token);

    Task<int> UserAdd(ApplicationUser user, CancellationToken token);

    Task<bool> UserCanSignIn(Guid userId, CancellationToken token);

    Task<bool> UserCanSignInTenant(Guid userId, Guid tenantId, CancellationToken token);

    void UserDelete(ApplicationUser user);

    Task<ICommandResponse<ApplicationUser>> UserFind(string normalizedName, CancellationToken token);

    Task<ApplicationUser?> UserFindRecord(Guid userId, CancellationToken token);

    Task<ApplicationUser?> UserFindRecord(string normalizedName, CancellationToken token);

    Task<ApplicationUser?> UserFindRecordByEmail(string normalizedEmail, CancellationToken token);

    Task<string> UserGetName(Guid userId, CancellationToken token);

    Task<IEnumerable<string>> UserGetRoles(Guid userId, CancellationToken token);

    Task<SelectItemList<UserSelectItem>> UserGetSelectList(CancellationToken token);
    Task<int> UserRoleAdd(IdentityUserRole<Guid> identityRole, CancellationToken token);

    void UserRoleDelete(IdentityUserRole<Guid> identityRole);

    Task<IdentityUserRole<Guid>?> UserRoleFindRecord(Guid userId, Guid roleId, CancellationToken token);

    Task<int> UserTenantAdd(ApplicationUserTenant identityUserTenant, CancellationToken token);

    void UserTenantDelete(ApplicationUserTenant userTenant);
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
