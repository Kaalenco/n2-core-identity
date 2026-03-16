using Microsoft.AspNetCore.Identity;

using N2.Core.Commands;
using N2.Core.Entity;
using N2.Core.Identity.Data;

namespace N2.Core.Identity;

public interface IIdentityContext : ICoreDataContext, IUnitOfWork
{
    int MaxLogSize { get; set; }

    Task<SelectItemList<HtmlString>> RolesAsync();

    Task<SelectItemList<UserSelectItem>> UsersAsync();

    Task<SelectItemList<UserSelectItem>> TenantsAsync();

    Task<SelectItemList<UserSelectItem>> ApplicationsAsync(Guid tenantId);

    Task<Application?> FindApplicationByIdAsync(Guid applicationId, CancellationToken token);
    Task<Application?> ApplicationAsync(Guid tenantId, string name, CancellationToken token);

    Task<string> GetNameForApplicationAsync(Guid applicationId);

    void RemoveApplication(Application application);

    Task<int> AddApplicationAsync(Application application, CancellationToken token);

    IQueryable<Application> Application { get; }

    Task<ICommandResponse<ApplicationUser>> FindByNameAsync(string normalizedName, CancellationToken token);
    Task<ApplicationUser?> FindByIdAsync(Guid userId, CancellationToken token);
    Task<ApplicationTenant?> FindTenantByIdAsync(Guid tenantId, CancellationToken token);
    Task<ApplicationTenant?> FindTenantByEmailAsync(string normalizedEmail, CancellationToken token);
    Task<ApplicationUser?> FindByEmailAsync(string normalizedEmail, CancellationToken token);

    Task<string> GetNameForUserAsync(Guid userId);
    Task<string> GetNameForTenantAsync(Guid tenantId);

    Task<bool> CanSignInAsync(Guid userId);

    Task<bool> CanSignInTenantAsync(Guid userId, Guid tenantId);

    void RemoveApplicationTenant(ApplicationTenant tenant);
    void RemoveApplicationUser(ApplicationUser user);

    void RemoveApplicationRole(ApplicationRole role);

    void RemoveApplicationUserRole(IdentityUserRole<Guid> identityRole);

    void RemoveApplicationUserTenant(ApplicationUserTenant userTenant);

    Task<int> AddApplicationTenantAsync(ApplicationTenant tenant, CancellationToken token);
    Task<int> AddApplicationUserAsync(ApplicationUser user, CancellationToken token);

    Task<int> AddApplicationRoleAsync(ApplicationRole role, CancellationToken token);

    Task<int> AddIdentityUserRoleAsync(IdentityUserRole<Guid> identityRole, CancellationToken token);

    Task<int> AddIdentityUserTenantAsync(ApplicationUserTenant identityUserTenant, CancellationToken token);

    Task<ApplicationUser?> ApplicationUserAsync(string normalizedName, CancellationToken token);

    Task<ApplicationUser?> ApplicationUserAsync(Guid userId, CancellationToken token);

    Task<ApplicationUser?> ApplicationUserByEmailAsync(string normalizedEmail, CancellationToken token);

    Task<ApplicationRole?> ApplicationRoleAsync(string normalizedName, CancellationToken token);

    Task<ApplicationTenant?> ApplicationTenantAsync(string normalizedName, CancellationToken token);

    Task<IdentityUserRole<Guid>?> IdentityUserRoleAsync(Guid userId, Guid roleId, CancellationToken token);

    IQueryable<ApplicationUser> ApplicationUser { get; }
    IQueryable<ApplicationRole> ApplicationRole { get; }
    IQueryable<IdentityUserRole<Guid>> IdentityUserRole { get; }
    IQueryable<ApplicationUserTenant> ApplicationUserTenant { get; }

    Task<IEnumerable<string>> UserRolesAsync(Guid userId);
    Task<IEnumerable<string>> TenantUsersAsync(Guid tenantId);

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