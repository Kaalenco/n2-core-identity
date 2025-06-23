using Microsoft.AspNetCore.Identity;

using N2.Core.Entity;
using N2.Core.Identity.Data;

namespace N2.Core.Identity;

public interface IIdentityContext : ICoreDataContext, IUnitOfWork
{
    Task<SelectItemList<HtmlString>> RolesAsync();

    Task<SelectItemList<UserSelectItem>> UsersAsync();

    Task<string> GetNameForUserAsync(Guid userId);

    Task<bool> CanSignInAsync(Guid userId);

    void RemoveApplicationUser(ApplicationUser user);

    void RemoveApplicationRole(ApplicationRole role);

    void RemoveApplicationUserRole(IdentityUserRole<Guid> identityRole);

    Task<int> AddApplicationUserAsync(ApplicationUser user, CancellationToken token);

    Task<int> AddApplicationRoleAsync(ApplicationRole role, CancellationToken token);

    Task<int> AddIdentityUserRoleAsync(IdentityUserRole<Guid> identityRole, CancellationToken token);

    Task<ApplicationUser?> ApplicationUserAsync(string normalizedName, CancellationToken token);

    Task<ApplicationUser?> ApplicationUserAsync(Guid userId, CancellationToken token);

    Task<ApplicationUser?> ApplicationUserByEmailAsync(string normalizedEmail, CancellationToken token);

    Task<ApplicationRole?> ApplicationRoleAsync(string normalizedName, CancellationToken token);

    Task<IdentityUserRole<Guid>?> IdentityUserRoleAsync(Guid userId, Guid roleId, CancellationToken token);

    IQueryable<ApplicationUser> ApplicationUser { get; }
    IQueryable<ApplicationRole> ApplicationRole { get; }
    IQueryable<IdentityUserRole<Guid>> IdentityUserRole { get; }

    Task<IEnumerable<string>> UserRolesAsync(Guid userId);
}

public interface IIdentityContextFactory : ICoreDataContextFactory<IIdentityContext>;