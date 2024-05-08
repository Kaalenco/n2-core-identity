using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using N2.Core;
using N2.Core.Entity;
using N2.Core.Identity;
using N2.Identity.Data;

namespace N2.Identity;

public interface IIdentityContext : ICoreDataContext
{
    Task<SelectItemList<HtmlString>> RolesAsync();

    Task<SelectItemList<UserSelectItem>> UsersAsync();

    Task<string> GetNameForUserAsync(Guid userId);

    Task<bool> CanSignInAsync(Guid userId);

    DbSet<ApplicationUser> ApplicationUser { get; }
    DbSet<ApplicationRole> ApplicationRole { get; }
    DbSet<IdentityUserRole<Guid>> ApplicationUserRole { get; }

    Task<IEnumerable<string>> UserRolesAsync(Guid userId);
}

public interface IIdentityContextFactory : ICoreDataContextFactory<IIdentityContext>;