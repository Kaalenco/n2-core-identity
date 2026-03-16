using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

using N2.Core.Commands;
using N2.Core.Entity;
using N2.Core.Identity.Commands;

using System.Collections.Concurrent;
using System.Data;
using System.Data.Common;

namespace N2.Core.Identity.Data;

public class N2IdentityContext(
    DbContextOptions<N2IdentityContext> options,
    ILogger<N2IdentityContext> logger) :
    IdentityDbContext<ApplicationUser, ApplicationRole, Guid>(options), IIdentityContext {
    public const int DefaultMaxLogSize = 1000;
    public int MaxLogSize { get; set; } = DefaultMaxLogSize;
    private readonly ConcurrentQueue<IChangeLog> logQueue = new();
    private readonly object logLock = new();
    private int logCount;

    private int NextLogId() {
        lock (logLock) {
            return ++logCount;
        }
    }

    public DbSet<ApplicationTenant> Tenants { get; set; } = null!;
    public DbSet<ApplicationUserTenant> UserTenants { get; set; } = null!;
    public DbSet<Application> Applications { get; set; } = null!;
    public DbSet<ApplicationSecret> ApplicationSecrets { get; set; } = null!;

    public IQueryable<ApplicationTenant> ApplicationTenant => Tenants;
    public IQueryable<Application> Application => Applications;
    public IQueryable<ApplicationUser> ApplicationUser => Users;
    public IQueryable<ApplicationRole> ApplicationRole => Roles;
    public IQueryable<IdentityUserRole<Guid>> IdentityUserRole => UserRoles;
    public IQueryable<ApplicationUserTenant> ApplicationUserTenant => UserTenants;
    public IQueryable<ApplicationSecret> ApplicationSecret => ApplicationSecrets;


#pragma warning disable CA1862

    // Use the 'StringComparison' method overloads to perform case-insensitive string comparisons
    // Except for linq2sql queryables, where stringcomparison method can have side effects.
    public async Task<ICommandResponse<ApplicationUser>> FindByNameAsync(string normalizedName, CancellationToken token) {
        var result = await ApplicationUserAsync(normalizedName, token);
        return new ApplicationUserResponse(result);
    }

    public Task<ApplicationUser?> ApplicationUserAsync(string normalizedName, CancellationToken token)
        => Users.Where(u => u.NormalizedUserName == normalizedName).FirstOrDefaultAsync(token);

    public Task<ApplicationUser?> FindByIdAsync(Guid userId, CancellationToken token)
        => Users.Where(u => u.Id == userId).FirstOrDefaultAsync(token);

    public Task<ApplicationTenant?> FindTenantByIdAsync(Guid tenantId, CancellationToken token)
        => Tenants.Where(t => t.Id == tenantId).FirstOrDefaultAsync(token);

    public Task<ApplicationUser?> ApplicationUserAsync(Guid userId, CancellationToken token)
        => Users.Where(u => u.Id == userId).FirstOrDefaultAsync(token);

    public Task<ApplicationTenant?> ApplicationTenantAsync(string normalizedName, CancellationToken token)
        => Tenants.Where(t => t.NormalizedName == normalizedName).FirstOrDefaultAsync(token);

    public Task<ApplicationUser?> FindByEmailAsync(string normalizedEmail, CancellationToken token)
        => Users.Where(u => u.NormalizedEmail == normalizedEmail).FirstOrDefaultAsync(token);

    public Task<ApplicationTenant?> FindTenantByEmailAsync(string normalizedEmail, CancellationToken token)
        => Tenants.Where(u => u.NormalizedEmail == normalizedEmail).FirstOrDefaultAsync(token);

    public Task<Application?> FindApplicationByIdAsync(Guid applicationId, CancellationToken token)
        => Applications.Where(a => a.Id == applicationId).FirstOrDefaultAsync(token);

    public Task<Application?> ApplicationAsync(Guid tenantId, string name, CancellationToken token) {
        var normalizedName = (name ?? "").Trim().ToUpperInvariant();
        return Applications.Where(a => a.ApplicationTenantId == tenantId && a.NormalizedName == normalizedName).FirstOrDefaultAsync(token);
    }

    public Task<ApplicationUser?> ApplicationUserByEmailAsync(string normalizedEmail, CancellationToken token)
        => Users.Where(u => u.NormalizedEmail == normalizedEmail).FirstOrDefaultAsync(token);

    public Task<ApplicationRole?> ApplicationRoleAsync(string normalizedName, CancellationToken token)
        => Roles.Where(r => r.NormalizedName == normalizedName).FirstOrDefaultAsync(token);

    public Task<IdentityUserRole<Guid>?> IdentityUserRoleAsync(Guid userId, Guid roleId, CancellationToken token)
        => UserRoles.Where(ur => ur.UserId == userId && ur.RoleId == roleId).FirstOrDefaultAsync(token);

    public Task<List<KeyValuePair<string, string>>> GetSelectListAsync(string tableName)
    => tableName switch {
        nameof(TableNames.AspNetUsers) => base.Users
                .Where(m => m.EmailConfirmed && m.UserName != null)
                .Select(x => new KeyValuePair<string, string>(x.Id.ToString(), x.UserName ?? string.Empty))
                .ToListAsync(),
        nameof(TableNames.AspNetRoles) => base.Roles
                .Where(m => m.Name != null)
                .Select(x => new KeyValuePair<string, string>(x.Id.ToString(), x.Name ?? string.Empty))
                .ToListAsync(),
        nameof(TableNames.Tenants) => Tenants
                .Where(m => m.Name != null)
                .Select(x => new KeyValuePair<string, string>(x.Id.ToString(), x.Name ?? string.Empty))
                .ToListAsync(),
        _ => throw new ArgumentOutOfRangeException(nameof(tableName), "Unknown table name.")
    };

    public async Task<string> GetNameForUserAsync(Guid userId) {
        var user = await base.Users
            .Where(u => u.Id == userId)
            .Select(u => u.DisplayName ?? u.UserName ?? "???")
            .FirstOrDefaultAsync();
        return user ?? "Unknown";
    }

    public async Task<string> GetNameForTenantAsync(Guid tenantId) {
        var tenant = await Tenants
            .Where(t => t.Id == tenantId)
            .Select(t => t.Name ?? "???")
            .FirstOrDefaultAsync();
        return tenant ?? "Unknown";
    }

    public async Task<string> GetNameForApplicationAsync(Guid applicationId) {
        var application = await Applications
            .Where(a => a.Id == applicationId)
            .Select(a => a.Name ?? "???")
            .FirstOrDefaultAsync();
        return application ?? "Unknown";
    }

    public IQueryable<IChangeLog> ChangeLogs => logQueue.AsQueryable();

    public void AddChangeLog(IChangeLog changeLog) {
        logQueue.Enqueue(changeLog);
        while (logQueue.Count > MaxLogSize) {
            logQueue.TryDequeue(out _);
        }
    }

    public void AddChangeLog<T>(
        Guid publicId,
        string message,
        Guid userId,
        string userName)
        where T : class {
        QueueLogEntry logEntry = new() {
            Id = NextLogId(),
            LogRecordId = Guid.NewGuid(),
            TableName = typeof(T).Name,
            ReferenceId = publicId,
            Message = message,
            CreatedBy = userId,
            CreatedByName = userName,
            Created = DateTime.UtcNow
        };
        AddChangeLog(logEntry);
    }

    public void AddRecord<T>(T model) where T : class => Set<T>().Add(model);

    public Task<T?> FindRecordAsync<T>(Guid publicId) where T : class => Set<T>().FindAsync(publicId).AsTask();

    public async Task<(ResponseStatus status, string message)> DeleteAsync<T>(Guid publicId) where T : class {
        var dbSet = Set<T>();
        var dbItem = await dbSet.FindAsync(publicId);
        if (dbItem == null) {
            return (ResponseStatus.NotFound, "Not found");
        }
        dbSet.Remove(dbItem);
        return new(ResponseStatus.NoContent, "Removed");
    }

    public string CurrentDatabaseName => Database.GetDbConnection().Database;

    public bool IsActive => base.Database.CanConnect();

    public async Task<(ResponseStatus status, string? message)> Complete() {
        try {
            var modified = await base.SaveChangesAsync();
            return new(ResponseStatus.Success, $"{modified} records modified");
        } catch (DbException ex) {
            return new(ResponseStatus.ServerError, ex.Message);
        }
    }

    public async Task<SelectItemList<HtmlString>> RolesAsync() {
        SelectItemList<HtmlString> result = new();
        var roles = await base.Roles
            .Where(r => r.Name != null)
            .Select(m => new {
                m.Id,
                m.Name
            })
            .ToArrayAsync();
        if (roles == null) {
            return result;
        }

        foreach (var role in roles) {
            if (role == null || role.Name == null) {
                continue;
            }
            result.Add(new SelectItem<HtmlString> { Key = role.Id, Value = new HtmlString(role.Name) });
        }
        return result;
    }

    public async Task<SelectItemList<UserSelectItem>> UsersAsync() {
        SelectItemList<UserSelectItem> result = new();
        var items = await
            base.Users
            .AsNoTracking()
            .Where(r => r.EmailConfirmed)
            .Select(m => new {
                Key = m.Id,
                Value = new UserSelectItem {
                    Key = m.Id,
                    ImagePath = m.ImagePath,
                    DisplayName = m.DisplayName ?? m.UserName ?? "???",
                    Email = m.Email
                }
            })
            .ToArrayAsync();
        if (items == null) {
            return result;
        }

        foreach (var item in items) {
            if (item == null) {
                continue;
            }
            result.Add(new SelectItem<UserSelectItem> { Key = item.Key, Value = item.Value });
        }
        return result;
    }

    public async Task<SelectItemList<UserSelectItem>> TenantsAsync() {
        SelectItemList<UserSelectItem> result = new();
        var items = await
            Tenants
            .AsNoTracking()
            .Where(r => !(r.IsRemoved || r.IsHidden))
            .Select(m => new {
                Key = m.Id,
                Value = new UserSelectItem {
                    Key = m.Id,
                    ImagePath = m.ImagePath,
                    DisplayName = m.Name + (m.IsLocked ? " (Locked)" : ""),
                    Email = m.AdminEmail
                }
            })
            .ToArrayAsync();
        if (items == null) {
            return result;
        }

        foreach (var item in items) {
            if (item == null) {
                continue;
            }
            result.Add(new SelectItem<UserSelectItem> { Key = item.Key, Value = item.Value });
        }
        return result;
    }

    public async Task<SelectItemList<UserSelectItem>> ApplicationsAsync(Guid tenantId) {
        SelectItemList<UserSelectItem> result = new();
        var items = await
            Applications
            .AsNoTracking()
            .Where(m => m.ApplicationTenantId == tenantId)
            .Select(m => new {
                Key = m.Id,
                Value = new UserSelectItem {
                    Key = m.Id,
                    DisplayName = m.Name + (m.IsLocked ? " (Locked)" : ""),
                }
            })
            .ToArrayAsync();
        if (items == null) {
            return result;
        }

        foreach (var item in items) {
            if (item == null) {
                continue;
            }
            result.Add(new SelectItem<UserSelectItem> { Key = item.Key, Value = item.Value });
        }
        return result;
    }

    public Task<bool> CanSignInAsync(Guid userId) {
        return  base.Users
            .AsNoTracking()
            .Where(u => u.Id == userId &&
                (
                    !u.LockoutEnabled ||
                    (
                        u.LockoutEnabled && (u.LockoutEnd == null || u.LockoutEnd < DateTime.UtcNow)
                    )
                )
            )
            .Select(u => u.EmailConfirmed || u.PhoneNumberConfirmed || u.MfaType == MultiFactorType.None)
            .FirstOrDefaultAsync();
    }

    public async Task<bool> CanSignInTenantAsync(Guid userId, Guid tenantId) {
        var userAllowed = await base.Users
            .AsNoTracking()
            .Where(u => u.Id == userId &&
                (
                    !u.LockoutEnabled ||
                    (
                        u.LockoutEnabled && (u.LockoutEnd == null || u.LockoutEnd < DateTime.UtcNow)
                    )
                )
            )
            .Select(u => u.EmailConfirmed || u.PhoneNumberConfirmed || u.MfaType == MultiFactorType.None)
            .FirstOrDefaultAsync();
        if (!userAllowed)
            return false;

        // check tenant lockout
        var tenantAllowed = await UserTenants
            .AsNoTracking()
            .Where(ut => ut.ApplicationUserId == userId && ut.ApplicationTenantId == tenantId)
            .Join(Tenants, ut => ut.ApplicationTenantId, t => t.Id, (ut, t) => t)
            .Select(t => new { t.Id, t.IsLocked })
            .FirstOrDefaultAsync();
        if (tenantAllowed == null) {
            return false;
        }
        if (tenantAllowed.IsLocked) {
            return false;
        }
        return true;
    }

    public async Task<IEnumerable<string>> TenantUsersAsync(Guid tenantId) {
        var tenant = await Tenants
            .AsNoTracking()
            .Where(m => !(m.IsLocked || m.IsRemoved) && m.Id == tenantId)
            .FirstOrDefaultAsync();
        if (tenant == null) {
            return Enumerable.Empty<string>();
        }

        var users = await UserTenants
            .AsNoTracking()
            .Where(m => m.ApplicationTenantId == tenantId)
            .Join(base.Users, ut => ut.ApplicationUserId, r => r.Id, (ut, r) => r.UserName)
            .ToArrayAsync();
        if (users == null) {
            return Enumerable.Empty<string>();
        }

        List<string> result = new();
        foreach (var user in users) {
            if (user == null) {
                continue;
            }
            result.Add(user);
        }
        return result;
    }

    public async Task<IEnumerable<string>> UserRolesAsync(Guid userId) {
        var user = await base.Users
            .AsNoTracking()
            .Where(m => m.EmailConfirmed && m.UserName != null && m.Id == userId)
            .FirstOrDefaultAsync();
        if (user == null) {
            return Enumerable.Empty<string>();
        }

        var roles = await base.UserRoles
            .AsNoTracking()
            .Where(m => m.UserId == userId)
            .Join(base.Roles, ur => ur.RoleId, r => r.Id, (ur, r) => r.Name)
            .ToArrayAsync();
        if (roles == null) {
            return Enumerable.Empty<string>();
        }

        List<string> result = new();
        foreach (var role in roles) {
            if (role == null) {
                continue;
            }
            result.Add(role);
        }
        return result;
    }

    public void RemoveApplication(Application application) => Applications.Remove(application);

    public void RemoveApplicationTenant(ApplicationTenant tenant) => Tenants.Remove(tenant);

    public void RemoveApplicationUser(ApplicationUser user) => base.Users.Remove(user);

    public void RemoveApplicationRole(ApplicationRole role) => base.Roles.Remove(role);

    public void RemoveApplicationUserRole(IdentityUserRole<Guid> identityRole) => base.UserRoles.Remove(identityRole);

    public void RemoveApplicationUserTenant(ApplicationUserTenant userTenant) => UserTenants.Remove(userTenant);

    public async Task<int> AddApplicationAsync(Application application, CancellationToken token) {
        try {
            if (application == null) return -1;
            application.NormalizedName = (application.Name ?? "").Trim().ToUpperInvariant();
            await Applications.AddAsync(application, token);
            var count = await base.SaveChangesAsync(token);
            return count;
        } catch (System.InvalidOperationException e) {
            N2IdentityContextLoggingExtensions.LogAddApplicationUserFailed(logger, e.Message, e);
            return -1;
        }
    }

    public async Task<int> AddApplicationTenantAsync(ApplicationTenant tenant, CancellationToken token) {
        try {
            if (tenant == null) return -1;
            tenant.NormalizedName = (tenant.Name ?? "").Trim().ToUpperInvariant();
            tenant.NormalizedEmail = (tenant.AdminEmail ??"").Trim().ToUpperInvariant();

            var result = await Tenants.AddAsync(tenant, token);
            var count = await base.SaveChangesAsync(token);
            return count;
        } catch (System.InvalidOperationException e) {
            N2IdentityContextLoggingExtensions.LogAddApplicationUserFailed(logger, e.Message, e);
            return -1;
        }
    }

    public async Task<int> AddApplicationUserAsync(ApplicationUser user, CancellationToken token) {
        try {
            var result = await base.Users.AddAsync(user, token);
            var count = await base.SaveChangesAsync(token);
            return count;
        } catch (System.InvalidOperationException e) {
            N2IdentityContextLoggingExtensions.LogAddApplicationUserFailed(logger, e.Message, e);
            return -1;
        }
    }

    public async Task<int> AddApplicationRoleAsync(ApplicationRole role, CancellationToken token) {
        try {
            await base.Roles.AddAsync(role, token);
            var count = await base.SaveChangesAsync(token);
            return count;
        } catch (System.InvalidOperationException e) {
            N2IdentityContextLoggingExtensions.LogAddApplicationRoleFailed(logger, e.Message, e);
            return -1;
        }
    }

    public async Task<int> AddIdentityUserRoleAsync(IdentityUserRole<Guid> identityRole, CancellationToken token) {
        try {
            await base.UserRoles.AddAsync(identityRole, token);
            var count = await base.SaveChangesAsync(token);
            return count;
        } catch (System.InvalidOperationException e) {
            N2IdentityContextLoggingExtensions.LogAddIdentityUserRoleFailed(logger, e.Message, e);
            return -1;
        }
    }

    public async Task<int> AddIdentityUserTenantAsync(ApplicationUserTenant identityUserTenant, CancellationToken token) {
        try {
            await UserTenants.AddAsync(identityUserTenant, token);
            var count = await base.SaveChangesAsync(token);
            return count;
        } catch (System.InvalidOperationException e) {
            N2IdentityContextLoggingExtensions.LogAddIdentityUserTenantFailed(logger, e.Message, e);
            return -1;
        }
    }

    // Update the Health method to use the LoggerMessage delegate
    public DataContextHealthStatus Health() {
        string? dbName = null;
#pragma warning disable CA1031 // Do not catch general exception types
        try {
            // execute a query to verify the database
            dbName = base.Database.ProviderName ?? "No Provider";
            _ = base.Users.FirstOrDefault(m => m.EmailConfirmed);
            return new DataContextHealthStatus(ResponseStatus.Success, dbName);
        } catch (Exception ex) {
            N2IdentityContextLoggingExtensions.LogHealthStatusFailed(logger, ex.Message, ex);
            return new DataContextHealthStatus(ResponseStatus.PreconditionFailed, dbName ?? "Failed to connect");
        }
#pragma warning restore CA1031 // Do not catch general exception types
    }
}