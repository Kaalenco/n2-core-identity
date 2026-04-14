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
    public DbSet<ApplicationDefinition> ApplicationDefinitions { get; set; } = null!;
    public DbSet<ApplicationSecret> ApplicationSecrets { get; set; } = null!;
    public DbSet<ApplicationUserAlert> UserAlerts { get; set; } = null!;
    public DbSet<ApplicationRefreshToken> RefreshTokens { get; set; } = null!;

    public IQueryable<ApplicationTenant> Tenant => Tenants;
    public IQueryable<ApplicationDefinition> Application => ApplicationDefinitions;
    public IQueryable<ApplicationUser> User => base.Users;
    public IQueryable<ApplicationUserAlert> UserAlert => UserAlerts;
    public IQueryable<ApplicationRole> Role => base.Roles;
    public IQueryable<IdentityUserRole<Guid>> UserRole => base.UserRoles;
    public IQueryable<ApplicationUserTenant> UserTenant => UserTenants;
    public IQueryable<ApplicationSecret> ApplicationSecret => ApplicationSecrets;
    public IQueryable<ApplicationRefreshToken> RefreshToken => RefreshTokens;

    protected override void OnModelCreating(ModelBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);
        base.OnModelCreating(builder);
        ApplicationRefreshToken.Configure(builder);
    }

#pragma warning disable CA1862

    // Use the 'StringComparison' method overloads to perform case-insensitive string comparisons
    // Except for linq2sql queryables, where stringcomparison method can have side effects.
    public async Task<ICommandResponse<ApplicationUser>> UserFind(string normalizedName, CancellationToken ct) {
        var result = await UserFindRecord(normalizedName, ct);
        return new ApplicationUserResponse(result);
    }

    public Task<ApplicationUser?> UserFindRecord(string normalizedName, CancellationToken ct) 
        => Users
        .Include(u => u.ApplicationUserAlert.Where(a => !a.Acknowledged && a.CreatedAt > DateTime.UtcNow.AddDays(-7)))
        .Where(u => u.NormalizedUserName == normalizedName)
        .FirstOrDefaultAsync(ct);

    public Task<ApplicationUser?> UserFindRecord(Guid userId, CancellationToken ct)
        => Users
        .Include(u => u.ApplicationUserAlert.Where(a => !a.Acknowledged && a.CreatedAt > DateTime.UtcNow.AddDays(-7)))
        .Where(u => u.Id == userId)
        .FirstOrDefaultAsync(ct);

    public Task<ApplicationTenant?> TenantFindRecord(Guid tenantId, CancellationToken ct)
        => Tenants.Where(t => t.Id == tenantId).FirstOrDefaultAsync(ct);

    public Task<ApplicationTenant?> TenantFindRecord(string normalizedName, CancellationToken ct)
        => Tenants.Where(t => t.NormalizedName == normalizedName).FirstOrDefaultAsync(ct);

    public Task<ApplicationUser?> UserFindRecordByEmail(string normalizedEmail, CancellationToken ct)
        => Users
        .Include(u => u.ApplicationUserAlert.Where(a => !a.Acknowledged && a.CreatedAt > DateTime.UtcNow.AddDays(-7)))
        .Where(u => u.NormalizedEmail == normalizedEmail)
        .FirstOrDefaultAsync(ct);

    public Task<ApplicationTenant?> TenantFindRecordByEmail(string normalizedEmail, CancellationToken ct)
        => Tenants.Where(u => u.NormalizedEmail == normalizedEmail).FirstOrDefaultAsync(ct);

    public Task<ApplicationDefinition?> ApplicationFindRecord(Guid applicationId, CancellationToken ct)
        => Application.Where(a => a.Id == applicationId).FirstOrDefaultAsync(ct);

    public Task<ApplicationDefinition?> ApplicationFindRecord(Guid tenantId, string name, CancellationToken ct) {
        var normalizedName = (name ?? "").Trim().ToUpperInvariant();
        return Application.Where(a => a.ApplicationTenantId == tenantId && a.NormalizedName == normalizedName).FirstOrDefaultAsync(ct);
    }

    public Task<ApplicationRole?> RoleFindRecord(string normalizedName, CancellationToken ct)
        => Roles.Where(r => r.NormalizedName == normalizedName).FirstOrDefaultAsync(ct);

    public Task<IdentityUserRole<Guid>?> UserRoleFindRecord(Guid userId, Guid roleId, CancellationToken ct)
        => UserRoles.Where(ur => ur.UserId == userId && ur.RoleId == roleId).FirstOrDefaultAsync(ct);

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

    public async Task<string> UserGetName(Guid userId, CancellationToken ct) {
        var user = await base.Users
            .Where(u => u.Id == userId)
            .Select(u => u.DisplayName ?? u.UserName ?? "???")
            .FirstOrDefaultAsync(ct);
        return user ?? "Unknown";
    }

    public async Task<string> TenantGetName(Guid tenantId, CancellationToken ct) {
        var tenant = await Tenants
            .Where(t => t.Id == tenantId)
            .Select(t => t.Name ?? "???")
            .FirstOrDefaultAsync(ct);
        return tenant ?? "Unknown";
    }

    public async Task<string> ApplicationGetName(Guid applicationId, CancellationToken ct) {
        var application = await Application
            .Where(a => a.Id == applicationId)
            .Select(a => a.Name ?? "???")
            .FirstOrDefaultAsync(ct);
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

    public async Task<SelectItemList<HtmlString>> RoleGetSelectList(CancellationToken ct) {
        SelectItemList<HtmlString> result = new();
        var roles = await base.Roles
            .Where(r => r.Name != null)
            .Select(m => new {
                m.Id,
                m.Name
            })
            .ToArrayAsync(ct);
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

    public async Task<SelectItemList<UserSelectItem>> UserGetSelectList(CancellationToken ct) {
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
            .ToArrayAsync(ct);
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

    public async Task<SelectItemList<UserSelectItem>> TenantGetSelectList(CancellationToken ct) {
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
            .ToArrayAsync(ct);
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

    public async Task<SelectItemList<HtmlString>> ApplicationGetSelectList(Guid tenantId, CancellationToken ct) {
        SelectItemList<HtmlString> result = new();
        var items = await
            Application
            .AsNoTracking()
            .Where(m => m.ApplicationTenantId == tenantId)
            .Select(m => new {
                Key = m.Id,
                Value = new HtmlString(m.Name + (m.IsLocked ? " (Locked)" : ""))
            })
            .ToArrayAsync(ct);
        if (items == null) {
            return result;
        }

        foreach (var item in items) {
            if (item == null) {
                continue;
            }
            result.Add(new SelectItem<HtmlString> { Key = item.Key, Value = item.Value });
        }
        return result;
    }

    public Task<bool> UserCanSignIn(Guid userId, CancellationToken ct) {
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
            .FirstOrDefaultAsync(ct);
    }

    public async Task<bool> UserCanSignInTenant(Guid userId, Guid tenantId, CancellationToken ct) {
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
            .FirstOrDefaultAsync(ct);
        if (!userAllowed)
            return false;

        // check tenant lockout
        var tenantAllowed = await UserTenants
            .AsNoTracking()
            .Where(ut => ut.ApplicationUserId == userId && ut.ApplicationTenantId == tenantId)
            .Join(Tenants, ut => ut.ApplicationTenantId, t => t.Id, (ut, t) => t)
            .Select(t => new { t.Id, t.IsLocked })
            .FirstOrDefaultAsync(ct);
        if (tenantAllowed == null) {
            return false;
        }
        if (tenantAllowed.IsLocked) {
            return false;
        }
        return true;
    }

    public async Task<IEnumerable<string>> TenantGetUsers(Guid tenantId, CancellationToken ct) {
        var tenant = await Tenants
            .AsNoTracking()
            .Where(m => !(m.IsLocked || m.IsRemoved) && m.Id == tenantId)
            .FirstOrDefaultAsync(ct);
        if (tenant == null) {
            return Enumerable.Empty<string>();
        }

        var users = await UserTenants
            .AsNoTracking()
            .Where(m => m.ApplicationTenantId == tenantId)
            .Join(base.Users, ut => ut.ApplicationUserId, r => r.Id, (ut, r) => r.UserName)
            .ToArrayAsync(ct);
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

    public async Task<IEnumerable<string>> UserGetRoles(Guid userId, CancellationToken ct) {
        var user = await base.Users
            .AsNoTracking()
            .Where(m => m.EmailConfirmed && m.UserName != null && m.Id == userId)
            .FirstOrDefaultAsync(ct);
        if (user == null) {
            return Enumerable.Empty<string>();
        }

        var roles = await base.UserRoles
            .AsNoTracking()
            .Where(m => m.UserId == userId)
            .Join(base.Roles, ur => ur.RoleId, r => r.Id, (ur, r) => r.Name)
            .ToArrayAsync(ct);
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

    public void ApplicationDelete(ApplicationDefinition application) => ApplicationDefinitions.Remove(application);

    public void TenantDelete(ApplicationTenant tenant) => Tenants.Remove(tenant);

    public void UserDelete(ApplicationUser user) => base.Users.Remove(user);

    public void RoleDelete(ApplicationRole role) => base.Roles.Remove(role);

    public void UserRoleDelete(IdentityUserRole<Guid> identityRole) => base.UserRoles.Remove(identityRole);

    public void UserTenantDelete(ApplicationUserTenant userTenant) => UserTenants.Remove(userTenant);

    public Task<bool> UserTenantIsAdmin(Guid userId, Guid tenantId, CancellationToken ct)
        => UserTenants
            .AsNoTracking()
            .Where(ut => ut.ApplicationUserId == userId && ut.ApplicationTenantId == tenantId)
            .Select(ut => ut.IsAdmin)
            .FirstOrDefaultAsync(ct);

    public async Task<(ResponseStatus status, string? message)> UserTenantSetAdmin(Guid userId, Guid tenantId, bool isAdmin, CancellationToken ct) {
        var membership = await UserTenants
            .Where(ut => ut.ApplicationUserId == userId && ut.ApplicationTenantId == tenantId)
            .FirstOrDefaultAsync(ct);
        if (membership == null)
            return (ResponseStatus.NotFound, $"User '{userId}' is not a member of tenant '{tenantId}'.");
        if (membership.IsAdmin == isAdmin)
            return (ResponseStatus.Success, "No change required.");
        membership.IsAdmin = isAdmin;
        return await Complete();
    }

    public async Task<int> ApplicationAdd(ApplicationDefinition application, CancellationToken ct) {
        try {
            if (application == null) return -1;
            application.NormalizedName = (application.Name ?? "").Trim().ToUpperInvariant();
            await ApplicationDefinitions.AddAsync(application, ct);
            var count = await base.SaveChangesAsync(ct);
            return count;
        } catch (System.InvalidOperationException e) {
            N2IdentityContextLoggingExtensions.LogAddApplicationUserFailed(logger, e.Message, e);
            return -1;
        }
    }

    public async Task<int> TenantAdd(ApplicationTenant tenant, CancellationToken ct) {
        try {
            if (tenant == null) return -1;
            tenant.NormalizedName = (tenant.Name ?? "").Trim().ToUpperInvariant();
            tenant.NormalizedEmail = (tenant.AdminEmail ??"").Trim().ToUpperInvariant();

            var result = await Tenants.AddAsync(tenant, ct);
            var count = await base.SaveChangesAsync(ct);
            return count;
        } catch (System.InvalidOperationException e) {
            N2IdentityContextLoggingExtensions.LogAddApplicationUserFailed(logger, e.Message, e);
            return -1;
        }
    }

    public async Task<int> UserAdd(ApplicationUser user, CancellationToken ct) {
        try {
            var result = await base.Users.AddAsync(user, ct);
            var count = await base.SaveChangesAsync(ct);
            return count;
        } catch (System.InvalidOperationException e) {
            N2IdentityContextLoggingExtensions.LogAddApplicationUserFailed(logger, e.Message, e);
            return -1;
        }
    }

    public async Task<int> RoleAdd(ApplicationRole role, CancellationToken ct) {
        try {
            await base.Roles.AddAsync(role, ct);
            var count = await base.SaveChangesAsync(ct);
            return count;
        } catch (System.InvalidOperationException e) {
            N2IdentityContextLoggingExtensions.LogAddApplicationRoleFailed(logger, e.Message, e);
            return -1;
        }
    }

    public async Task<int> UserRoleAdd(IdentityUserRole<Guid> identityRole, CancellationToken ct) {
        try {
            await base.UserRoles.AddAsync(identityRole, ct);
            var count = await base.SaveChangesAsync(ct);
            return count;
        } catch (System.InvalidOperationException e) {
            N2IdentityContextLoggingExtensions.LogAddIdentityUserRoleFailed(logger, e.Message, e);
            return -1;
        }
    }

    public async Task<int> UserTenantAdd(ApplicationUserTenant identityUserTenant, CancellationToken ct) {
        try {
            await UserTenants.AddAsync(identityUserTenant, ct);
            var count = await base.SaveChangesAsync(ct);
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

    public Task<ApplicationSecret?> SecretFindRecord(Guid applicationSecretId, CancellationToken ct)  => ApplicationSecrets.Where(a => a.Id == applicationSecretId).FirstOrDefaultAsync(ct);

    public Task<ApplicationSecret?> SecretFindRecord(string hashedToken, CancellationToken ct) => ApplicationSecrets.Where(a => a.HashedToken == hashedToken).FirstOrDefaultAsync(ct);

    public void SecretAdd(ApplicationSecret secret) {
        ApplicationSecrets.Add(secret);
    }

    public void SecretDelete(ApplicationSecret secret) => ApplicationSecrets.Remove(secret);

    public async Task<SelectItemList<HtmlString>> SecretGetSelectList(Guid ownerId, string ownerType, CancellationToken ct) {
        SelectItemList<HtmlString> result = new();
        var items = await ApplicationSecrets
            .Where(r => r.Name != null && r.Expiration > DateTime.UtcNow && r.ReferenceId == ownerId && r.ReferenceType == ownerType)
            .Select(m => new {
                m.Id,
                m.Name
            })
            .ToArrayAsync(ct);
        if (items == null) {
            return result;
        }

        foreach (var item in items) {
            if (item == null || item.Name == null) {
                continue;
            }
            result.Add(new SelectItem<HtmlString> { Key = item.Id, Value = new HtmlString(item.Name) });
        }
        return result;
    }

    public Task<int> UserAlertAdd(ApplicationUserAlert alert, CancellationToken ct) {
        UserAlerts.Add(alert);
        return base.SaveChangesAsync(ct);
    }

    // ── Refresh tokens ────────────────────────────────────────────────────────

    public Task<ApplicationRefreshToken?> RefreshTokenFind(string token, CancellationToken ct)
        => RefreshTokens.Where(r => r.Token == token).FirstOrDefaultAsync(ct);

    public void RefreshTokenAdd(ApplicationRefreshToken token)
        => RefreshTokens.Add(token);

    public void RefreshTokenRevoke(ApplicationRefreshToken token) {
        if (token is null || token.RevokedAt != null) {
            return;
        }
        token.RevokedAt = DateTime.UtcNow;
    }
        

    public Task<int> RefreshTokenPurgeStale(Guid userId, CancellationToken ct)
    {
        var stale = RefreshTokens
            .Where(r => r.ApplicationUserId == userId && (r.RevokedAt != null || r.ExpiresAt < DateTime.UtcNow));
        RefreshTokens.RemoveRange(stale);
        return base.SaveChangesAsync(ct);
    }

    public Task<int> RefreshTokenPurgeExpired(CancellationToken ct) {
        var expired = RefreshTokens
            .Where(r => r.ExpiresAt < DateTime.UtcNow);
        RefreshTokens.RemoveRange(expired);
        return base.SaveChangesAsync(ct);
    }
}