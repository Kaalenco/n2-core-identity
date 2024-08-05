using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using N2.Core;
using N2.Core.Entity;
using N2.Core.Identity;
using System.Collections.Concurrent;
using System.Data;
using System.Data.Common;

namespace N2.Core.Identity.Data;

public class N2IdentityContext(DbContextOptions<N2IdentityContext> options) :
    IdentityDbContext<ApplicationUser, ApplicationRole, Guid>(options), IIdentityContext
{
    public const int DefaultMaxLogSize = 1000;
    public int MaxLogSize { get; set; } = DefaultMaxLogSize;
    private readonly ConcurrentQueue<IChangeLog> logQueue = new();
    private readonly object logLock = new();
    private int logCount;

    private int NextLogId()
    {
        lock (logLock)
        {
            return ++logCount;
        }
    }

    public IQueryable<ApplicationUser> ApplicationUser => Users;
    public IQueryable<ApplicationRole> ApplicationRole => Roles;
    public IQueryable<IdentityUserRole<Guid>> IdentityUserRole => UserRoles;

    public Task<ApplicationUser?> ApplicationUserAsync(string normalizedName, CancellationToken token)
        => Users.Where(u => u.NormalizedUserName == normalizedName).FirstOrDefaultAsync(token);

    public Task<ApplicationUser?> ApplicationUserAsync(Guid userId, CancellationToken token)
        => Users.Where(u => u.Id == userId).FirstOrDefaultAsync(token);

    public Task<ApplicationUser?> ApplicationUserByEmailAsync(string normalizedEmail, CancellationToken token)
        => Users.Where(u => u.NormalizedEmail == normalizedEmail).FirstOrDefaultAsync(token);

    public Task<ApplicationRole?> ApplicationRoleAsync(string normalizedName, CancellationToken token)
        => Roles.Where(r => r.NormalizedName == normalizedName).FirstOrDefaultAsync(token);

    public Task<IdentityUserRole<Guid>?> IdentityUserRoleAsync(Guid userId, Guid roleId, CancellationToken token)
        => UserRoles.Where(ur => ur.UserId == userId && ur.RoleId == roleId).FirstOrDefaultAsync(token);

    public Task<List<KeyValuePair<string, string>>> GetSelectListAsync(string tableName)
    => tableName switch
    {
        nameof(TableNames.AspNetUsers) => base.Users
                .Where(m => m.EmailConfirmed && m.UserName != null)
                .Select(x => new KeyValuePair<string, string>(x.Id.ToString(), x.UserName ?? string.Empty))
                .ToListAsync(),
        nameof(TableNames.AspNetRoles) => base.Roles
                .Where(m => m.Name != null)
                .Select(x => new KeyValuePair<string, string>(x.Id.ToString(), x.Name ?? string.Empty))
                .ToListAsync(),
        _ => throw new ArgumentOutOfRangeException(tableName, tableName, null)
    };

    public async Task<string> GetNameForUserAsync(Guid userId)
    {
        var user = await base.Users
            .Where(u => u.Id == userId)
            .Select(u => u.DisplayName ?? u.UserName ?? "???")
            .FirstOrDefaultAsync();
        return user ?? "Unknown";
    }

    public IQueryable<IChangeLog> ChangeLogs => logQueue.AsQueryable();

    public void AddChangeLog(IChangeLog changeLog)
    {
        logQueue.Enqueue(changeLog);
        while (logQueue.Count > MaxLogSize)
        {
            logQueue.TryDequeue(out _);
        }
    }

    public void AddChangeLog<T>(
        Guid publicId,
        string message,
        Guid userId,
        string userName)
        where T : class
    {
        var logEntry = new QueueLogEntry
        {
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

    public async Task<(int resultCode, string message)> DeleteAsync<T>(Guid publicId) where T : class
    {
        var dbSet = Set<T>();
        var dbItem = await dbSet.FindAsync(publicId);
        if (dbItem == null)
        {
            return (404, "Not found");
        }
        dbSet.Remove(dbItem);
        return new(204, "Removed");
    }

    public string CurrentDatabaseName => Database.GetDbConnection().Database;

    public async Task<(int code, string message)> SaveChangesAsync()
    {
        try
        {
            var modified = await base.SaveChangesAsync();
            return new(200, $"{modified} records modified");
        }
        catch (DbException ex)
        {
            return new(500, ex.Message);
        }
    }

    public async Task<SelectItemList<HtmlString>> RolesAsync()
    {
        var result = new SelectItemList<HtmlString>();
        var roles = await base.Roles
            .Where(r => r.Name != null)
            .Select(m => new
            {
                m.Id,
                m.Name
            })
            .ToArrayAsync();
        if (roles == null)
        {
            return result;
        }

        foreach (var role in roles)
        {
            if (role == null || role.Name == null)
            {
                continue;
            }
            result.Add(new SelectItem<HtmlString> { Key = role.Id, Value = new HtmlString(role.Name) });
        }
        return result;
    }

    public async Task<SelectItemList<UserSelectItem>> UsersAsync()
    {
        var result = new SelectItemList<UserSelectItem>();
        var users = await
            base.Users
            .Where(r => r.EmailConfirmed)
            .Select(m => new
            {
                Key = m.Id,
                Value = new UserSelectItem
                {
                    Key = m.Id,
                    ImagePath = m.ImagePath,
                    DisplayName = m.DisplayName ?? m.UserName ?? "???",
                    Email = m.Email
                }
            })
            .ToArrayAsync();
        if (users == null)
        {
            return result;
        }

        foreach (var user in users)
        {
            if (user == null)
            {
                continue;
            }
            result.Add(new SelectItem<UserSelectItem> { Key = user.Key, Value = user.Value });
        }
        return result;
    }

    public Task<bool> CanSignInAsync(Guid userId)
    {
        return base.Users
            .Where(u => u.Id == userId &&
                (
                    !u.LockoutEnabled ||
                    (
                        u.LockoutEnabled && (u.LockoutEnd == null || u.LockoutEnd < DateTime.UtcNow)
                    )
                )
            )
            .Select(u => u.EmailConfirmed)
            .FirstOrDefaultAsync();
    }

    public async Task<IEnumerable<string>> UserRolesAsync(Guid userId)
    {
        var user = await base.Users
            .Where(m => m.EmailConfirmed && m.UserName != null && m.Id == userId)
            .FirstOrDefaultAsync();
        if (user == null)
        {
            return Enumerable.Empty<string>();
        }

        var roles = await base.UserRoles
            .Where(m => m.UserId == userId)
            .Join(base.Roles, ur => ur.RoleId, r => r.Id, (ur, r) => r.Name)
            .ToArrayAsync();
        if (roles == null)
        {
            return Enumerable.Empty<string>();
        }

        var result = new List<string>();
        foreach (var role in roles)
        {
            if (role == null)
            {
                continue;
            }
            result.Add(role);
        }
        return result;
    }

    public void RemoveApplicationUser(ApplicationUser user) => Users.Remove(user);

    public void RemoveApplicationRole(ApplicationRole role) => Roles.Remove(role);

    public void RemoveApplicationUserRole(IdentityUserRole<Guid> identityRole) => UserRoles.Remove(identityRole);

    public Task AddApplicationUserAsync(ApplicationUser user, CancellationToken token) => Users.AddAsync(user, token).AsTask();

    public Task AddApplicationRoleAsync(ApplicationRole role, CancellationToken token) => Roles.AddAsync(role, token).AsTask();

    public Task AddIdentityUserRoleAsync(IdentityUserRole<Guid> identityRole, CancellationToken token) => UserRoles.AddAsync(identityRole, token).AsTask();
}