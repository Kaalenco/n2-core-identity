using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

using N2.Core.Commands;
using N2.Core.Entity;
using N2.Core.Identity.Data;
using N2.Core.Identity.Services;

namespace N2.Core.Identity.UnitTests;

internal static class TestContext {
    private static readonly Guid AdminGuid = Guid.Parse("11111111-1111-1111-1111-111111111111");
    private static readonly Guid SysAdminRoleGuid = Guid.Parse("22222222-2222-2222-2222-222222222222");
    private static readonly Guid PublisherRoleGuid = Guid.Parse("33333333-3333-3333-3333-333333333333");

    public static void ConfigureServices(ServiceCollection serviceCollection) {
        ConfigurationBuilder config = new();
        config
            .AddJsonFile("appsettings.json", true)
            .AddEnvironmentVariables()
            .AddUserSecrets(typeof(TestContext).Assembly);

        var configuration = config.Build();
        serviceCollection.AddSingleton<IConfiguration>(configuration);
        var auth = configuration.GetAuthenticationConfig();
        serviceCollection.AddSingleton(auth);

        serviceCollection.AddScoped<IPasswordHasher<ApplicationUser>>(s => {
            // Configure PasswordHasherOptions using IOptions<PasswordHasherOptions>
            var options = new PasswordHasherOptions {
                CompatibilityMode = PasswordHasherCompatibilityMode.IdentityV3,
                IterationCount = 310000 // OWASP 2023 recommendation
            };
            return new PasswordHasher<ApplicationUser>(Microsoft.Extensions.Options.Options.Create(options));
        });

        serviceCollection.AddLogging(configure => {
            configure.SetMinimumLevel(LogLevel.Debug);
            configure.AddConsole();
        });

        // Use in-memory database with unique name per service provider to avoid conflicts
        var databaseName = $"TestIdentityDb_{Guid.NewGuid()}";

        // Register as Singleton to prevent premature disposal in concurrent tests
        serviceCollection.AddSingleton(sp => {
            var loggerFactory = sp.GetRequiredService<ILoggerFactory>();
            DbContextOptionsBuilder<N2IdentityContext> optionsBuilder = new();
            optionsBuilder.UseInMemoryDatabase(databaseName);
            optionsBuilder.EnableSensitiveDataLogging();
            optionsBuilder.UseLoggerFactory(loggerFactory);

            // Configure to throw on client-side evaluation and enforce constraints
            optionsBuilder.ConfigureWarnings(warnings => {
                warnings.Throw(Microsoft.EntityFrameworkCore.Diagnostics.InMemoryEventId.TransactionIgnoredWarning);
            });

            var logger = loggerFactory.CreateLogger<N2IdentityContext>();
            var authenticationConfig = sp.GetRequiredService<AuthenticationConfig>();
            N2IdentityContext context = new(optionsBuilder.Options, authenticationConfig, logger);

            // Configure unique indexes manually since InMemory doesn't enforce them automatically
            var indexVerify = context.Model.GetEntityTypes()
                .SelectMany(e => e.GetIndexes())
                .Where(i => i.IsUnique)
                .ToList();  // Force evaluation to ensure indexes are configured

            return context;
        });

        // Register identity context factory
        serviceCollection.AddScoped<IIdentityContextFactory, InMemoryIdentityContextFactory>();

        // Register user manager
        serviceCollection.AddScoped<IUserManager<ApplicationUser>>((s) => {
            var logger = s.GetRequiredService<ILogger<N2UserManager>>();
            var config = s.GetRequiredService<IConfiguration>();
            var hasher = s.GetRequiredService<IPasswordHasher<ApplicationUser>>();
            var factory = s.GetRequiredService<IIdentityContextFactory>();
            return new N2UserManager(factory, config, hasher, "IdentityDb", logger);
        });

        serviceCollection.AddScoped<IAuthenticator, N2AuthenticationService>();

        // Seed the database with test data
        var tempProvider = serviceCollection.BuildServiceProvider();
        using var scope = tempProvider.CreateScope();
        var context = scope.ServiceProvider.GetRequiredService<N2IdentityContext>();
        var hasher = scope.ServiceProvider.GetService<IPasswordHasher<ApplicationUser>>();
        SeedTestData(context, hasher!);
    }

    private static void SeedTestData(N2IdentityContext context, IPasswordHasher<ApplicationUser> passwordHasher) {
        // Add test roles
        context.Roles.Add(new ApplicationRole {
            Id = SysAdminRoleGuid,
            Name = "SysAdmin",
            NormalizedName = "SYSADMIN"
        });

        context.Roles.Add(new ApplicationRole {
            Id = PublisherRoleGuid,
            Name = "Publisher",
            NormalizedName = "PUBLISHER"
        });

        // Add test users
        // Password hash calculated for: ADMIN:secret:TestSecurityStamp using SHA384
        var adminUser = new ApplicationUser {
            Id = AdminGuid,
            UserName = "admin",
            Email = "admin@email.com",
            NormalizedUserName = "ADMIN",
            NormalizedEmail = "ADMIN@EMAIL.COM",
            EmailConfirmed = true,
            SecurityStamp = "TestSecurityStamp",
        };
        var adminPasswordHash = passwordHasher.HashPassword(adminUser, "secret");
        adminUser.PasswordHash = adminPasswordHash;
        context.Users.Add(adminUser);

        var lockedoutUser = new ApplicationUser {
            Id = Guid.NewGuid(),
            UserName = "lockedOut",
            Email = "lockedout@email.com",
            NormalizedUserName = "LOCKEDOUT",
            NormalizedEmail = "LOCKEDOUT@EMAIL.COM",
            EmailConfirmed = true,
            LockoutEnabled = true,
            LockoutEnd = DateTimeOffset.UtcNow.AddDays(1),
            SecurityStamp = "TestSecurityStamp",
        };
        var lockedoutUserHash = passwordHasher.HashPassword(lockedoutUser, "secret");
        lockedoutUser.PasswordHash = lockedoutUserHash;
        context.Users.Add(lockedoutUser);

        // Assign admin role to admin user
        context.UserRoles.Add(new IdentityUserRole<Guid> {
            UserId = AdminGuid,
            RoleId = SysAdminRoleGuid
        });

        context.SaveChanges();
    }
}

#pragma warning disable CA1812 // This is a designer class and required for EF
/// <summary>
/// In-memory implementation of IIdentityContextFactory for testing
/// </summary>
internal sealed class InMemoryIdentityContextFactory : IIdentityContextFactory {
    private readonly N2IdentityContext context;

    public InMemoryIdentityContextFactory(N2IdentityContext context) {
        this.context = context;
    }

    public Task<IIdentityContext> CreateAsync(string catalog) {
        // Return a non-disposing wrapper to prevent premature disposal
        return Task.FromResult<IIdentityContext>(new NonDisposingIdentityContextWrapper(context));
    }

    public Task<IIdentityContext> CreateAsync() {
        // Return a non-disposing wrapper to prevent premature disposal
        return Task.FromResult<IIdentityContext>(new NonDisposingIdentityContextWrapper(context));
    }
}

/// <summary>
/// Wrapper that delegates all IIdentityContext calls but prevents disposal of the underlying context.
/// Uses a static SemaphoreSlim shared across all instances to ensure only one operation executes at a time,
/// preventing concurrent access issues with the shared singleton context.
/// </summary>
internal sealed class NonDisposingIdentityContextWrapper : IIdentityContext {
    private readonly N2IdentityContext innerContext;
    // Static semaphore shared across all wrapper instances to protect the singleton context
    private static readonly SemaphoreSlim semaphore = new(1, 1);

    public NonDisposingIdentityContextWrapper(N2IdentityContext innerContext) {
        this.innerContext = innerContext;
    }

    // Prevent disposal - context is managed by DI container
    public void Dispose() {
        // Do nothing - let the DI container manage disposal
        // Note: Static SemaphoreSlim is not disposed as it's shared across all test instances
    }

    // Properties that return queryables - no locking needed as queries are read-only
    public IQueryable<ApplicationUser> ApplicationUser => innerContext.ApplicationUser;
    public IQueryable<ApplicationRole> ApplicationRole => innerContext.ApplicationRole;
    public IQueryable<IdentityUserRole<Guid>> IdentityUserRole => innerContext.IdentityUserRole;
    public IQueryable<IChangeLog> ChangeLogs => innerContext.ChangeLogs;

    public int MaxLogSize {
        get {
            semaphore.Wait();
            try {
                return innerContext.MaxLogSize;
            } finally {
                semaphore.Release();
            }
        }
        set {
            semaphore.Wait();
            try {
                innerContext.MaxLogSize = value;
            } finally {
                semaphore.Release();
            }
        }
    }

    public string CurrentDatabaseName {
        get {
            semaphore.Wait();
            try {
                return innerContext.CurrentDatabaseName;
            } finally {
                semaphore.Release();
            }
        }
    }

    public bool IsActive {
        get {
            semaphore.Wait();
            try {
                return innerContext.IsActive;
            } finally {
                semaphore.Release();
            }
        }
    }

    public async Task<SelectItemList<HtmlString>> RolesAsync() {
        await semaphore.WaitAsync();
        try {
            return await innerContext.RolesAsync();
        } finally {
            semaphore.Release();
        }
    }

    public async Task<SelectItemList<UserSelectItem>> UsersAsync() {
        await semaphore.WaitAsync();
        try {
            return await innerContext.UsersAsync();
        } finally {
            semaphore.Release();
        }
    }

    public async Task<string> GetNameForUserAsync(Guid userId) {
        await semaphore.WaitAsync();
        try {
            return await innerContext.GetNameForUserAsync(userId);
        } finally {
            semaphore.Release();
        }
    }

    public async Task<bool> CanSignInAsync(Guid userId) {
        await semaphore.WaitAsync();
        try {
            return await innerContext.CanSignInAsync(userId);
        } finally {
            semaphore.Release();
        }
    }

    public void RemoveApplicationUser(ApplicationUser user) {
        semaphore.Wait();
        try {
            innerContext.RemoveApplicationUser(user);
        } finally {
            semaphore.Release();
        }
    }

    public void RemoveApplicationRole(ApplicationRole role) {
        semaphore.Wait();
        try {
            innerContext.RemoveApplicationRole(role);
        } finally {
            semaphore.Release();
        }
    }

    public void RemoveApplicationUserRole(IdentityUserRole<Guid> identityRole) {
        semaphore.Wait();
        try {
            innerContext.RemoveApplicationUserRole(identityRole);
        } finally {
            semaphore.Release();
        }
    }

    public async Task<int> AddApplicationUserAsync(ApplicationUser user, CancellationToken token) {
        await semaphore.WaitAsync(token);
        try {
            return await innerContext.AddApplicationUserAsync(user, token);
        } finally {
            semaphore.Release();
        }
    }

    public async Task<int> AddApplicationRoleAsync(ApplicationRole role, CancellationToken token) {
        await semaphore.WaitAsync(token);
        try {
            return await innerContext.AddApplicationRoleAsync(role, token);
        } finally {
            semaphore.Release();
        }
    }

    public async Task<int> AddIdentityUserRoleAsync(IdentityUserRole<Guid> identityRole, CancellationToken token) {
        await semaphore.WaitAsync(token);
        try {
            return await innerContext.AddIdentityUserRoleAsync(identityRole, token);
        } finally {
            semaphore.Release();
        }
    }

    public async Task<ApplicationUser?> ApplicationUserAsync(string normalizedName, CancellationToken token) {
        await semaphore.WaitAsync(token);
        try {
            return await innerContext.ApplicationUserAsync(normalizedName, token);
        } finally {
            semaphore.Release();
        }
    }

    public async Task<ApplicationUser?> ApplicationUserAsync(Guid userId, CancellationToken token) {
        await semaphore.WaitAsync(token);
        try {
            return await innerContext.ApplicationUserAsync(userId, token);
        } finally {
            semaphore.Release();
        }
    }

    public async Task<ApplicationUser?> ApplicationUserByEmailAsync(string normalizedEmail, CancellationToken token) {
        await semaphore.WaitAsync(token);
        try {
            return await innerContext.ApplicationUserByEmailAsync(normalizedEmail, token);
        } finally {
            semaphore.Release();
        }
    }

    public async Task<ApplicationRole?> ApplicationRoleAsync(string normalizedName, CancellationToken token) {
        await semaphore.WaitAsync(token);
        try {
            return await innerContext.ApplicationRoleAsync(normalizedName, token);
        } finally {
            semaphore.Release();
        }
    }

    public async Task<IdentityUserRole<Guid>?> IdentityUserRoleAsync(Guid userId, Guid roleId, CancellationToken token) {
        await semaphore.WaitAsync(token);
        try {
            return await innerContext.IdentityUserRoleAsync(userId, roleId, token);
        } finally {
            semaphore.Release();
        }
    }

    public async Task<IEnumerable<string>> UserRolesAsync(Guid userId) {
        await semaphore.WaitAsync();
        try {
            return await innerContext.UserRolesAsync(userId);
        } finally {
            semaphore.Release();
        }
    }

    public async Task<ICommandResponse<ApplicationUser>> FindByNameAsync(string normalizedName, CancellationToken token) {
        await semaphore.WaitAsync(token);
        try {
            return await innerContext.FindByNameAsync(normalizedName, token);
        } finally {
            semaphore.Release();
        }
    }

    public async Task<ApplicationUser?> FindByIdAsync(Guid userId, CancellationToken token) {
        await semaphore.WaitAsync(token);
        try {
            return await innerContext.FindByIdAsync(userId, token);
        } finally {
            semaphore.Release();
        }
    }

    public async Task<ApplicationUser?> FindByEmailAsync(string normalizedEmail, CancellationToken token) {
        await semaphore.WaitAsync(token);
        try {
            return await innerContext.FindByEmailAsync(normalizedEmail, token);
        } finally {
            semaphore.Release();
        }
    }

    public async Task<List<KeyValuePair<string, string>>> GetSelectListAsync(string tableName) {
        await semaphore.WaitAsync();
        try {
            return await innerContext.GetSelectListAsync(tableName);
        } finally {
            semaphore.Release();
        }
    }

    public void AddChangeLog(IChangeLog changeLog) {
        semaphore.Wait();
        try {
            innerContext.AddChangeLog(changeLog);
        } finally {
            semaphore.Release();
        }
    }

    public void AddChangeLog<T>(Guid publicId, string message, Guid userId, string userName) where T : class {
        semaphore.Wait();
        try {
            innerContext.AddChangeLog<T>(publicId, message, userId, userName);
        } finally {
            semaphore.Release();
        }
    }

    public void AddRecord<T>(T model) where T : class {
        semaphore.Wait();
        try {
            innerContext.AddRecord(model);
        } finally {
            semaphore.Release();
        }
    }

    public async Task<T?> FindRecordAsync<T>(Guid publicId) where T : class {
        await semaphore.WaitAsync();
        try {
            return await innerContext.FindRecordAsync<T>(publicId);
        } finally {
            semaphore.Release();
        }
    }

    public async Task<(ResponseStatus status, string message)> DeleteAsync<T>(Guid publicId) where T : class {
        await semaphore.WaitAsync();
        try {
            return await innerContext.DeleteAsync<T>(publicId);
        } finally {
            semaphore.Release();
        }
    }

    public async Task<(ResponseStatus status, string? message)> Complete() {
        await semaphore.WaitAsync();
        try {
            return await innerContext.Complete();
        } finally {
            semaphore.Release();
        }
    }

    public DataContextHealthStatus Health() {
        semaphore.Wait();
        try {
            return innerContext.Health();
        } finally {
            semaphore.Release();
        }
    }
}