using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

using N2.Core.Commands;
using N2.Core.Entity;
using N2.Core.Identity.Data;
using N2.Core.Identity.Services;

using System.Security.Cryptography;

using static Microsoft.ApplicationInsights.MetricDimensionNames.TelemetryContext;

namespace N2.Core.Identity.UnitTests;

internal static class TestContext {
    private static readonly Guid AdminGuid = Guid.Parse("11111111-1111-1111-1111-111111111111");
    private static readonly Guid SysAdminRoleGuid = Guid.Parse("22222222-2222-2222-2222-222222222222");
    private static readonly Guid PublisherRoleGuid = Guid.Parse("33333333-3333-3333-3333-333333333333");
    public static readonly Guid TenantGuid = Guid.Parse("44444444-4444-4444-4444-444444444444");
    public static readonly Guid LockedTenantGuid = Guid.Parse("55555555-5555-5555-5555-555555555555");
    public static readonly Guid ApplicationGuid = Guid.Parse("66666666-6666-6666-6666-666666666666");

    public static void ConfigureServices(ServiceCollection serviceCollection) {
        ConfigurationBuilder config = new();

        config
            .AddInMemoryCollection(new Dictionary<string, string?> {
                ["AuthenticationConfig:TokenSigningSecret"] = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
                ["AuthenticationConfig:SecretEncryptionKey"] = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
                ["AuthenticationConfig:MfaTokenSecret"] = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
                ["AuthenticationConfig:JwtSettings:Secret"] = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
                ["AuthenticationConfig:JwtSettings:Issuer"] = "http://localhost:8080",
                ["AuthenticationConfig:JwtSettings:Audience"] = "http://localhost:8081",
            })
            //.AddEnvironmentVariables()
            //.AddJsonFile("appsettings.json", true)
            //.AddUserSecrets(typeof(TestContext).Assembly)
            ;

        var configuration = config.Build();
        serviceCollection.AddSingleton<IConfiguration>(configuration);
        var auth = configuration.GetAuthenticationConfig();
        serviceCollection.AddSingleton(auth);
        serviceCollection.AddMemoryCache();
        serviceCollection.AddSingleton<IRateLimiter>(s => {
            var config = s.GetAuthenticationConfig();
            var mcache = s.GetRequiredService<IMemoryCache>();
            var logger = s.GetRequiredService<ILogger<RateLimiter>>();
            return new RateLimiter(mcache, logger, config.MfaMaxAttempts, config.MfaLockoutMinutes);
        });

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
            N2IdentityContext context = new(optionsBuilder.Options, logger);

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
            var rateLimiter = s.GetRequiredService<IRateLimiter>();
            var hasher = s.GetRequiredService<IPasswordHasher<ApplicationUser>>();
            var factory = s.GetRequiredService<IIdentityContextFactory>();
            return new N2UserManager(factory, config, rateLimiter, hasher, "IdentityDb", logger);
        });

        // Register N2-specific user manager interface (exposes GetSecretOwner)
        serviceCollection.AddScoped<IN2UserManager>((s) => {
            var logger = s.GetRequiredService<ILogger<N2UserManager>>();
            var config = s.GetRequiredService<IConfiguration>();
            var rateLimiter = s.GetRequiredService<IRateLimiter>();
            var hasher = s.GetRequiredService<IPasswordHasher<ApplicationUser>>();
            var factory = s.GetRequiredService<IIdentityContextFactory>();
            return new N2UserManager(factory, config, rateLimiter, hasher, "IdentityDb", logger);
        });

        // Register tenant manager
        serviceCollection.AddScoped<ITenantManager>((s) => {
            var logger = s.GetRequiredService<ILogger<N2TenantManager>>();
            var config = s.GetRequiredService<IConfiguration>();
            var factory = s.GetRequiredService<IIdentityContextFactory>();
            return new N2TenantManager(factory, config, "IdentityDb", logger);
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

        // Add tenants for tenant tests
        context.Tenants.Add(new ApplicationTenant {
            Id = TenantGuid,
            Name = "Test Tenant",
            NormalizedName = "TEST TENANT",
            AdminEmail = "admin@testtenant.com",
            NormalizedEmail = "ADMIN@TESTTENANT.COM",
            IsLocked = false
        });
        context.Tenants.Add(new ApplicationTenant {
            Id = LockedTenantGuid,
            Name = "Locked Tenant",
            NormalizedName = "LOCKED TENANT",
            IsLocked = true
        });

        // Add seeded application linked to the active tenant
        context.ApplicationDefinitions.Add(new ApplicationDefinition {
            Id = ApplicationGuid,
            Name = "Test App",
            NormalizedName = "TEST APP",
            ApplicationTenantId = TenantGuid,
            IsLocked = false
        });

        // Link admin user to the active tenant as admin
        context.UserTenants.Add(new ApplicationUserTenant {
            Id = Guid.NewGuid(),
            ApplicationUserId = AdminGuid,
            ApplicationTenantId = TenantGuid,
            IsAdmin = true
        });
        // Link admin user to the locked tenant as admin
        context.UserTenants.Add(new ApplicationUserTenant {
            Id = Guid.NewGuid(),
            ApplicationUserId = AdminGuid,
            ApplicationTenantId = LockedTenantGuid,
            IsAdmin = true
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

    public Task<IIdentityContext> CreateAsync(DatabaseProvider provider) => CreateAsync();

    public Task<IIdentityContext> CreateAsync(DatabaseProvider provider, string connectionName) => CreateAsync(connectionName);
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
    public Task<ICommandResponse<ApplicationUser>> UserFind(string name, CancellationToken ct) => innerContext.UserFind(name, ct);
    public IQueryable<ApplicationUser> User => innerContext.Users;
    public IQueryable<ApplicationRole> Role => innerContext.Roles;
    public IQueryable<IdentityUserRole<Guid>> UserRole => innerContext.UserRoles;
    public IQueryable<ApplicationUserTenant> UserTenant => innerContext.UserTenants;
    public IQueryable<ApplicationTenant> Tenant => innerContext.Tenants;
    public IQueryable<ApplicationDefinition> Application => innerContext.ApplicationDefinitions;
    public IQueryable<ApplicationSecret> ApplicationSecret => innerContext.ApplicationSecrets;
    public IQueryable<ApplicationRefreshToken> RefreshToken => innerContext.RefreshToken;

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

    public async Task<SelectItemList<HtmlString>> RoleGetSelectList(CancellationToken ct) {
        await semaphore.WaitAsync(ct);
        try {
            return await innerContext.RoleGetSelectList(ct);
        } finally {
            semaphore.Release();
        }
    }

    public async Task<SelectItemList<UserSelectItem>> UserGetSelectList(CancellationToken ct) {
        await semaphore.WaitAsync(ct);
        try {
            return await innerContext.UserGetSelectList(ct);
        } finally {
            semaphore.Release();
        }
    }

    public async Task<SelectItemList<UserSelectItem>> TenantGetSelectList(CancellationToken ct) {
        await semaphore.WaitAsync(ct);
        try {
            return await innerContext.TenantGetSelectList(ct);
        } finally {
            semaphore.Release();
        }
    }

    public async Task<SelectItemList<HtmlString>> ApplicationGetSelectList(Guid tenantId, CancellationToken ct) {
        await semaphore.WaitAsync(ct);
        try {
            return await innerContext.ApplicationGetSelectList(tenantId, ct);
        } finally {
            semaphore.Release();
        }
    }

    public async Task<ApplicationDefinition?> ApplicationFindRecord(Guid applicationId, CancellationToken ct) {
        await semaphore.WaitAsync(ct);
        try {
            return await innerContext.ApplicationFindRecord(applicationId, ct);
        } finally {
            semaphore.Release();
        }
    }

    public async Task<ApplicationDefinition?> ApplicationFindRecord(Guid tenantId, string name, CancellationToken ct) {
        await semaphore.WaitAsync(ct);
        try {
            return await innerContext.ApplicationFindRecord(tenantId, name, ct);
        } finally {
            semaphore.Release();
        }
    }

    public async Task<string> ApplicationGetName(Guid applicationId, CancellationToken ct) {
        await semaphore.WaitAsync(ct);
        try {
            return await innerContext.ApplicationGetName(applicationId, ct);
        } finally {
            semaphore.Release();
        }
    }

    public void ApplicationDelete(ApplicationDefinition application) {
        semaphore.Wait();
        try {
            innerContext.ApplicationDelete(application);
        } finally {
            semaphore.Release();
        }
    }

    public async Task<int> ApplicationAdd(ApplicationDefinition application, CancellationToken ct) {
        await semaphore.WaitAsync(ct);
        try {
            return await innerContext.ApplicationAdd(application, ct);
        } finally {
            semaphore.Release();
        }
    }

    public async Task<ApplicationSecret?> SecretFindRecord(Guid applicationSecretId, CancellationToken ct) {
        await semaphore.WaitAsync(ct);
        try {
            return await innerContext.SecretFindRecord(applicationSecretId, ct);
        } finally {
            semaphore.Release();
        }
    }

    public async Task<ApplicationSecret?> SecretFindRecord(string hashedToken, CancellationToken ct) {
        await semaphore.WaitAsync(ct);
        try {
            return await innerContext.SecretFindRecord(hashedToken, ct);
        } finally {
            semaphore.Release();
        }
    }

    public void SecretAdd(ApplicationSecret secret) {
        semaphore.Wait();
        try {
            innerContext.SecretAdd(secret);
        } finally {
            semaphore.Release();
        }
    }

    public void SecretDelete(ApplicationSecret secret) {
        semaphore.Wait();
        try {
            innerContext.SecretDelete(secret);
        } finally {
            semaphore.Release();
        }
    }

    public async Task<SelectItemList<HtmlString>> SecretGetSelectList(Guid ownerId, string ownerType, CancellationToken ct) {
        await semaphore.WaitAsync(ct);
        try {
            return await innerContext.SecretGetSelectList(ownerId, ownerType, ct);
        } finally {
            semaphore.Release();
        }
    }

    public async Task<string> UserGetName(Guid userId, CancellationToken ct) {
        await semaphore.WaitAsync(ct);
        try {
            return await innerContext.UserGetName(userId, ct);
        } finally {
            semaphore.Release();
        }
    }

    public async Task<string> TenantGetName(Guid tenantId, CancellationToken ct) {
        await semaphore.WaitAsync(ct);
        try {
            return await innerContext.TenantGetName(tenantId, ct);
        } finally {
            semaphore.Release();
        }
    }

    public async Task<bool> UserCanSignIn(Guid userId, CancellationToken ct) {
        await semaphore.WaitAsync(ct);
        try {
            return await innerContext.UserCanSignIn(userId, ct);
        } finally {
            semaphore.Release();
        }
    }

    public async Task<bool> UserCanSignInTenant(Guid userId, Guid tenantId, CancellationToken ct) {
        await semaphore.WaitAsync(ct);
        try {
            return await innerContext.UserCanSignInTenant(userId, tenantId, ct);
        } finally {
            semaphore.Release();
        }
    }

    public void TenantDelete(ApplicationTenant tenant) {
        semaphore.Wait();
        try {
            innerContext.TenantDelete(tenant);
        } finally {
            semaphore.Release();
        }
    }

    public void UserDelete(ApplicationUser user) {
        semaphore.Wait();
        try {
            innerContext.UserDelete(user);
        } finally {
            semaphore.Release();
        }
    }

    public void RoleDelete(ApplicationRole role) {
        semaphore.Wait();
        try {
            innerContext.RoleDelete(role);
        } finally {
            semaphore.Release();
        }
    }

    public void UserRoleDelete(IdentityUserRole<Guid> identityRole) {
        semaphore.Wait();
        try {
            innerContext.UserRoleDelete(identityRole);
        } finally {
            semaphore.Release();
        }
    }

    public void UserTenantDelete(ApplicationUserTenant userTenant) {
        semaphore.Wait();
        try {
            innerContext.UserTenantDelete(userTenant);
        } finally {
            semaphore.Release();
        }
    }

    public async Task<int> TenantAdd(ApplicationTenant tenant, CancellationToken ct) {
        await semaphore.WaitAsync(ct);
        try {
            return await innerContext.TenantAdd(tenant, ct);
        } finally {
            semaphore.Release();
        }
    }

    public async Task<int> UserAdd(ApplicationUser user, CancellationToken ct) {
        await semaphore.WaitAsync(ct);
        try {
            return await innerContext.UserAdd(user, ct);
        } finally {
            semaphore.Release();
        }
    }

    public async Task<int> RoleAdd(ApplicationRole role, CancellationToken ct) {
        await semaphore.WaitAsync(ct);
        try {
            return await innerContext.RoleAdd(role, ct);
        } finally {
            semaphore.Release();
        }
    }

    public async Task<int> UserRoleAdd(IdentityUserRole<Guid> identityRole, CancellationToken ct) {
        await semaphore.WaitAsync(ct);
        try {
            return await innerContext.UserRoleAdd(identityRole, ct);
        } finally {
            semaphore.Release();
        }
    }

    public async Task<int> UserTenantAdd(ApplicationUserTenant identityUserTenant, CancellationToken ct) {
        await semaphore.WaitAsync(ct);
        try {
            return await innerContext.UserTenantAdd(identityUserTenant, ct);
        } finally {
            semaphore.Release();
        }
    }

    public async Task<bool> UserTenantIsAdmin(Guid userId, Guid tenantId, CancellationToken ct) {
        await semaphore.WaitAsync(ct);
        try {
            return await innerContext.UserTenantIsAdmin(userId, tenantId, ct);
        } finally {
            semaphore.Release();
        }
    }

    public async Task<(ResponseStatus status, string? message)> UserTenantSetAdmin(Guid userId, Guid tenantId, bool isAdmin, CancellationToken ct) {
        await semaphore.WaitAsync(ct);
        try {
            return await innerContext.UserTenantSetAdmin(userId, tenantId, isAdmin, ct);
        } finally {
            semaphore.Release();
        }
    }

    public async Task<ApplicationUser?> UserFindRecord(string normalizedName, CancellationToken ct) {
        await semaphore.WaitAsync(ct);
        try {
            return await innerContext.UserFindRecord(normalizedName, ct);
        } finally {
            semaphore.Release();
        }
    }

    public async Task<ApplicationUser?> UserFindRecord(Guid userId, CancellationToken ct) {
        await semaphore.WaitAsync(ct);
        try {
            return await innerContext.UserFindRecord(userId, ct);
        } finally {
            semaphore.Release();
        }
    }

    public async Task<ApplicationUser?> UserFindRecordByEmail(string normalizedEmail, CancellationToken ct) {
        await semaphore.WaitAsync(ct);
        try {
            return await innerContext.UserFindRecordByEmail(normalizedEmail, ct);
        } finally {
            semaphore.Release();
        }
    }

    public async Task<ApplicationRole?> RoleFindRecord(string normalizedName, CancellationToken ct) {
        await semaphore.WaitAsync(ct);
        try {
            return await innerContext.RoleFindRecord(normalizedName, ct);
        } finally {
            semaphore.Release();
        }
    }

    public async Task<ApplicationTenant?> TenantFindRecord(string normalizedName, CancellationToken ct) {
        await semaphore.WaitAsync(ct);
        try {
            return await innerContext.TenantFindRecord(normalizedName, ct);
        } finally {
            semaphore.Release();
        }
    }

    public async Task<ApplicationTenant?> TenantFindRecord(Guid tenantId, CancellationToken ct) {
        await semaphore.WaitAsync(ct);
        try {
            return await innerContext.TenantFindRecord(tenantId, ct);
        } finally {
            semaphore.Release();
        }
    }

    public async Task<ApplicationTenant?> TenantFindRecordByEmail(string normalizedEmail, CancellationToken ct) {
        await semaphore.WaitAsync(ct);
        try {
            return await innerContext.TenantFindRecordByEmail(normalizedEmail, ct);
        } finally {
            semaphore.Release();
        }
    }

    public async Task<IdentityUserRole<Guid>?> UserRoleFindRecord(Guid userId, Guid roleId, CancellationToken ct) {
        await semaphore.WaitAsync(ct);
        try {
            return await innerContext.UserRoleFindRecord(userId, roleId, ct);
        } finally {
            semaphore.Release();
        }
    }

    public async Task<IEnumerable<string>> UserGetRoles(Guid userId, CancellationToken ct) {
        await semaphore.WaitAsync(ct);
        try {
            return await innerContext.UserGetRoles(userId, ct);
        } finally {
            semaphore.Release();
        }
    }

    public async Task<IEnumerable<string>> TenantGetUsers(Guid tenantId, CancellationToken ct) {
        await semaphore.WaitAsync(ct);
        try {
            return await innerContext.TenantGetUsers(tenantId, ct);
        } finally {
            semaphore.Release();
        }
    }

    public async Task<List<KeyValuePair<string, string>>> GetSelectListAsync(string tableName) {
        await semaphore.WaitAsync(CancellationToken.None);
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
        await semaphore.WaitAsync(CancellationToken.None);
        try {
            return await innerContext.FindRecordAsync<T>(publicId);
        } finally {
            semaphore.Release();
        }
    }

    public async Task<(ResponseStatus status, string message)> DeleteAsync<T>(Guid publicId) where T : class {
        await semaphore.WaitAsync(CancellationToken.None);
        try {
            return await innerContext.DeleteAsync<T>(publicId);
        } finally {
            semaphore.Release();
        }
    }

    public async Task<(ResponseStatus status, string? message)> Complete() {
        await semaphore.WaitAsync(CancellationToken.None);
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

    public async Task<int> UserAlertAdd(ApplicationUserAlert alert, CancellationToken ct) {
        await semaphore.WaitAsync(ct);
        try {
            return await innerContext.UserAlertAdd(alert, ct);
        } finally {
            semaphore.Release();
        }
    }

    public async Task<ApplicationRefreshToken?> RefreshTokenFind(string token, CancellationToken ct) {
        await semaphore.WaitAsync(ct);
        try {
            return await innerContext.RefreshTokenFind(token, ct);
        } finally {
            semaphore.Release();
        }
    }

    public void RefreshTokenAdd(ApplicationRefreshToken token) => innerContext.RefreshTokenAdd(token);

    public void RefreshTokenRevoke(ApplicationRefreshToken token) => innerContext.RefreshTokenRevoke(token);

    public async Task<int> RefreshTokenPurgeStale(Guid userId, CancellationToken ct) {
        await semaphore.WaitAsync(ct);
        try {
            return await innerContext.RefreshTokenPurgeStale(userId, ct);
        } finally {
            semaphore.Release();
        }
    }

    public async Task RefreshTokenRevokeAll(Guid userId, CancellationToken ct) {
        await semaphore.WaitAsync(ct);
        try {
            await innerContext.RefreshTokenRevokeAll(userId, ct);
        } finally {
            semaphore.Release();
        }
    }

    public async Task<int> RefreshTokenPurgeExpired(CancellationToken ct) {
        await semaphore.WaitAsync(ct);
        try {
            return await innerContext.RefreshTokenPurgeExpired(ct);
        } finally {
            semaphore.Release();
        }
    }
}