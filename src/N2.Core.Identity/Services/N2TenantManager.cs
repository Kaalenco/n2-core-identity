using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

using N2.Core.Commands;
using N2.Core.Identity.Data;
using N2.Core.Identity.Models;

using System.Diagnostics.CodeAnalysis;

using static System.Net.Mime.MediaTypeNames;


namespace N2.Core.Identity.Services;

public class N2TenantManager : ITenantManager, IHaveSecrets {

    private readonly DatabaseProvider provider;

    /// <summary>
    /// Gets the name of the database connection used for establishing connections.
    /// </summary>
    private readonly string connectionName;

    private readonly AuthenticationConfig configuration;
    private readonly IIdentityContextFactory factory;
    private readonly ILogger<N2TenantManager> logger;
    private readonly IChangeLogWriter? changeLogWriter;
    private readonly IVaultCallerContext? callerContext;

    public N2TenantManager(
        IIdentityContextFactory identityContextFactory,
        IConfiguration configuration,
        string connectionName,
        ILogger<N2TenantManager> logger,
        DatabaseProvider provider = DatabaseProvider.SqlServer,
        IChangeLogWriter? changeLogWriter = null,
        IVaultCallerContext? callerContext = null) {
        this.factory = identityContextFactory;
        this.connectionName = connectionName;
        this.provider = provider;
        this.logger = logger;
        this.changeLogWriter = changeLogWriter;
        this.callerContext = callerContext;

        this.configuration = configuration.GetAuthenticationConfig();

        // Validate token signing secret
        if (string.IsNullOrEmpty(this.configuration.TokenSigningSecret)) {
            throw new InvalidOperationException(
                "TokenSigningSecret is required in Authentication configuration. " +
                "Generate a secure key using: Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))"
            );
        }

        var secretBytes = Convert.FromBase64String(this.configuration.TokenSigningSecret);
        if (secretBytes.Length < 32) {
            throw new InvalidOperationException(
                $"TokenSigningSecret must be at least 32 bytes (256 bits). Current length: {secretBytes.Length} bytes"
            );
        }
    }

    private Task<IIdentityContext> CreateContextAsync() =>
        factory.CreateAsync(provider, connectionName);

    public async Task<ICommandResponse> CreateAsync([NotNull] ApplicationTenant tenant, CancellationToken ct) {
        using var ctx = await CreateContextAsync();
        // Check for existing tenant
        var existingTenant = await ctx.TenantFindRecord(tenant.NormalizedName!, ct);
        if (existingTenant != null) { 
            return new RequestResult(ResponseStatus.NotAcceptable, $"Tenant '{tenant.NormalizedName}' already exists");
        }

        // normalize name and email
        tenant.NormalizedName = tenant.Name?.Trim().ToUpperInvariant();
        tenant.NormalizedEmail = tenant.AdminEmail?.Trim().ToUpperInvariant();

        // Add new tenant
        await ctx.TenantAdd(tenant, ct);
        (var code, var message) = await ctx.Complete();
        return new RequestResult(code, message ?? string.Empty);
    }

    public async Task<ICommandResponse> DeleteAsync([NotNull] ApplicationTenant tenant, CancellationToken ct) {
        ArgumentNullException.ThrowIfNull(tenant);
        ArgumentOutOfRangeException.ThrowIfEqual(tenant.Id, Guid.Empty);

        using var ctx = await CreateContextAsync();
        var existing = await ctx.TenantFindRecord(tenant.Id, ct);
        if (existing == null) {
            return new RequestResult(ResponseStatus.NotFound, $"Tenant '{tenant.Id}' not found");
        }

        ctx.TenantDelete(existing);
        (var code, var message) = await ctx.Complete();
        return new RequestResult(code, message ?? string.Empty);
    }

    public async Task<ICommandResponse> UpdateAsync([NotNull] ApplicationTenant tenant, CancellationToken ct) {
        ArgumentNullException.ThrowIfNull(tenant);
        ArgumentOutOfRangeException.ThrowIfEqual(tenant.Id, Guid.Empty);
        ArgumentException.ThrowIfNullOrWhiteSpace(tenant.Name);

        using var ctx = await CreateContextAsync();
        var existing = await ctx.TenantFindRecord(tenant.Id, ct);
        if (existing == null) {
            return new RequestResult(ResponseStatus.NotFound, $"Tenant '{tenant.Id}' not found");
        }

        existing.Name = tenant.Name.Trim();
        existing.NormalizedName = existing.Name.ToUpperInvariant();
        existing.Address = tenant.Address?.Trim();
        existing.AdminEmail = tenant.AdminEmail?.Trim();
        existing.NormalizedEmail = tenant.AdminEmail?.Trim().ToUpperInvariant();
        existing.ContactInfo = tenant.ContactInfo?.Trim();
        existing.ImagePath = tenant.ImagePath?.Trim();
        existing.UserLimit = tenant.UserLimit != 0 ? tenant.UserLimit : existing.UserLimit;
        existing.IsHidden = tenant.IsHidden;
        existing.MfaSecret = string.IsNullOrEmpty(tenant.MfaSecret) ? existing.MfaSecret : tenant.MfaSecret;

        (var code, var message) = await ctx.Complete();
        return new RequestResult(code, message ?? string.Empty);
    }

    public async Task<ApplicationTenant?> FindByIdAsync(Guid tenantId, CancellationToken ct) {
        ArgumentOutOfRangeException.ThrowIfEqual(tenantId, Guid.Empty);

        using var ctx = await CreateContextAsync();
        return await ctx.TenantFindRecord(tenantId, ct);
    }

    public async Task<ApplicationTenant?> FindByNameAsync(string name, CancellationToken ct) {
        ArgumentException.ThrowIfNullOrEmpty(name);

        using var ctx = await CreateContextAsync();
        return await ctx.TenantFindRecord(name.Trim().ToUpperInvariant(), ct);
    }

    public async Task<ApplicationTenant?> FindByEmailAsync(string email, CancellationToken ct) {
        ArgumentException.ThrowIfNullOrEmpty(email);

        using var ctx = await CreateContextAsync();
        return await ctx.TenantFindRecordByEmail(email.Trim().ToUpperInvariant(), ct);
    }

    public async Task<SelectItemList<UserSelectItem>> GetTenantsAsync(CancellationToken ct) {
        using var ctx = await CreateContextAsync();
        return await ctx.TenantGetSelectList(ct);
    }

    public async Task<ICommandResponse> LockAsync([NotNull] ApplicationTenant tenant, CancellationToken ct) {
        ArgumentNullException.ThrowIfNull(tenant);
        ArgumentOutOfRangeException.ThrowIfEqual(tenant.Id, Guid.Empty);

        using var ctx = await CreateContextAsync();
        var existing = await ctx.TenantFindRecord(tenant.Id, ct);
        if (existing == null) {
            return new RequestResult(ResponseStatus.NotFound, $"Tenant '{tenant.Id}' not found");
        }

        existing.IsLocked = true;
        (var code, var message) = await ctx.Complete();
        return new RequestResult(code, message ?? string.Empty);
    }

    public async Task<ICommandResponse> UnlockAsync([NotNull] ApplicationTenant tenant, CancellationToken ct) {
        ArgumentNullException.ThrowIfNull(tenant);
        ArgumentOutOfRangeException.ThrowIfEqual(tenant.Id, Guid.Empty);

        using var ctx = await CreateContextAsync();
        var existing = await ctx.TenantFindRecord(tenant.Id, ct);
        if (existing == null) {
            return new RequestResult(ResponseStatus.NotFound, $"Tenant '{tenant.Id}' not found");
        }

        existing.IsLocked = false;
        (var code, var message) = await ctx.Complete();
        return new RequestResult(code, message ?? string.Empty);
    }

    private void Log(Guid referenceId, string message) {
        changeLogWriter?.Add(new QueueLogEntry {
            LogRecordId = Guid.NewGuid(),
            TableName = nameof(ApplicationUserTenant),
            ReferenceId = referenceId,
            Message = message,
            CreatedBy = callerContext?.CallerId ?? Guid.Empty,
            CreatedByName = callerContext?.CallerName ?? "system",
            Created = DateTime.UtcNow
        });
    }

    public Task<ICommandResponse> AddUserAsync([NotNull] ApplicationUser user, [NotNull] ApplicationTenant tenant, CancellationToken ct)
        => AddUserAsync(user, tenant, isAdmin: false, ct);

    public async Task<ICommandResponse> AddUserAsync([NotNull] ApplicationUser user, [NotNull] ApplicationTenant tenant, bool isAdmin, CancellationToken ct) {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(tenant);
        ArgumentOutOfRangeException.ThrowIfEqual(user.Id, Guid.Empty);
        ArgumentOutOfRangeException.ThrowIfEqual(tenant.Id, Guid.Empty);

        using var ctx = await CreateContextAsync();
        var existingTenant = await ctx.TenantFindRecord(tenant.Id, ct);
        if (existingTenant == null) {
            return new RequestResult(ResponseStatus.NotFound, $"Tenant '{tenant.Id}' not found");
        }

        var existingUser = await ctx.UserFindRecord(user.Id, ct);
        if (existingUser == null) {
            return new RequestResult(ResponseStatus.NotFound, $"User '{user.Id}' not found");
        }

        // Idempotent: already assigned — only update IsAdmin if it differs
        var existing = await ctx.UserTenant
            .Where(ut => ut.ApplicationUserId == user.Id && ut.ApplicationTenantId == tenant.Id)
            .FirstOrDefaultAsync(ct);
        if (existing != null) {
            if (existing.IsAdmin == isAdmin)
                return RequestResult.Ok();
            (var updateCode, var updateMsg) = await ctx.UserTenantSetAdmin(user.Id, tenant.Id, isAdmin, ct);
            Log(user.Id, isAdmin ? $"Granted admin in tenant '{tenant.Id}'" : $"Revoked admin in tenant '{tenant.Id}'");
            return new RequestResult(updateCode, updateMsg ?? string.Empty);
        }

        var userTenant = new ApplicationUserTenant {
            Id = Guid.NewGuid(),
            ApplicationUserId = user.Id,
            ApplicationTenantId = tenant.Id,
            IsAdmin = isAdmin
        };
        await ctx.UserTenantAdd(userTenant, ct);
        (var code, var message) = await ctx.Complete();
        Log(user.Id, isAdmin ? $"Added to tenant '{tenant.Id}' as admin" : $"Added to tenant '{tenant.Id}'");
        return new RequestResult(code, message ?? string.Empty);
    }

    public async Task<ICommandResponse> RemoveUserAsync([NotNull] ApplicationUser user, [NotNull] ApplicationTenant tenant, CancellationToken ct) {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(tenant);
        ArgumentOutOfRangeException.ThrowIfEqual(user.Id, Guid.Empty);
        ArgumentOutOfRangeException.ThrowIfEqual(tenant.Id, Guid.Empty);

        using var ctx = await CreateContextAsync();
        var userTenant = await ctx.UserTenant
            .FirstOrDefaultAsync(ut => ut.ApplicationUserId == user.Id && ut.ApplicationTenantId == tenant.Id, ct);

        // Idempotent: already removed is not an error
        if (userTenant == null) {
            return RequestResult.Ok();
        }

        ctx.UserTenantDelete(userTenant);
        (var code, var message) = await ctx.Complete();
        return new RequestResult(code, message ?? string.Empty);
    }

    public async Task<ICommandResponse> SetAdminAsync([NotNull] ApplicationUser user, [NotNull] ApplicationTenant tenant, bool isAdmin, CancellationToken ct) {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(tenant);
        ArgumentOutOfRangeException.ThrowIfEqual(user.Id, Guid.Empty);
        ArgumentOutOfRangeException.ThrowIfEqual(tenant.Id, Guid.Empty);

        using var ctx = await CreateContextAsync();
        (var code, var message) = await ctx.UserTenantSetAdmin(user.Id, tenant.Id, isAdmin, ct);
        if (code == ResponseStatus.Success && message != "No change required.")
            Log(user.Id, isAdmin ? $"Granted admin in tenant '{tenant.Id}'" : $"Revoked admin in tenant '{tenant.Id}'");
        return new RequestResult(code, message ?? string.Empty);
    }

    public async Task<bool> IsAdminAsync(Guid userId, Guid tenantId, CancellationToken ct) {
        ArgumentOutOfRangeException.ThrowIfEqual(userId, Guid.Empty);
        ArgumentOutOfRangeException.ThrowIfEqual(tenantId, Guid.Empty);

        using var ctx = await CreateContextAsync();
        return await ctx.UserTenantIsAdmin(userId, tenantId, ct);
    }

    public async Task<IEnumerable<Guid>> GetAdminsForTenantAsync(Guid tenantId, CancellationToken ct) {
        ArgumentOutOfRangeException.ThrowIfEqual(tenantId, Guid.Empty);

        using var ctx = await CreateContextAsync();
        return await ctx.UserTenant
            .AsNoTracking()
            .Where(ut => ut.ApplicationTenantId == tenantId && ut.IsAdmin)
            .Select(ut => ut.ApplicationUserId)
            .ToListAsync(ct);
    }

    public async Task<IEnumerable<string>> GetUsersForTenantAsync(Guid tenantId, CancellationToken ct) {
        ArgumentOutOfRangeException.ThrowIfEqual(tenantId, Guid.Empty);

        using var ctx = await CreateContextAsync();
        return await ctx.TenantGetUsers(tenantId, ct);
    }

    public async Task<IEnumerable<Guid>> GetTenantIdsForUserAsync(Guid userId, CancellationToken ct) {
        ArgumentOutOfRangeException.ThrowIfEqual(userId, Guid.Empty);

        using var ctx = await CreateContextAsync();
        return await ctx.UserTenant
            .AsNoTracking()
            .Where(ut => ut.ApplicationUserId == userId)
            .Select(ut => ut.ApplicationTenantId)
            .ToListAsync(ct);
    }

    public async Task<bool> ApplicationUserCanSignIn(Guid userId, Guid tenantId, CancellationToken ct) {
        ArgumentOutOfRangeException.ThrowIfEqual(userId, Guid.Empty);
        ArgumentOutOfRangeException.ThrowIfEqual(tenantId, Guid.Empty);

        using var ctx = await CreateContextAsync();
        return await ctx.UserCanSignInTenant(userId, tenantId, ct);
    }

    public async Task<ISecretOwner?> GetSecretOwner(Guid id, CancellationToken ct) {
        using var ctx = await CreateContextAsync();
        var dbTenant = await ctx.TenantFindRecord(id, ct);
        if (dbTenant == null) {
            return null;
        }
        if (dbTenant.SecretKeyMaterial == null || dbTenant.SecretKeyMaterial.Length == 0) {
            logger.LogMfaSecretNotSet(dbTenant.Name ?? dbTenant.Id.ToString());
            throw new InvalidOperationException("SecretKeyMaterial is not set for tenant. Provision key material before creating secrets.");
        }
        return new SecretOwner(dbTenant.Id, OwnerTypeCode.Tenant, dbTenant.SecretKeyMaterial);
    }

    public Task<ISecretManager> GetSecretManager(CancellationToken ct) {
        return Task.FromResult<ISecretManager>(
            new N2SecretManager(factory, provider, connectionName, configuration, logger, changeLogWriter, callerContext));
    }
}

