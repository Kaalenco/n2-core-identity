using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

using N2.Core.Commands;
using N2.Core.Identity.Data;

using System.Diagnostics.CodeAnalysis;

using static System.Net.Mime.MediaTypeNames;


namespace N2.Core.Identity.Services;

public class N2TenantManager : ITenantManager {

    private readonly DatabaseProvider provider;

    /// <summary>
    /// Gets the name of the database connection used for establishing connections.
    /// </summary>
    private readonly string connectionName;

    private readonly AuthenticationConfig configuration;
    private readonly IIdentityContextFactory factory;
    private readonly ILogger<N2TenantManager> logger;

    public N2TenantManager(
        IIdentityContextFactory identityContextFactory,
        IConfiguration configuration,
        string connectionName,
        ILogger<N2TenantManager> logger,
        DatabaseProvider provider = DatabaseProvider.SqlServer) {
        this.factory = identityContextFactory;
        this.connectionName = connectionName;
        this.provider = provider;
        this.logger = logger;


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

    public async Task<ICommandResponse> CreateAsync([NotNull] ApplicationTenant tenant, CancellationToken token) {
        using var ctx = await CreateContextAsync();
        // Check for existing tenant
        var existingTenant = await ctx.ApplicationTenantAsync(tenant.NormalizedName!, token);
        if (existingTenant != null) { 
            return new RequestResult(ResponseStatus.NotAcceptable, $"Tenant '{tenant.NormalizedName}' already exists");
        }

        // normalize name and email
        tenant.NormalizedName = tenant.Name?.Trim().ToUpperInvariant();
        tenant.NormalizedEmail = tenant.AdminEmail?.Trim().ToUpperInvariant();

        // Add new tenant
        await ctx.AddApplicationTenantAsync(tenant, token);
        (var code, var message) = await ctx.Complete();
        return new RequestResult(code, message ?? string.Empty);
    }

    public async Task<ICommandResponse> DeleteAsync([NotNull] ApplicationTenant tenant, CancellationToken token) {
        ArgumentNullException.ThrowIfNull(tenant);
        ArgumentOutOfRangeException.ThrowIfEqual(tenant.Id, Guid.Empty);

        using var ctx = await CreateContextAsync();
        var existing = await ctx.FindTenantByIdAsync(tenant.Id, token);
        if (existing == null) {
            return new RequestResult(ResponseStatus.NotFound, $"Tenant '{tenant.Id}' not found");
        }

        ctx.RemoveApplicationTenant(existing);
        (var code, var message) = await ctx.Complete();
        return new RequestResult(code, message ?? string.Empty);
    }

    public async Task<ICommandResponse> UpdateAsync([NotNull] ApplicationTenant tenant, CancellationToken token) {
        ArgumentNullException.ThrowIfNull(tenant);
        ArgumentOutOfRangeException.ThrowIfEqual(tenant.Id, Guid.Empty);
        ArgumentException.ThrowIfNullOrWhiteSpace(tenant.Name);

        using var ctx = await CreateContextAsync();
        var existing = await ctx.FindTenantByIdAsync(tenant.Id, token);
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

    public async Task<ApplicationTenant?> FindByIdAsync(Guid tenantId, CancellationToken token) {
        ArgumentOutOfRangeException.ThrowIfEqual(tenantId, Guid.Empty);

        using var ctx = await CreateContextAsync();
        return await ctx.FindTenantByIdAsync(tenantId, token);
    }

    public async Task<ApplicationTenant?> FindByNameAsync(string name, CancellationToken token) {
        ArgumentException.ThrowIfNullOrEmpty(name);

        using var ctx = await CreateContextAsync();
        return await ctx.ApplicationTenantAsync(name.Trim().ToUpperInvariant(), token);
    }

    public async Task<ApplicationTenant?> FindByEmailAsync(string email, CancellationToken token) {
        ArgumentException.ThrowIfNullOrEmpty(email);

        using var ctx = await CreateContextAsync();
        return await ctx.FindTenantByEmailAsync(email.Trim().ToUpperInvariant(), token);
    }

    public async Task<SelectItemList<UserSelectItem>> GetTenantsAsync(CancellationToken token) {
        using var ctx = await CreateContextAsync();
        return await ctx.TenantsAsync();
    }

    public async Task<ICommandResponse> LockAsync([NotNull] ApplicationTenant tenant, CancellationToken token) {
        ArgumentNullException.ThrowIfNull(tenant);
        ArgumentOutOfRangeException.ThrowIfEqual(tenant.Id, Guid.Empty);

        using var ctx = await CreateContextAsync();
        var existing = await ctx.FindTenantByIdAsync(tenant.Id, token);
        if (existing == null) {
            return new RequestResult(ResponseStatus.NotFound, $"Tenant '{tenant.Id}' not found");
        }

        existing.IsLocked = true;
        (var code, var message) = await ctx.Complete();
        return new RequestResult(code, message ?? string.Empty);
    }

    public async Task<ICommandResponse> UnlockAsync([NotNull] ApplicationTenant tenant, CancellationToken token) {
        ArgumentNullException.ThrowIfNull(tenant);
        ArgumentOutOfRangeException.ThrowIfEqual(tenant.Id, Guid.Empty);

        using var ctx = await CreateContextAsync();
        var existing = await ctx.FindTenantByIdAsync(tenant.Id, token);
        if (existing == null) {
            return new RequestResult(ResponseStatus.NotFound, $"Tenant '{tenant.Id}' not found");
        }

        existing.IsLocked = false;
        (var code, var message) = await ctx.Complete();
        return new RequestResult(code, message ?? string.Empty);
    }

    public async Task<ICommandResponse> AddUserAsync([NotNull] ApplicationUser user, [NotNull] ApplicationTenant tenant, CancellationToken token) {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(tenant);
        ArgumentOutOfRangeException.ThrowIfEqual(user.Id, Guid.Empty);
        ArgumentOutOfRangeException.ThrowIfEqual(tenant.Id, Guid.Empty);

        using var ctx = await CreateContextAsync();
        var existingTenant = await ctx.FindTenantByIdAsync(tenant.Id, token);
        if (existingTenant == null) {
            return new RequestResult(ResponseStatus.NotFound, $"Tenant '{tenant.Id}' not found");
        }

        var existingUser = await ctx.FindByIdAsync(user.Id, token);
        if (existingUser == null) {
            return new RequestResult(ResponseStatus.NotFound, $"User '{user.Id}' not found");
        }

        // Idempotent: already assigned is not an error
        var alreadyAssigned = await ctx.ApplicationUserTenant
            .AnyAsync(ut => ut.ApplicationUserId == user.Id && ut.ApplicationTenantId == tenant.Id, token);
        if (alreadyAssigned) {
            return RequestResult.Ok();
        }

        var userTenant = new ApplicationUserTenant {
            Id = Guid.NewGuid(),
            ApplicationUserId = user.Id,
            ApplicationTenantId = tenant.Id
        };
        await ctx.AddIdentityUserTenantAsync(userTenant, token);
        (var code, var message) = await ctx.Complete();
        return new RequestResult(code, message ?? string.Empty);
    }

    public async Task<ICommandResponse> RemoveUserAsync([NotNull] ApplicationUser user, [NotNull] ApplicationTenant tenant, CancellationToken token) {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(tenant);
        ArgumentOutOfRangeException.ThrowIfEqual(user.Id, Guid.Empty);
        ArgumentOutOfRangeException.ThrowIfEqual(tenant.Id, Guid.Empty);

        using var ctx = await CreateContextAsync();
        var userTenant = await ctx.ApplicationUserTenant
            .FirstOrDefaultAsync(ut => ut.ApplicationUserId == user.Id && ut.ApplicationTenantId == tenant.Id, token);

        // Idempotent: already removed is not an error
        if (userTenant == null) {
            return RequestResult.Ok();
        }

        ctx.RemoveApplicationUserTenant(userTenant);
        (var code, var message) = await ctx.Complete();
        return new RequestResult(code, message ?? string.Empty);
    }

    public async Task<IEnumerable<string>> GetUsersForTenantAsync(Guid tenantId, CancellationToken token) {
        ArgumentOutOfRangeException.ThrowIfEqual(tenantId, Guid.Empty);

        using var ctx = await CreateContextAsync();
        return await ctx.TenantUsersAsync(tenantId);
    }

    public async Task<IEnumerable<Guid>> GetTenantIdsForUserAsync(Guid userId, CancellationToken token) {
        ArgumentOutOfRangeException.ThrowIfEqual(userId, Guid.Empty);

        using var ctx = await CreateContextAsync();
        return await ctx.ApplicationUserTenant
            .AsNoTracking()
            .Where(ut => ut.ApplicationUserId == userId)
            .Select(ut => ut.ApplicationTenantId)
            .ToListAsync(token);
    }

    public async Task<bool> CanSignInAsync(Guid userId, Guid tenantId, CancellationToken token) {
        ArgumentOutOfRangeException.ThrowIfEqual(userId, Guid.Empty);
        ArgumentOutOfRangeException.ThrowIfEqual(tenantId, Guid.Empty);

        using var ctx = await CreateContextAsync();
        return await ctx.CanSignInTenantAsync(userId, tenantId);
    }
}

