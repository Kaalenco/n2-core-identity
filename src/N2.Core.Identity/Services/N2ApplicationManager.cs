
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

using N2.Core.Commands;
using N2.Core.Identity.Data;

using System.Diagnostics.CodeAnalysis;

namespace N2.Core.Identity.Services;

public class N2ApplicationManager : IApplicationManager {

    private readonly DatabaseProvider provider;

    /// <summary>
    /// Gets the name of the database connection used for establishing connections.
    /// </summary>
    private readonly string connectionName;

    private readonly AuthenticationConfig configuration;
    private readonly IIdentityContextFactory factory;
    private readonly ILogger<N2ApplicationManager> logger;

    public N2ApplicationManager(
        IIdentityContextFactory identityContextFactory,
        IConfiguration configuration,
        string connectionName,
        ILogger<N2ApplicationManager> logger,
        DatabaseProvider provider = DatabaseProvider.SqlServer) {
        this.factory = identityContextFactory;
        this.connectionName = connectionName;
        this.provider = provider;
        this.logger = logger;

        this.configuration = configuration.GetAuthenticationConfig();

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

    public async Task<ICommandResponse> CreateAsync(Guid tenantId, [NotNull] ApplicationDefinition application, CancellationToken token) {
        ArgumentNullException.ThrowIfNull(application);
        ArgumentOutOfRangeException.ThrowIfEqual(tenantId, Guid.Empty);
        ArgumentException.ThrowIfNullOrWhiteSpace(application.Name);

        using var ctx = await CreateContextAsync();

        var existingTenant = await ctx.TenantFindRecord(tenantId, token);
        if (existingTenant == null) {
            return new RequestResult(ResponseStatus.NotFound, $"Tenant '{tenantId}' not found");
        }

        application.ApplicationTenantId = tenantId;
        application.NormalizedName = application.Name.Trim().ToUpperInvariant();

        var existing = await ctx.ApplicationFindRecord(tenantId, application.Name.Trim(), token);
        if (existing != null) {
            return new RequestResult(ResponseStatus.NotAcceptable, $"Application '{application.Name}' already exists in tenant '{tenantId}'");
        }

        await ctx.ApplicationAdd(application, token);
        (var code, var message) = await ctx.Complete();
        return new RequestResult(code, message ?? string.Empty);
    }

    public async Task<ICommandResponse> DeleteAsync(Guid tenantId, [NotNull] ApplicationDefinition application, CancellationToken token) {
        ArgumentNullException.ThrowIfNull(application);
        ArgumentOutOfRangeException.ThrowIfEqual(tenantId, Guid.Empty);
        ArgumentOutOfRangeException.ThrowIfEqual(application.Id, Guid.Empty);

        using var ctx = await CreateContextAsync();

        var existing = await ctx.ApplicationFindRecord(application.Id, token);
        if (existing == null) {
            return new RequestResult(ResponseStatus.NotFound, $"Application '{application.Id}' not found");
        }
        if (existing.ApplicationTenantId != tenantId) {
            return new RequestResult(ResponseStatus.NotFound, $"Application '{application.Id}' does not belong to tenant '{tenantId}'");
        }

        ctx.ApplicationDelete(existing);
        (var code, var message) = await ctx.Complete();
        return new RequestResult(code, message ?? string.Empty);
    }

    public async Task<ICommandResponse> UpdateAsync(Guid tenantId, [NotNull] ApplicationDefinition application, CancellationToken token) {
        ArgumentNullException.ThrowIfNull(application);
        ArgumentOutOfRangeException.ThrowIfEqual(tenantId, Guid.Empty);
        ArgumentOutOfRangeException.ThrowIfEqual(application.Id, Guid.Empty);
        ArgumentException.ThrowIfNullOrWhiteSpace(application.Name);

        using var ctx = await CreateContextAsync();

        var existing = await ctx.ApplicationFindRecord(application.Id, token);
        if (existing == null) {
            return new RequestResult(ResponseStatus.NotFound, $"Application '{application.Id}' not found");
        }
        if (existing.ApplicationTenantId != tenantId) {
            return new RequestResult(ResponseStatus.NotFound, $"Application '{application.Id}' does not belong to tenant '{tenantId}'");
        }

        existing.Name = application.Name.Trim();
        existing.NormalizedName = existing.Name.ToUpperInvariant();
        existing.MfaSecret = string.IsNullOrEmpty(application.MfaSecret) ? existing.MfaSecret : application.MfaSecret;

        (var code, var message) = await ctx.Complete();
        return new RequestResult(code, message ?? string.Empty);
    }

    public async Task<ApplicationDefinition?> FindByIdAsync(Guid tenantId, Guid applicationId, CancellationToken token) {
        ArgumentOutOfRangeException.ThrowIfEqual(tenantId, Guid.Empty);
        ArgumentOutOfRangeException.ThrowIfEqual(applicationId, Guid.Empty);

        using var ctx = await CreateContextAsync();
        var app = await ctx.ApplicationFindRecord(applicationId, token);
        return app?.ApplicationTenantId == tenantId ? app : null;
    }

    public async Task<ApplicationDefinition?> FindByNameAsync(Guid tenantId, string name, CancellationToken token) {
        ArgumentOutOfRangeException.ThrowIfEqual(tenantId, Guid.Empty);
        ArgumentException.ThrowIfNullOrEmpty(name);

        using var ctx = await CreateContextAsync();
        return await ctx.ApplicationFindRecord(tenantId, name, token);
    }

    public async Task<SelectItemList<UserSelectItem>> GetApplicationGetSelectList(Guid tenantId, CancellationToken token) {
        ArgumentOutOfRangeException.ThrowIfEqual(tenantId, Guid.Empty);

        using var ctx = await CreateContextAsync();
        return await ctx.ApplicationGetSelectList(tenantId, token);
    }

    public async Task<ICommandResponse> LockAsync(Guid tenantId, [NotNull] ApplicationDefinition application, CancellationToken token) {
        ArgumentNullException.ThrowIfNull(application);
        ArgumentOutOfRangeException.ThrowIfEqual(tenantId, Guid.Empty);
        ArgumentOutOfRangeException.ThrowIfEqual(application.Id, Guid.Empty);

        using var ctx = await CreateContextAsync();
        var existing = await ctx.ApplicationFindRecord(application.Id, token);
        if (existing == null) {
            return new RequestResult(ResponseStatus.NotFound, $"Application '{application.Id}' not found");
        }
        if (existing.ApplicationTenantId != tenantId) {
            return new RequestResult(ResponseStatus.NotFound, $"Application '{application.Id}' does not belong to tenant '{tenantId}'");
        }

        existing.IsLocked = true;
        (var code, var message) = await ctx.Complete();
        return new RequestResult(code, message ?? string.Empty);
    }

    public async Task<ICommandResponse> UnlockAsync(Guid tenantId, [NotNull] ApplicationDefinition application, CancellationToken token) {
        ArgumentNullException.ThrowIfNull(application);
        ArgumentOutOfRangeException.ThrowIfEqual(tenantId, Guid.Empty);
        ArgumentOutOfRangeException.ThrowIfEqual(application.Id, Guid.Empty);

        using var ctx = await CreateContextAsync();
        var existing = await ctx.ApplicationFindRecord(application.Id, token);
        if (existing == null) {
            return new RequestResult(ResponseStatus.NotFound, $"Application '{application.Id}' not found");
        }
        if (existing.ApplicationTenantId != tenantId) {
            return new RequestResult(ResponseStatus.NotFound, $"Application '{application.Id}' does not belong to tenant '{tenantId}'");
        }

        existing.IsLocked = false;
        (var code, var message) = await ctx.Complete();
        return new RequestResult(code, message ?? string.Empty);
    }
}
