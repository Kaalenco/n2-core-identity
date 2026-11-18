using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;

using N2.Core.Entity;

namespace N2.Core.Identity.Data;

public class N2IdentityContextFactory : IIdentityContextFactory {
    private readonly IConnectionStringService settingService;
    private readonly DatabaseProvider defaultProvider;
    private readonly string defaultConnectionName;

    public N2IdentityContextFactory(
        IConnectionStringService settingService,
        DatabaseProvider defaultProvider,
        string defaultConnectionName) {
        EnsureSupported(defaultProvider);
        this.settingService = settingService;
        this.defaultProvider = defaultProvider;
        this.defaultConnectionName = defaultConnectionName;
    }

    public Task<IIdentityContext> Create(CancellationToken cancellationToken) => Create(defaultProvider, defaultConnectionName, cancellationToken);

    public Task<IIdentityContext> Create(string connectionName, CancellationToken cancellationToken) => Create(defaultProvider, connectionName, cancellationToken);

    public Task<IIdentityContext> Create(DatabaseProvider provider, CancellationToken cancellationToken) => Create(provider, defaultConnectionName, cancellationToken);

    public Task<IIdentityContext> Create(DatabaseProvider provider, string connectionName, CancellationToken cancellationToken) {
        cancellationToken.ThrowIfCancellationRequested();
        EnsureSupported(provider);
        var connectionString = settingService.GetConnectionString(connectionName);
        if (string.IsNullOrEmpty(connectionString)) {
            throw new InvalidOperationException($"Connection string '{connectionName}' not found.");
        }
        DbContextOptionsBuilder<N2IdentityContext> optionsBuilder = new();
        optionsBuilder.UseSqlServer(connectionString);
        N2IdentityContext result = new(optionsBuilder.Options, NullLogger<N2IdentityContext>.Instance);
        return Task.FromResult<IIdentityContext>(result);
    }

    /// <summary>
    /// Returns <paramref name="provider"/> when it is supported; throws otherwise.
    /// </summary>
    /// <exception cref="IdentityConfigurationException">The provider is not SQL Server.</exception>
    private static DatabaseProvider EnsureSupported(DatabaseProvider provider) =>
        provider == DatabaseProvider.SqlServer
            ? provider
            : throw new IdentityConfigurationException(
                $"Database provider value '{(int)provider}' is not supported by N2.Core.Identity 2.0.0. " +
                $"Only '{nameof(DatabaseProvider.SqlServer)}' is supported; MySQL support was removed in 2.0.0 " +
                "and is planned as a separate package (N2.Core.Identity.MySql).");
}
