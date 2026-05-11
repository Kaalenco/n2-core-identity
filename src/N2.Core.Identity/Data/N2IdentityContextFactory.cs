using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.Logging.Abstractions;

using N2.Core.Entity;

using Pomelo.EntityFrameworkCore.MySql.Infrastructure;

namespace N2.Core.Identity.Data;

public class N2IdentityContextFactory : IIdentityContextFactory {
    private readonly IConnectionStringService settingService;
    private readonly DatabaseProvider defaultProvider;
    private readonly string defaultConnectionName;

    public N2IdentityContextFactory(
        IConnectionStringService settingService,
        DatabaseProvider defaultProvider,
        string defaultConnectionName) {
        this.settingService = settingService;
        this.defaultProvider = defaultProvider;
        this.defaultConnectionName = defaultConnectionName;
    }

    public Task<IIdentityContext> CreateAsync() => CreateAsync(defaultProvider, defaultConnectionName);

    public Task<IIdentityContext> CreateAsync(string connectionName) => CreateAsync(defaultProvider, connectionName);

    public Task<IIdentityContext> CreateAsync(DatabaseProvider provider) => CreateAsync(provider, defaultConnectionName);

    public Task<IIdentityContext> CreateAsync(DatabaseProvider provider, string connectionName) {
        var connectionString = settingService.GetConnectionString(connectionName);
        if (string.IsNullOrEmpty(connectionString)) {
            throw new InvalidOperationException($"Connection string '{connectionName}' not found.");
        }
        DbContextOptionsBuilder<N2IdentityContext> optionsBuilder = new();
        var logger = NullLogger<N2IdentityContext>.Instance;
        if (provider == DatabaseProvider.MySql) {
            var (cleanedConnectionString, serverVersion) = ParseMySqlConnectionString(connectionString);
            optionsBuilder
                .UseMySql(cleanedConnectionString, serverVersion)
                // The snapshot is generated against SQL Server (the canonical design-time
                // provider) and retains SqlServer:Identity and HasFilter annotations that the
                // MySQL runtime model does not carry. EF Core 8+ detects this as a
                // pending-model-changes mismatch and would throw from MigrateAsync via
                // Migrator.ValidateMigrations. The schema produced by the Up() methods is
                // correct — AgnosticMigrationOperationGenerator strips all provider-specific
                // types from migration DDL. Ignoring this warning prevents the false-positive
                // exception while keeping all actual schema changes detectable.
                .ConfigureWarnings(w => w.Ignore(RelationalEventId.PendingModelChangesWarning));
        } else {
            optionsBuilder.UseSqlServer(connectionString);
        }
        N2IdentityContext result = new(optionsBuilder.Options, logger);
        return Task.FromResult<IIdentityContext>(result);
    }

    /// <summary>
    /// Extracts the optional <c>Version=</c> key from a MySQL connection string and returns
    /// the sanitized connection string alongside the resolved <see cref="MySqlServerVersion"/>.
    /// </summary>
    /// <remarks>
    /// <c>Version=</c> is not part of the official MySQL connection string specification.
    /// It is a custom key recognised only by this helper and consumed by Pomelo's
    /// <c>UseMySql</c> configuration. It must be removed before the connection string is
    /// passed to the MySQL driver, which would reject unknown keys.
    ///
    /// Set the version to match the MySQL server in your environment (e.g. <c>Version=8.0.36</c>).
    /// Using a version lower than the actual server is safe but may miss newer optimisations.
    /// Using a version higher may generate SQL the server does not support.
    /// If the key is absent, version 8.0.0 is assumed.
    /// </remarks>
    private static (string ConnectionString, MySqlServerVersion ServerVersion) ParseMySqlConnectionString(string connectionString) {
        var parts = connectionString.Split(';', StringSplitOptions.RemoveEmptyEntries);
        string? versionString = null;
        var clean = new List<string>(parts.Length);

        foreach (var part in parts) {
            if (part.Trim().StartsWith("Version=", StringComparison.OrdinalIgnoreCase))
                versionString = part.Trim()["Version=".Length..].Trim();
            else
                clean.Add(part);
        }

        var serverVersion = versionString is not null
            ? new MySqlServerVersion(System.Version.Parse(versionString))
            : new MySqlServerVersion(new Version(8, 0, 0));

        return (string.Join(";", clean), serverVersion);
    }
}