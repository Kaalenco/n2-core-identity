using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.Logging.Abstractions;

using N2.Core.Entity;

using Pomelo.EntityFrameworkCore.MySql.Infrastructure;

namespace N2.Core.Identity.Data;

public class N2IdentityContextFactory : IIdentityContextFactory {
    private readonly IConnectionStringService settingService;

    public N2IdentityContextFactory(IConnectionStringService settingService) {
        this.settingService = settingService;
    }

    public Task<IIdentityContext> CreateAsync() => CreateAsync(DatabaseProvider.SqlServer, "UserDbConnection");

    public Task<IIdentityContext> CreateAsync(string connectionName) => CreateAsync(DatabaseProvider.SqlServer, connectionName);

    public Task<IIdentityContext> CreateAsync(DatabaseProvider provider) => CreateAsync(provider, "UserDbConnection");

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
                // The model snapshot intentionally retains SQL Server column-type annotations
                // (e.g. HasColumnType("uniqueidentifier")) so that design-time tooling can diff
                // correctly when running `dotnet ef migrations add` against SQL Server. At
                // MySQL runtime, Pomelo resolves those types differently, which EF Core 8+
                // detects as a pending-model-changes mismatch. Logging instead of throwing
                // lets migrations run; the schema produced by the Up() method is still correct
                // because AgnosticMigrationOperationGenerator strips all provider-specific types
                // from the migration code itself.
                // Re-generate the migration once with the new AgnosticAnnotationCodeGenerator in
                // place to get a fully type-agnostic snapshot and eliminate this warning entirely.
                .ConfigureWarnings(w => w.Log(RelationalEventId.PendingModelChangesWarning));
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