using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;

namespace N2.Core.Identity.Data;

#pragma warning disable CA1812 // DesignTimeFactory is an internal class by design
/// <summary>
/// Provides an <see cref="N2IdentityContext"/> for EF Core design-time tooling
/// (<c>dotnet ef migrations add</c> / <c>dotnet ef migrations remove</c>).
/// Reads the connection string from, in order:
/// <list type="number">
///   <item>The <c>SQLSERVER_IDENTITY_CONNECTION</c> environment variable.</item>
///   <item><c>ConnectionStrings:UserDbSqlServerTest</c> in user secrets
///         (secrets ID <c>N2-Core-0c368d89-5cb3-4451-9c68-b79e69920a09</c>).</item>
/// </list>
/// Always targets SQL Server — this is the canonical provider for migration generation.
/// The <see cref="ProviderAgnosticDesignTimeServices"/> registered alongside this factory
/// ensures the generated migration code contains no provider-specific column types.
/// </summary>
internal sealed class DesignTimeFactory : IDesignTimeDbContextFactory<N2IdentityContext> {
    public N2IdentityContext CreateDbContext(string[] args) {
        var configuration = new ConfigurationBuilder()
            .AddUserSecrets<DesignTimeFactory>()
            .AddEnvironmentVariables()
            .Build();

        var connectionString =
            configuration.GetValue<string>("SQLSERVER_IDENTITY_CONNECTION")
            ?? configuration.GetConnectionString("UserDbSqlServerTest")
            ?? throw new InvalidOperationException(
                "No design-time connection string found. " +
                "Set the 'SQLSERVER_IDENTITY_CONNECTION' environment variable or " +
                "add 'ConnectionStrings:UserDbSqlServerTest' to user secrets " +
                "(ID: N2-Core-0c368d89-5cb3-4451-9c68-b79e69920a09).");

        DbContextOptionsBuilder<N2IdentityContext> optionsBuilder = new();
        optionsBuilder.UseSqlServer(connectionString);
        return new N2IdentityContext(optionsBuilder.Options, NullLogger<N2IdentityContext>.Instance);
    }
}
