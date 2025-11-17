using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using Microsoft.Extensions.Logging.Abstractions;

namespace N2.Core.Identity.Data;

#pragma warning disable CA1812 // DesignTimeFactory is an internal class by design
/// <summary>
/// The system context design time factory provides the ef code migration
/// service with a SystemContext connected to a local database.
/// </summary>
internal sealed class DesignTimeFactory : IDesignTimeDbContextFactory<N2IdentityContext> {
    private const string ConnectionString = "Data Source=tp-i9;Initial Catalog=asp-users;Persist Security Info=True;Integrated Security=true;TrustServerCertificate=True;";

    /// <summary>
    /// Create the system context
    /// </summary>
    /// <param name="args">Arguments provided by the design-time service.</param>
    /// <returns>An instance of SystemContext</returns>
    public N2IdentityContext CreateDbContext(string[] args) {
        DbContextOptionsBuilder<N2IdentityContext> optionsBuilder = new();
        var logger = NullLogger<N2IdentityContext>.Instance;
        optionsBuilder.UseSqlServer(ConnectionString);

        return new N2IdentityContext(optionsBuilder.Options, new AuthenticationConfig(), logger);
    }
}