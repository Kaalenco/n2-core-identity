using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;

using N2.Core.Entity;

namespace N2.Core.Identity.Data;

public class N2IdentityContextFactory : IIdentityContextFactory {
    private readonly IConnectionStringService settingService;

    public N2IdentityContextFactory(IConnectionStringService settingService) {
        this.settingService = settingService;
    }

    public Task<IIdentityContext> CreateAsync() => CreateAsync("UserDbConnection");

    public Task<IIdentityContext> CreateAsync(string connectionName) {
        var connectionString = settingService.GetConnectionString(connectionName);
        if (string.IsNullOrEmpty(connectionString)) {
            throw new InvalidOperationException($"Connection string '{connectionName}' not found.");
        }
        DbContextOptionsBuilder<N2IdentityContext> optionsBuilder = new();
        var logger = NullLogger<N2IdentityContext>.Instance;
        optionsBuilder.UseSqlServer(connectionString);
        N2IdentityContext result = new(optionsBuilder.Options, logger);
        return Task.FromResult<IIdentityContext>(result);
    }
}