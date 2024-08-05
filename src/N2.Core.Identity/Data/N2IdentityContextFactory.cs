using Microsoft.EntityFrameworkCore;
using N2.Core.Entity;

namespace N2.Core.Identity.Data;

public class N2IdentityContextFactory : IIdentityContextFactory
{
    private readonly IConnectionStringService settingService;

    public N2IdentityContextFactory(IConnectionStringService settingService)
    {
        this.settingService = settingService;
    }

    public Task<IIdentityContext> CreateAsync() => CreateAsync("UserDbConnection");

    public Task<IIdentityContext> CreateAsync(string connectionName)
    {
        var connectionString = settingService.GetConnectionString(connectionName);
        if (string.IsNullOrEmpty(connectionString))
        {
            throw new InvalidOperationException($"Connection string '{connectionName}' not found.");
        }
        var optionsBuilder = new DbContextOptionsBuilder<N2IdentityContext>();
        optionsBuilder.UseSqlServer(connectionString);
        var result = new N2IdentityContext(optionsBuilder.Options);
        return Task.FromResult<IIdentityContext>(result);
    }
}