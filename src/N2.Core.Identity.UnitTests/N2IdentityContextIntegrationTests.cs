using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;

using Moq;

using N2.Core.Commands;
using N2.Core.Entity;
using N2.Core.Identity.Data;

namespace N2.Core.Identity.UnitTests;

/// <summary>
/// Runs all integration tests against MySQL.
/// Requires <c>ConnectionStrings:UserDbMySqlTest</c> in user secrets or
/// the <c>ConnectionStrings__UserDbMySqlTest</c> environment variable.
/// </summary>
[TestClass]
[TestCategory("Integration")]
[TestCategory("Integration.MySql")]
public class MySqlIntegrationTests : N2IdentityContextIntegrationTestsBase {
    protected override DatabaseProvider Provider => DatabaseProvider.MySql;
    protected override string ConnectionName => "UserDbMySqlTest";

    [TestMethod]
    public Task MigrateAsync_ShouldHaveNoPendingMigrations() =>
        MigrateAsync_ShouldHaveNoPendingMigrationsCore();
}
