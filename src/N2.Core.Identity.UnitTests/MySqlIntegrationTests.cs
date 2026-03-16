using N2.Core.Identity.Data;

namespace N2.Core.Identity.UnitTests;

/// <summary>
/// Runs all <see cref="N2IdentityContextIntegrationTestsBase"/> tests against MySQL.
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

/// <summary>
/// Runs all <see cref="N2TenantManagerIntegrationTestsBase"/> tests against MySQL.
/// Requires <c>ConnectionStrings:UserDbMySqlTest</c> in user secrets or
/// the <c>ConnectionStrings__UserDbMySqlTest</c> environment variable.
/// </summary>
[TestClass]
[TestCategory("Integration")]
[TestCategory("Integration.MySql")]
public class MySqlTenantManagerIntegrationTests : N2TenantManagerIntegrationTestsBase {
    protected override DatabaseProvider Provider => DatabaseProvider.MySql;
    protected override string ConnectionName => "UserDbMySqlTest";
}
