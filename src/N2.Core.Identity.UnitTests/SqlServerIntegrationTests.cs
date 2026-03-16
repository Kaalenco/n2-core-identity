using N2.Core.Identity.Data;

namespace N2.Core.Identity.UnitTests;

// ── Concrete test classes ─────────────────────────────────────────────────────

/// <summary>
/// Runs all <see cref="N2IdentityContextIntegrationTestsBase"/> tests against SQL Server.
/// Requires <c>ConnectionStrings:UserDbSqlServerTest</c> in user secrets or
/// the <c>ConnectionStrings__UserDbSqlServerTest</c> environment variable.
/// </summary>
[TestClass]
[TestCategory("Integration")]
[TestCategory("Integration.SqlServer")]
public class SqlServerIntegrationTests : N2IdentityContextIntegrationTestsBase {
    protected override DatabaseProvider Provider => DatabaseProvider.SqlServer;
    protected override string ConnectionName => "UserDbSqlServerTest";

    [TestMethod]
    public Task MigrateAsync_ShouldHaveNoPendingMigrations() =>
        MigrateAsync_ShouldHaveNoPendingMigrationsCore();
}

/// <summary>
/// Runs all <see cref="N2TenantManagerIntegrationTestsBase"/> tests against SQL Server.
/// Requires <c>ConnectionStrings:UserDbSqlServerTest</c> in user secrets or
/// the <c>ConnectionStrings__UserDbSqlServerTest</c> environment variable.
/// </summary>
[TestClass]
[TestCategory("Integration")]
[TestCategory("Integration.SqlServer")]
public class SqlServerTenantManagerIntegrationTests : N2TenantManagerIntegrationTestsBase {
    protected override DatabaseProvider Provider => DatabaseProvider.SqlServer;
    protected override string ConnectionName => "UserDbSqlServerTest";
}
