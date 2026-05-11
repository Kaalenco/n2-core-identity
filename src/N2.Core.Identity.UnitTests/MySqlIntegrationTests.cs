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
    // HasPendingModelChanges() is intentionally not tested here. The snapshot is
    // generated against SQL Server (the canonical design-time provider), so it
    // contains SqlServer:Identity annotations that the MySQL runtime model does
    // not have. The schema itself is correct; the annotation mismatch is an
    // unavoidable artefact of the cross-provider snapshot strategy.
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

/// <summary>
/// Runs all <see cref="N2SecretManagerIntegrationTestsBase"/> tests against MySQL.
/// Requires <c>ConnectionStrings:UserDbMySqlTest</c> in user secrets or
/// the <c>ConnectionStrings__UserDbMySqlTest</c> environment variable.
/// </summary>
[TestClass]
[TestCategory("Integration")]
[TestCategory("Integration.MySql")]
public class MySqlSecretManagerIntegrationTests : N2SecretManagerIntegrationTestsBase {
    protected override DatabaseProvider Provider => DatabaseProvider.MySql;
    protected override string ConnectionName => "UserDbMySqlTest";
}
