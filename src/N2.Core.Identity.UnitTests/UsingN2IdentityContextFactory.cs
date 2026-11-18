using Microsoft.Extensions.Configuration;

using Moq;

using N2.Core.Entity;
using N2.Core.Identity.Data;

namespace N2.Core.Identity.UnitTests;

[TestClass]
public class UsingN2IdentityContextFactory {
    private const string SqlServerConnectionName = "UserDbSqlServerTest";

    private static IConfiguration BuildConfiguration() =>
        new ConfigurationBuilder()
            .AddUserSecrets<UsingN2IdentityContextFactory>()
            .AddEnvironmentVariables()   // CI injects ConnectionStrings__UserDbSqlServerTest etc.
            .Build();

    private static Mock<IConnectionStringService> BuildMock(IConfiguration configuration) {
        var mock = new Mock<IConnectionStringService>();
        mock.Setup(s => s.GetConnectionString(It.IsAny<string>()))
            .Returns((string name) => configuration.GetConnectionString(name) ?? string.Empty);
        return mock;
    }

    [TestMethod]
    [TestCategory("Integration")]
    public async Task CreateAsync_SqlServerProvider_ShouldConfigureSqlServerProvider() {
        // Arrange
        var factory = new N2IdentityContextFactory(BuildMock(BuildConfiguration()).Object, DatabaseProvider.SqlServer, SqlServerConnectionName);

        // Act
        using var context = await factory.Create(DatabaseProvider.SqlServer, SqlServerConnectionName, CancellationToken.None);

        // Assert
        var dbContext = (N2IdentityContext)context;
        Assert.AreEqual("Microsoft.EntityFrameworkCore.SqlServer", dbContext.Database.ProviderName);
    }

    [TestMethod]
    public void Constructor_UnsupportedProvider_ShouldThrowIdentityConfigurationException() {
        // Arrange: value 1 was DatabaseProvider.MySql before 2.0.0.
        const DatabaseProvider removedMySql = (DatabaseProvider)1;
        var mock = new Mock<IConnectionStringService>();

        // Act & Assert
        var ex = Assert.ThrowsExactly<IdentityConfigurationException>(
            () => new N2IdentityContextFactory(mock.Object, removedMySql, SqlServerConnectionName));
        StringAssert.Contains(ex.Message, "SqlServer");
    }

    [TestMethod]
    public async Task Create_UnsupportedProvider_ShouldThrowIdentityConfigurationException() {
        // Arrange
        var mock = new Mock<IConnectionStringService>();
        mock.Setup(s => s.GetConnectionString(It.IsAny<string>())).Returns("Server=x;Database=y");
        var factory = new N2IdentityContextFactory(mock.Object, DatabaseProvider.SqlServer, SqlServerConnectionName);

        // Act & Assert
        await Assert.ThrowsExactlyAsync<IdentityConfigurationException>(
            () => factory.Create((DatabaseProvider)1, SqlServerConnectionName, CancellationToken.None));
        mock.Verify(s => s.GetConnectionString(It.IsAny<string>()), Times.Never);
    }

    [TestMethod]
    public async Task Create_CancelledToken_ShouldThrowOperationCanceledException() {
        // Arrange
        var mock = new Mock<IConnectionStringService>();
        var factory = new N2IdentityContextFactory(mock.Object, DatabaseProvider.SqlServer, SqlServerConnectionName);
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        // Act & Assert
        await Assert.ThrowsExactlyAsync<OperationCanceledException>(
            () => factory.Create(cts.Token));
    }

    [TestMethod]
    [TestCategory("Integration")]
    public async Task CreateAsync_NoArgsOverload_ShouldUseConfiguredProvider() {
        // Arrange
        var factory = new N2IdentityContextFactory(BuildMock(BuildConfiguration()).Object, DatabaseProvider.SqlServer, SqlServerConnectionName);

        // Act
        using var context = await factory.Create(CancellationToken.None);

        // Assert
        var dbContext = (N2IdentityContext)context;
        Assert.AreEqual("Microsoft.EntityFrameworkCore.SqlServer", dbContext.Database.ProviderName);
    }

    [TestMethod]
    [TestCategory("Integration")]
    public async Task CreateAsync_ConnectionNameOverload_ShouldUseConfiguredProvider() {
        // Arrange
        var factory = new N2IdentityContextFactory(BuildMock(BuildConfiguration()).Object, DatabaseProvider.SqlServer, SqlServerConnectionName);

        // Act
        using var context = await factory.Create(SqlServerConnectionName, CancellationToken.None);

        // Assert
        var dbContext = (N2IdentityContext)context;
        Assert.AreEqual("Microsoft.EntityFrameworkCore.SqlServer", dbContext.Database.ProviderName);
    }

    [TestMethod]
    [TestCategory("Integration")]
    public async Task CreateAsync_ProviderOnly_ShouldUseConfiguredConnectionName() {
        // Arrange
        var factory = new N2IdentityContextFactory(BuildMock(BuildConfiguration()).Object, DatabaseProvider.SqlServer, SqlServerConnectionName);

        // Act
        using var context = await factory.Create(DatabaseProvider.SqlServer, CancellationToken.None);

        // Assert
        var dbContext = (N2IdentityContext)context;
        Assert.AreEqual("Microsoft.EntityFrameworkCore.SqlServer", dbContext.Database.ProviderName);
    }

    [TestMethod]
    [TestCategory("Integration")]
    public async Task CreateAsync_MissingConnectionString_ShouldThrowInvalidOperationException() {
        // Arrange
        var mock = new Mock<IConnectionStringService>();
        mock.Setup(s => s.GetConnectionString(It.IsAny<string>())).Returns(string.Empty);
        var factory = new N2IdentityContextFactory(mock.Object, DatabaseProvider.SqlServer, SqlServerConnectionName);

        // Act & Assert
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => factory.Create(DatabaseProvider.SqlServer, SqlServerConnectionName, CancellationToken.None));
    }
}
