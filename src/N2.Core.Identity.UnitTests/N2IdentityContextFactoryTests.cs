using Microsoft.Extensions.Configuration;

using Moq;

using N2.Core.Entity;
using N2.Core.Identity.Data;

namespace N2.Core.Identity.UnitTests;

[TestClass]
public class N2IdentityContextFactoryTests {
    private const string SqlServerConnectionName = "UserDbSqlServerTest";
    private const string MySqlConnectionName = "UserDbMySqlTest";

    private static IConfiguration BuildConfiguration() =>
        new ConfigurationBuilder()
            .AddUserSecrets<N2IdentityContextFactoryTests>()
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
        var factory = new N2IdentityContextFactory(BuildMock(BuildConfiguration()).Object);

        // Act
        using var context = await factory.CreateAsync(DatabaseProvider.SqlServer, SqlServerConnectionName);

        // Assert
        var dbContext = (N2IdentityContext)context;
        Assert.AreEqual("Microsoft.EntityFrameworkCore.SqlServer", dbContext.Database.ProviderName);
    }

    [TestMethod]
    [TestCategory("Integration")]
    public async Task CreateAsync_MySqlProvider_ShouldConfigureMySqlProvider() {
        // Arrange
        var factory = new N2IdentityContextFactory(BuildMock(BuildConfiguration()).Object);

        // Act
        using var context = await factory.CreateAsync(DatabaseProvider.MySql, MySqlConnectionName);

        // Assert
        var dbContext = (N2IdentityContext)context;
        Assert.AreEqual("Pomelo.EntityFrameworkCore.MySql", dbContext.Database.ProviderName);
    }

    [TestMethod]
    [TestCategory("Integration")]
    public async Task CreateAsync_DefaultOverload_ShouldDefaultToSqlServer() {
        // Arrange
        var factory = new N2IdentityContextFactory(BuildMock(BuildConfiguration()).Object);

        // Act
        using var context = await factory.CreateAsync();

        // Assert
        var dbContext = (N2IdentityContext)context;
        Assert.AreEqual("Microsoft.EntityFrameworkCore.SqlServer", dbContext.Database.ProviderName);
    }

    [TestMethod]
    [TestCategory("Integration")]
    public async Task CreateAsync_ConnectionNameOverload_ShouldDefaultToSqlServer() {
        // Arrange
        var factory = new N2IdentityContextFactory(BuildMock(BuildConfiguration()).Object);

        // Act
        using var context = await factory.CreateAsync(SqlServerConnectionName);

        // Assert
        var dbContext = (N2IdentityContext)context;
        Assert.AreEqual("Microsoft.EntityFrameworkCore.SqlServer", dbContext.Database.ProviderName);
    }

    [TestMethod]
    [TestCategory("Integration")]
    public async Task CreateAsync_ProviderOnly_ShouldUseDefaultConnectionName() {
        // Arrange
        var factory = new N2IdentityContextFactory(BuildMock(BuildConfiguration()).Object);

        // Act
        using var context = await factory.CreateAsync(DatabaseProvider.SqlServer);

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
        var factory = new N2IdentityContextFactory(mock.Object);

        // Act & Assert
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => factory.CreateAsync(DatabaseProvider.SqlServer, SqlServerConnectionName));
    }
}
