using Microsoft.EntityFrameworkCore.Design;
using Microsoft.EntityFrameworkCore.Design.Internal;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.EntityFrameworkCore.Migrations.Design;
using Microsoft.EntityFrameworkCore.Migrations.Operations;
using Microsoft.EntityFrameworkCore.SqlServer.Design.Internal;
using Microsoft.Extensions.DependencyInjection;

using N2.Core.Identity.Data;

#pragma warning disable EF1001 // Internal EF Core API usage is unavoidable for design-time services

namespace N2.Core.Identity.UnitTests.Data;

[TestClass]
public class UsingAgnosticMigrationOperationGenerator {

    private AgnosticMigrationOperationGenerator _generator = default!;

    [TestInitialize]
    public void Initialize() {
        // SqlServerDesignTimeServices registers ICSharpHelper and other primitives,
        // but NOT CSharpMigrationOperationGeneratorDependencies itself — so we
        // resolve ICSharpHelper and construct the dependencies struct manually.
        var services = new ServiceCollection();
        services.AddSingleton<ICSharpHelper, CSharpHelper>();
        new SqlServerDesignTimeServices().ConfigureDesignTimeServices(services);
        var provider = services.BuildServiceProvider();

        var csharpHelper = provider.GetRequiredService<ICSharpHelper>();
        var dependencies = new CSharpMigrationOperationGeneratorDependencies(csharpHelper);
        _generator = new AgnosticMigrationOperationGenerator(dependencies);
    }

    // -------------------------------------------------------------------------
    // StripType (tested indirectly through Generate)
    // -------------------------------------------------------------------------

    [TestMethod]
    public void Generate_CreateTable_ShouldNullifyColumnTypes() {
        // Arrange
        var col = new AddColumnOperation { ColumnType = "nvarchar(max)", Name = "Name", Table = "Users", ClrType = typeof(string) };
        var createTable = new CreateTableOperation {
            Name = "Users",
            Columns = { col }
        };

        // Act
        _generator.Generate("mb", [createTable], new IndentedStringBuilder());

        // Assert – StripType must have cleared the column type
        Assert.IsNull(col.ColumnType, "ColumnType should be null after Generate for CreateTable.");
    }

    [TestMethod]
    public void Generate_CreateTable_WithSqlServerIdentity_ShouldAddMySqlValueGenerationStrategy() {
        // Arrange
        var col = new AddColumnOperation { Name = "Id", Table = "Users", ClrType = typeof(int) };
        col["SqlServer:Identity"] = "1, 1";
        var createTable = new CreateTableOperation {
            Name = "Users",
            Columns = { col }
        };

        // Act
        _generator.Generate("mb", [createTable], new IndentedStringBuilder());

        // Assert – StripType must have added the MySql strategy annotation
        Assert.IsNotNull(col["MySql:ValueGenerationStrategy"], "MySql:ValueGenerationStrategy annotation should be added when SqlServer:Identity is present.");
        Assert.AreEqual(MySqlValueGenerationStrategy.IdentityColumn, col["MySql:ValueGenerationStrategy"]);
    }

    [TestMethod]
    public void Generate_CreateTable_WhenMySqlStrategyAlreadySet_ShouldNotOverwrite() {
        // Arrange – consumer has already pinned a specific strategy
        var col = new AddColumnOperation { Name = "Id", Table = "Users", ClrType = typeof(int) };
        col["SqlServer:Identity"] = "1, 1";
        col["MySql:ValueGenerationStrategy"] = MySqlValueGenerationStrategy.ComputedColumn;
        var createTable = new CreateTableOperation {
            Name = "Users",
            Columns = { col }
        };

        // Act
        _generator.Generate("mb", [createTable], new IndentedStringBuilder());

        // Assert – pre-existing value must be preserved
        Assert.AreEqual(MySqlValueGenerationStrategy.ComputedColumn, col["MySql:ValueGenerationStrategy"],
            "A pre-existing MySql:ValueGenerationStrategy must not be overwritten.");
    }

    [TestMethod]
    public void Generate_AddColumn_ShouldNullifyColumnType() {
        // Arrange
        var add = new AddColumnOperation { ColumnType = "int", Name = "Age", Table = "Users", ClrType = typeof(int) };

        // Act
        _generator.Generate("mb", [add], new IndentedStringBuilder());

        // Assert
        Assert.IsNull(add.ColumnType, "ColumnType should be null after Generate for AddColumn.");
    }

    [TestMethod]
    public void Generate_AddColumn_WithSqlServerIdentity_ShouldAddMySqlValueGenerationStrategy() {
        // Arrange
        var add = new AddColumnOperation { Name = "Id", Table = "Users", ClrType = typeof(int) };
        add["SqlServer:Identity"] = "1, 1";

        // Act
        _generator.Generate("mb", [add], new IndentedStringBuilder());

        // Assert
        Assert.AreEqual(MySqlValueGenerationStrategy.IdentityColumn, add["MySql:ValueGenerationStrategy"]);
    }

    [TestMethod]
    public void Generate_CreateIndex_ShouldNullifyFilter() {
        // Arrange
        var index = new CreateIndexOperation {
            Name = "IX_Users_Email",
            Table = "Users",
            Columns = ["Email"],
            Filter = "[Email] IS NOT NULL"  // SQL Server partial-index filter
        };

        // Act
        _generator.Generate("mb", [index], new IndentedStringBuilder());

        // Assert
        Assert.IsNull(index.Filter, "Filter should be null after Generate for CreateIndex.");
    }

    [TestMethod]
    public void Generate_CreateIndex_WithNullFilter_ShouldRemainNull() {
        // Arrange
        var index = new CreateIndexOperation {
            Name = "IX_Users_Name",
            Table = "Users",
            Columns = ["Name"],
            Filter = null
        };

        // Act – must not throw
        _generator.Generate("mb", [index], new IndentedStringBuilder());

        // Assert
        Assert.IsNull(index.Filter);
    }

    [TestMethod]
    public void Generate_UnrelatedOperation_ShouldPassThroughUntouched() {
        // Arrange – DropTableOperation has no columns or filter to strip
        var drop = new DropTableOperation { Name = "OldTable" };

        // Act & Assert – must not throw
        _generator.Generate("mb", [drop], new IndentedStringBuilder());
    }

    [TestMethod]
    public void Generate_MultipleOperations_ShouldProcessAll() {
        // Arrange
        var col1 = new AddColumnOperation { ColumnType = "nvarchar(50)", Name = "Name", Table = "Users", ClrType = typeof(string) };
        var col2 = new AddColumnOperation { ColumnType = "bigint", Name = "TenantId", Table = "Users", ClrType = typeof(long) };
        var createTable = new CreateTableOperation {
            Name = "Users",
            Columns = { col1, col2 }
        };
        var addCol = new AddColumnOperation { ColumnType = "int", Name = "Score", Table = "Stats", ClrType = typeof(int) };
        var index = new CreateIndexOperation {
            Name = "IX_Stats_Score", Table = "Stats", Columns = ["Score"],
            Filter = "[Score] IS NOT NULL"
        };

        // Act
        _generator.Generate("mb", [createTable, addCol, index], new IndentedStringBuilder());

        // Assert
        Assert.IsNull(col1.ColumnType);
        Assert.IsNull(col2.ColumnType);
        Assert.IsNull(addCol.ColumnType);
        Assert.IsNull(index.Filter);
    }
}