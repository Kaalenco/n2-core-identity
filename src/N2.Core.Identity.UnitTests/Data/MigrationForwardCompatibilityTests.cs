using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.EntityFrameworkCore.Migrations.Operations;

using N2.Core.Identity.Migrations;

using System.Reflection;

namespace N2.Core.Identity.UnitTests.Data;

/// <summary>
/// Verifies the forward-only migration policy: columns may be added or widened, never dropped,
/// renamed, or narrowed in a single migration. Removal spans two or more migrations; type changes
/// are not permitted.
/// </summary>
[TestClass]
public sealed class MigrationForwardCompatibilityTests {

    private static readonly MethodInfo UpMethod =
        typeof(Migration).GetMethod("Up", BindingFlags.NonPublic | BindingFlags.Instance)!;

    public static IEnumerable<(Type EntityType, string Name)> AllMigrations() =>
        typeof(InitialCreate).Assembly
            .GetTypes()
            .Where(t => t.IsSubclassOf(typeof(Migration)) && !t.IsAbstract)
            .OrderBy(t => t.Name)
            .Select(t => (EntityType: t, Name: t.Name));

    private static IReadOnlyList<MigrationOperation> UpOperations(Type migrationType) {
        var migration = (Migration)Activator.CreateInstance(migrationType)!;
        var builder = new MigrationBuilder(activeProvider: null);
        UpMethod.Invoke(migration, [builder]);
        return builder.Operations;
    }

    [TestMethod]
    [DynamicData(nameof(AllMigrations))]
    public void Up_IsForwardCompatible((Type EntityType, string Name) migration) {
        var ops = UpOperations(migration.EntityType);
        Console.WriteLine($"Testing migration {migration.Name} with {ops.Count} operations...");
        var droppedColumns = ops.OfType<DropColumnOperation>().ToList();
        Assert.IsEmpty(droppedColumns,
            "Columns must not be dropped in a single migration. " +
            "Use two migrations: first make the column nullable/unused, then remove it. " +
            $"Violations: {Describe(droppedColumns, o => $"{o.Table}.{o.Name}")}");

        var renamedColumns = ops.OfType<RenameColumnOperation>().ToList();
        Assert.IsEmpty(renamedColumns,
            "Columns must not be renamed. Add a new column and migrate data instead. " +
            $"Violations: {Describe(renamedColumns, o => $"{o.Table}.{o.Name} → {o.NewName}")}");

        var droppedTables = ops.OfType<DropTableOperation>().ToList();
        Assert.IsEmpty(droppedTables,
            "Tables must not be dropped in a single migration. " +
            "Stop writing to the table first, then remove it in a later migration. " +
            $"Violations: {Describe(droppedTables, o => o.Name)}");

        var renamedTables = ops.OfType<RenameTableOperation>().ToList();
        Assert.IsEmpty(renamedTables,
            "Tables must not be renamed. Create the new table, migrate data, then drop the old one in a later migration. " +
            $"Violations: {Describe(renamedTables, o => $"{o.Name} → {o.NewName}")}");

        var nullabilityNarrowing = ops.OfType<AlterColumnOperation>()
            .Where(o => !o.IsNullable && o.OldColumn.IsNullable)
            .ToList();
        Assert.IsEmpty(nullabilityNarrowing,
            "Columns must not be changed from nullable to NOT NULL in a single migration — " +
            "existing rows may have NULL values that would cause the migration to fail or existing readers to break. " +
            $"Violations: {Describe(nullabilityNarrowing, o => $"{o.Table}.{o.Name}")}");

        var typeChanges = ops.OfType<AlterColumnOperation>()
            .Where(o => o.OldColumn.ClrType != null && o.ClrType != o.OldColumn.ClrType)
            .ToList();
        Assert.IsEmpty(typeChanges,
            "Column CLR types must not change. Changing a column's type can break readers " +
            "that are still running the previous revision. " +
            $"Violations: {Describe(typeChanges, o => $"{o.Table}.{o.Name}: {o.OldColumn.ClrType.Name} → {o.ClrType.Name}")}");
    }

    private static string Describe<T>(IEnumerable<T> items, Func<T, string> format) =>
        string.Join(", ", items.Select(format));
}