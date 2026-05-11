using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.EntityFrameworkCore.Migrations.Design;
using Microsoft.EntityFrameworkCore.Migrations.Operations;
using Microsoft.EntityFrameworkCore.SqlServer.Design.Internal;
using Microsoft.Extensions.DependencyInjection;

#pragma warning disable EF1001 // Internal EF Core API usage is unavoidable for design-time services

namespace N2.Core.Identity.Data;

/// <summary>
/// Registered automatically by EF Core design-time tooling.
/// Replaces the default migration operation generator and snapshot annotation
/// code generator with provider-agnostic equivalents, so that every generated
/// migration — and its embedded Designer snapshot — works against both SQL Server
/// and MySQL without post-editing.
/// </summary>
internal sealed class ProviderAgnosticDesignTimeServices : IDesignTimeServices {
    public void ConfigureDesignTimeServices(IServiceCollection serviceCollection) {
        serviceCollection.AddSingleton<ICSharpMigrationOperationGenerator, AgnosticMigrationOperationGenerator>();
        serviceCollection.AddSingleton<IAnnotationCodeGenerator, AgnosticAnnotationCodeGenerator>();
    }
}

/// <summary>
/// Generates provider-agnostic migration code by:
/// <list type="bullet">
///   <item>Nullifying explicit column types so each provider resolves its own DDL type.</item>
///   <item>Adding a <c>MySql:ValueGenerationStrategy</c> annotation next to every
///         <c>SqlServer:Identity</c> annotation so auto-increment columns work on both engines.</item>
///   <item>Removing SQL Server partial-index <c>filter:</c> expressions — MySQL UNIQUE
///         indexes natively allow multiple NULLs, so no filter is required.</item>
/// </list>
/// </summary>
internal sealed class AgnosticMigrationOperationGenerator : CSharpMigrationOperationGenerator {
    public AgnosticMigrationOperationGenerator(CSharpMigrationOperationGeneratorDependencies dependencies)
        : base(dependencies) { }

    public override void Generate(
        string builderName,
        IReadOnlyList<MigrationOperation> operations,
        IndentedStringBuilder builder) {
        foreach (var op in operations) {
            switch (op) {
                case CreateTableOperation create:
                    foreach (var col in create.Columns) StripType(col);
                    break;
                case AddColumnOperation add:
                    StripType(add);
                    break;
                case CreateIndexOperation index:
                    index.Filter = null;
                    break;
            }
        }
        base.Generate(builderName, operations, builder);
    }

    private static void StripType(ColumnOperation col) {
        col.ColumnType = null;
        if (col["SqlServer:Identity"] is not null && col["MySql:ValueGenerationStrategy"] is null)
            col["MySql:ValueGenerationStrategy"] = MySqlValueGenerationStrategy.IdentityColumn;
    }
}

/// <summary>
/// Generates provider-agnostic snapshot and Designer-file code. The following
/// SQL Server-specific metadata is stripped so the snapshot stays neutral:
/// <list type="bullet">
///   <item><c>HasColumnType()</c> — each provider resolves its own DDL type at migration time.</item>
///   <item><c>Relational:MaxIdentifierLength</c> — SQL Server uses 128, MySQL uses 64;
///         each provider's runtime convention supplies the correct value.</item>
///   <item><c>HasFilter()</c> on indexes — SQL Server conventions add <c>[col] IS NOT NULL</c>
///         filters to unique nullable indexes automatically; MySQL does not need them.
///         The filter is also stripped from migration DDL by <see cref="AgnosticMigrationOperationGenerator"/>.</item>
/// </list>
/// <para>
/// <c>SqlServer:Identity</c> / <c>UseIdentityColumn()</c> on properties is intentionally
/// kept in the snapshot. SQL Server conventions add it during model building and it is
/// required for <c>HasPendingModelChanges()</c> to pass against SQL Server. MySQL will
/// always show a false-positive for that check; do not run it for MySQL.
/// </para>
/// </summary>
internal sealed class AgnosticAnnotationCodeGenerator : SqlServerAnnotationCodeGenerator {
    public AgnosticAnnotationCodeGenerator(AnnotationCodeGeneratorDependencies dependencies)
        : base(dependencies) { }

    /// <inheritdoc/>
    public override IReadOnlyList<MethodCallCodeFragment> GenerateFluentApiCalls(
        IProperty property, IDictionary<string, IAnnotation> annotations) {
        // Drop HasColumnType() — provider conventions re-resolve the correct DDL
        // type when comparing models, so the differ never generates spurious
        // AlterColumn operations.
        annotations.Remove(RelationalAnnotationNames.ColumnType);
        return base.GenerateFluentApiCalls(property, annotations);
    }

    /// <inheritdoc/>
    public override IReadOnlyList<MethodCallCodeFragment> GenerateFluentApiCalls(
        IModel model, IDictionary<string, IAnnotation> annotations) {
        // Drop the SQL Server model-level value-generation annotation so the snapshot
        // does not carry UseIdentityColumns(). Without it, EF Core 9's pending-model
        // check no longer sees a mismatch when the runtime uses MySQL (which sets
        // MySql:ValueGenerationStrategy via Pomelo conventions instead).
        annotations.Remove("SqlServer:ValueGenerationStrategy");
        // Drop MaxIdentifierLength: SQL Server uses 128, MySQL uses 64. Omitting it
        // lets each provider's runtime convention supply the correct value so the
        // pending-model check sees no provider-specific difference.
        annotations.Remove(RelationalAnnotationNames.MaxIdentifierLength);
        return base.GenerateFluentApiCalls(model, annotations);
    }

}
