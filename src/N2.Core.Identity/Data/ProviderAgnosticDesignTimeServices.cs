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
/// Generates provider-agnostic snapshot and Designer-file code by omitting
/// <c>HasColumnType()</c> from every property. This lets each provider resolve its
/// own DDL type at migration-execution time (e.g. <c>uniqueidentifier</c> on SQL Server,
/// <c>char(36)</c> on MySQL) instead of hard-coding a SQL Server type that MySQL
/// cannot parse.
/// <para>
/// Index filters (<c>HasFilter()</c>) are intentionally kept: they are set
/// unconditionally by ASP.NET Core Identity's <c>OnModelCreating</c>, so both the
/// snapshot and the live model carry the annotation — the pending-model-changes check
/// therefore sees no difference. The filter is stripped from the migration DDL at
/// generation time by <see cref="AgnosticMigrationOperationGenerator"/>.
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
}
