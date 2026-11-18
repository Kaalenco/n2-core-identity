namespace N2.Core.Identity.Data;

/// <summary>
/// Specifies the database provider to use when creating an identity context.
/// </summary>
/// <remarks>
/// Since 2.0.0 only SQL Server is supported. The former <c>MySql</c> value (1) was removed;
/// passing it, or any other undefined value, throws <see cref="IdentityConfigurationException"/>.
/// MySQL support is planned as a separate package (N2.Core.Identity.MySql) once a stable
/// EF Core 10 MySQL provider exists.
/// </remarks>
public enum DatabaseProvider {
    /// <summary>Microsoft SQL Server database provider.</summary>
    SqlServer = 0
}
