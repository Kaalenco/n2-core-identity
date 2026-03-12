# N2.Core.Identity

## Description

**N2.Core.Identity** is a flexible identity and role management library for .NET applications, built on top of ASP.NET Core Identity. It provides a strongly-typed, extensible `N2IdentityDbContext` (extending `IdentityDbContext`) and a feature-rich `N2UserManager` for advanced user, role, and authentication scenarios. The library is designed for modern .NET (net8.0, net9.0) and supports custom user properties, role management, and token-based workflows.

## Features

- Extends `IdentityDbContext` for easy integration with ASP.NET Core Identity.
- Strongly-typed `ApplicationUser` and `ApplicationRole` with support for custom properties.
- Advanced user and role management via `N2UserManager`.
- Token generation and email confirmation workflows.
- Designed for .NET 8 and .NET 9.

## License

AFL-3.0

## Version History

| Version | Changes |
|---|---|
| **1.5.1** | MySQL integration test CI pipeline: Docker Compose environment, `Dockerfile.integration`, and `TestCategory`-based filtering (`Integration.MySql` / `Integration.SqlServer`). `PendingModelChangesWarning` downgraded to a logged warning for MySQL contexts. |
| **1.5.0** | Unit test infrastructure fixes. |
| **1.4.6** | Security hardening: constant-time comparisons to prevent timing/user-enumeration attacks, account lockout, MFA rate limiting, TOTP support, PBKDF2 iterations raised to 310,000 (OWASP 2023). Multi-targeted net8.0 + net9.0. Provider-agnostic EF Core migrations with MySQL / Pomelo support. |
| **1.4.5** | Authentication rework using a real database for integration testing. GitHub Actions CI workflow added. |
| **1.1.0** | Package updates, code refactoring, removed stale code. |
| **1.0.9** | Package version alignment. |
| **1.0.6** | Minor fixes and package updates. |
| **1.0.5** | Shortened API method names; test improvements. |
| **1.0.3** | Initial release: `N2IdentityContext`, `N2UserManager`, `ApplicationUser`/`ApplicationRole`, SQL Server support, JWT authentication, email confirmation tokens. |

## Database Migrations

### How migrations work

The library ships a single set of EF Core migrations (in `Migrations/`) that run
unchanged against **SQL Server** and **MySQL / Pomelo**. This is achieved through
two design-time components in `Data/`:

| File | Purpose |
|---|---|
| `DesignTimeFactory.cs` | Gives `dotnet ef` a SQL Server context to scaffold against (the canonical provider for migration generation). |
| `ProviderAgnosticDesignTimeServices.cs` | Replaces EF Core's default `ICSharpMigrationOperationGenerator` with `AgnosticMigrationOperationGenerator`, and replaces `IAnnotationCodeGenerator` with `AgnosticAnnotationCodeGenerator`. |

`AgnosticMigrationOperationGenerator` intercepts every migration operation **before**
the C# code is written and:

1. **Nullifies `ColumnType`** on every column — `type: "nvarchar(256)"` etc. are
   omitted from the generated code. At runtime, `MigrateAsync` resolves the
   correct DDL type through the active provider's type mapper (e.g.
   `uniqueidentifier` on SQL Server, `char(36)` on MySQL).
2. **Adds `MySql:ValueGenerationStrategy = IdentityColumn`** alongside every
   `SqlServer:Identity` annotation, so auto-increment columns work on both engines.
3. **Removes `filter:` from unique indexes** — the SQL Server partial-index syntax
   (`WHERE [NormalizedName] IS NOT NULL`) is not supported by MySQL. Both providers
   allow multiple NULLs in a UNIQUE index by default, so the filter is unnecessary.

`AgnosticAnnotationCodeGenerator` intercepts snapshot and Designer-file generation
and omits `HasColumnType()` from every property. Each provider then resolves the
correct DDL type through its own type mapper at migration-execution time, and the
model differ re-derives provider-specific types via conventions when comparing
snapshots — so no spurious `AlterColumn` operations are generated.

### Why the model snapshot keeps SQL Server types (existing migrations only)

The snapshot (`N2IdentityContextModelSnapshot.cs`) retains full SQL Server type
annotations **for migrations that were generated before `AgnosticAnnotationCodeGenerator`
was in place**. The snapshot is **only used by `dotnet ef migrations add`** to diff
the previous model state against the current one.

If the snapshot were type-agnostic but the live SQL Server model has resolved types,
the migration differ would detect a mismatch and generate spurious `AlterColumn`
operations for every column. Keeping the snapshot in SQL Server form prevents this
**for legacy snapshots**. Migrations generated with the current tooling produce
type-agnostic snapshots automatically.

> **Warning — MySQL `PendingModelChangesWarning`**
>
> When migrations were generated before `AgnosticAnnotationCodeGenerator` was
> active, their Designer snapshots contain SQL Server column-type annotations
> (e.g. `HasColumnType("uniqueidentifier")`). EF Core 8+ compares this snapshot
> against the live MySQL model and finds a mismatch (SQL Server types vs. Pomelo
> types), which would normally throw a `PendingModelChangesWarning` exception and
> abort `MigrateAsync`.
>
> `N2IdentityContextFactory` downgrades this to a **logged warning** for MySQL
> contexts so that migrations can still run. The schema produced by the migration
> `Up()` method is always correct because `AgnosticMigrationOperationGenerator`
> strips provider-specific types from the migration code itself.
>
> **To eliminate the warning entirely**, regenerate the migration after the
> `AgnosticAnnotationCodeGenerator` is in place:
> ```powershell
> dotnet ef migrations remove --force --project src/N2.Core.Identity --startup-project src/N2.Core.Identity --context N2IdentityContext --framework net10.0
> dotnet ef migrations add <MigrationName> --project src/N2.Core.Identity --startup-project src/N2.Core.Identity --context N2IdentityContext --framework net10.0
> ```
> The new Designer file and snapshot will have no `HasColumnType()` calls, and
> the warning will no longer appear.

### Adding a new migration

Connection string resolution order (SQL Server):

1. `SQLSERVER_IDENTITY_CONNECTION` environment variable
2. `ConnectionStrings:UserDbSqlServerTest` in user secrets
   (ID: `N2-Core-0c368d89-5cb3-4451-9c68-b79e69920a09`)

Run from the repository root (change the name for the migration):

```powershell
dotnet ef migrations add InitialMigration --project src/N2.Core.Identity --startup-project src/N2.Core.Identity --context N2IdentityContext --framework net8.0
```

The generated migration file will contain **no `type:` parameters** and will carry
both `SqlServer:Identity` and `MySql:ValueGenerationStrategy` annotations on
auto-increment columns. The Designer file and snapshot will also contain no
`HasColumnType()` calls. Commit the migration file, the Designer file, and the
updated snapshot.

## Basic Setup

1. **Configure the DbContext in your application:**
[![NuGet](https://img.shields.io/nuget/v/N2.Core.Identity.svg)](https://www.nuget.org/packages/N2.Core.Identity/)
2. **Register the N2UserManager:**
3. **Configure Identity (optional, for ASP.NET Core):**
4. **Use N2UserManager in your application:**

``` C#
using N2.Core.Identity.Services; using N2.Core.Identity.Data;
public class AccountService { private readonly IUserManager<ApplicationUser> _userManager;
   public AccountService(IUserManager<ApplicationUser> userManager)
   {
       _userManager = userManager;
   }

   public async Task CreateUserAsync(string email, string password)
   {
       var user = new ApplicationUser { UserName = email, Email = email };
       await _userManager.CreateAsync(user, password, CancellationToken.None);
   }
}
```

## Best Practices

1. Secure Configuration

- Connection Strings: Store database connection strings securely (e.g., environment variables, Azure Key Vault, or user secrets in development).  
- Sensitive Data: Never log sensitive information such as passwords or tokens.

2. Dependency Injection
- Always register N2UserManager and related services (N2IdentityContext, ApplicationUser, ApplicationRole) using dependency injection. This ensures proper lifetime management and testability.

3. Error Handling
- Always check the result of N2UserManager methods. Most methods return an ICommandResponse or similar result object—verify Status.IsSuccess() before proceeding.
- Handle and log errors gracefully, but avoid exposing internal details to end users.

4. User Input Validation
- Validate all user input before passing it to N2UserManager methods. This includes usernames, emails, and passwords.
- Use strong password policies and validate emails for format and uniqueness.

5. Token Management
- Use the provided token generation and validation methods for email confirmation and password reset. Tokens should be time-limited and single-use where possible.
- Never expose raw tokens in logs or error messages.

6. Role Management
- Use AddToRoleAsync, RemoveFromRoleAsync, and RoleExistsAsync to manage user roles. Always check for role existence before assignment.
- Avoid hardcoding role names; use constants or configuration.

7. DbContext Lifetime
- Ensure that the N2IdentityContext (or your DbContext) is registered with a scoped lifetime (the default for EF Core in ASP.NET Core).
- Avoid sharing DbContext instances across threads.

8. Concurrency and Transactions
- Be aware of concurrency issues, especially when updating user or role data. Use transactions if multiple changes must be atomic.
- Handle potential DbUpdateConcurrencyException or similar exceptions.

9. Security Practices
- Always hash and salt passwords using the built-in mechanisms.
- Use HTTPS for all communications.
- Enable account lockout and email confirmation for new users.

10. Testing
- Write unit and integration tests for all user management workflows.
- Use test doubles or in-memory databases for testing, not production data.



