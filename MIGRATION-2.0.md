# Migrating to N2.Core.Identity 2.0.0

This guide is for developers upgrading a codebase that consumes `N2.Core.Identity` 1.x (last
release 1.7.5) to 2.0.0. The full list of changes is in [CHANGELOG.md](CHANGELOG.md); this guide
explains how to apply them.

N2.Core.Identity 2.0.0 depends on `N2.Core.Abstractions` 2.0.0. Read the
[N2.Core.Abstractions migration guide](https://dev.azure.com/gjkaal/N2%20Vault%20services/_git/N2.Core.Abstractions?path=/MIGRATION-2.0.md&version=GBtrunk)
as well; section 3.1 below lists only the Abstractions changes that Identity consumers meet
directly.

## 1. Summary

**What changed.**

- The package applies the N2.Core.Abstractions 2.0.0 convention to its own members: every
  asynchronous member takes a **required** `CancellationToken` as its last parameter (no default
  value, no overload without it), and no member name ends in `Async`.
- Target frameworks are `net10.0` and `net11.0`; `net8.0` is dropped.
- EF Core and ASP.NET Core Identity EF move to 10.0.15.
- **MySQL support is removed.** 2.0.0 supports SQL Server only (section 4).
- Members that returned a bare `Task` now return a result (section 3.4).
- Security writes (lockout counter, MFA attempt record, refresh-token revocation) are no longer
  skipped when the caller cancels (section 5).

**Who is affected.**

- **Every consumer** of the package: the retarget and the renames are compile-time breaks.
- **MySQL users:** do not upgrade. Stay on 1.7.5 (section 4.3).
- **Code that implements or mocks** `IIdentityContext`, `IIdentityContextFactory`,
  `IApplicationManager`, `ITenantManager`, `ISecretManager` or `IN2UserManager`: rename the
  members and add the token parameter.
- **Code that relied on exceptions from `Complete`:** `DbUpdateException` and
  `DbUpdateConcurrencyException` now come back as a status (section 5.4).

**Effort.** Mostly mechanical. The compiler finds every renamed call (`CS1061`, `CS0117`,
`CS7036`, `CS0535`). The part that needs thought is passing a real `CancellationToken` from the
calling context instead of `CancellationToken.None` (section 7).

**Target frameworks.**

| 1.7.5 | 2.0.0 |
| --- | --- |
| `net8.0` | dropped |
| `net10.0` | `net10.0` |
| -- | `net11.0` (new) |

There is no `netstandard` asset. An application on .NET 8 or .NET 9 cannot consume 2.0.0; it
must retarget to `net10.0` or `net11.0` first.

**Minimum SDK.** .NET 10 SDK (10.0.x) for `net10.0`, .NET 11 SDK (11.0.x) for `net11.0`.

## 2. Upgrade checklist

1. **Check the database provider.** If any configuration, constructor call or DI registration
   uses `DatabaseProvider.MySql` (or the integer value 1), stop here and read section 4.

2. **Retarget.** Change `<TargetFramework>` to `net10.0` or `net11.0`. Install the matching SDK
   and update `global.json` if you pin one.

3. **Update the package references.**

   ```xml
   <PackageReference Include="N2.Core.Identity" Version="2.0.0" />
   <PackageReference Include="N2.Core.Abstractions" Version="2.0.0" />
   ```

   With central package management, change the versions in `Directory.Packages.props`. The
   package is on the `vault-packages` feed only (section 6).

4. **Align EF Core and ASP.NET Core packages.** If your project references any of the packages
   in section 6.2 directly, raise them to at least the listed version; otherwise NuGet reports a
   downgrade (`NU1605`). Remove `Pomelo.EntityFrameworkCore.MySql` if you referenced it only
   for this library.

5. **Build and fix the compile errors** with the tables in section 3. For each error:
   - **Caller:** drop the `Async` suffix and add a `CancellationToken` argument.
   - **Implementer or mock:** rename the method, add `CancellationToken` as the last parameter,
     and remove any `= default` on an existing token parameter.

6. **Fix the bare-Task call sites** (section 3.4) if you discarded or awaited the old `Task`.

7. **Review error handling around `Complete`** (section 5.4) and the
   `RevokeRefreshToken` result (section 5.3).

8. **Pass real tokens.** Replace any `CancellationToken.None` added to get the code compiling
   with a token from the calling context (section 7).

9. **Search for leftovers** with the patterns in section 8, then run your tests.

10. **Database.** No schema action is required. The migration history is unchanged on SQL
    Server (section 4.4).

## 3. Breaking API changes

Members not listed here are unchanged. "Parameters unchanged" means the member already took a
token in 1.x and only lost the `Async` suffix.

### 3.1 N2.Core.Abstractions changes seen through this package

These interfaces live in N2.Core.Abstractions and are implemented by N2.Core.Identity. The full
tables are in the Abstractions guide, sections 3.2 and 3.5.

| Interface (implementing type) | 1.x member | 2.0.0 member |
| --- | --- | --- |
| `IUnitOfWork` (`N2IdentityContext`) | `Complete()` | `Complete(CancellationToken)` |
| `ICoreDataContext` (`N2IdentityContext`) | `DeleteAsync<T>(Guid)` | `Delete<T>(Guid, CancellationToken)` |
| `ICoreDataContext` (`N2IdentityContext`) | `FindRecordAsync<T>(Guid)` | `FindRecord<T>(Guid, CancellationToken)` |
| `ICoreDataContext` (`N2IdentityContext`) | `GetSelectListAsync(string)` | `GetSelectList(string, CancellationToken)` |
| `ICoreDataContextFactory<IIdentityContext>` (`N2IdentityContextFactory`) | `CreateAsync()` | `Create(CancellationToken)` |
| `ICoreDataContextFactory<IIdentityContext>` (`N2IdentityContextFactory`) | `CreateAsync(string)` | `Create(string, CancellationToken)` |
| `IAuthenticator` (`N2AuthenticationService`) | `AuthenticateAsync(IUserLogin)` | `Authenticate(IUserLogin, CancellationToken)` |
| `IUserContextFactory` (`UserContextFactory`) | `CreateAsync()` | `Create(CancellationToken)` |
| `IUserManager<ApplicationUser>` (`N2UserManager`) | `...Async(...)` | same name without `Async`, parameters unchanged (section 3.3) |

### 3.2 Identity context and context factory

`IIdentityContextFactory` / `N2IdentityContextFactory`:

| 1.x member | 2.0.0 member |
| --- | --- |
| `CreateAsync()` | `Create(CancellationToken)` |
| `CreateAsync(string)` | `Create(string, CancellationToken)` |
| `CreateAsync(DatabaseProvider)` | `Create(DatabaseProvider, CancellationToken)` |
| `CreateAsync(DatabaseProvider, string)` | `Create(DatabaseProvider, string, CancellationToken)` |

The 2.0.0 declarations:

```csharp
public Task<IIdentityContext> Create(CancellationToken cancellationToken)
public Task<IIdentityContext> Create(string connectionName, CancellationToken cancellationToken)
public Task<IIdentityContext> Create(DatabaseProvider provider, CancellationToken cancellationToken)
public Task<IIdentityContext> Create(DatabaseProvider provider, string connectionName, CancellationToken cancellationToken)
```

`Create` throws `OperationCanceledException` when the token is already cancelled, and
`IdentityConfigurationException` when the provider is not `DatabaseProvider.SqlServer`.

```csharp
// 1.x
using IIdentityContext context = await factory.CreateAsync(DatabaseProvider.SqlServer, "Identity");

// 2.0.0
using IIdentityContext context = await factory.Create(DatabaseProvider.SqlServer, "Identity", cancellationToken);
```

`N2IdentityContext` (`IIdentityContext`):

| 1.x member | 2.0.0 member |
| --- | --- |
| `Task<(ResponseStatus status, string? message)> Complete()` | `Task<(ResponseStatus status, string? message)> Complete(CancellationToken cancellationToken)` |
| `Task<(ResponseStatus status, string message)> DeleteAsync<T>(Guid publicId)` | `Task<(ResponseStatus status, string message)> Delete<T>(Guid publicId, CancellationToken cancellationToken)` |
| `Task<T?> FindRecordAsync<T>(Guid publicId)` | `Task<T?> FindRecord<T>(Guid publicId, CancellationToken cancellationToken)` |
| `Task<List<KeyValuePair<string, string>>> GetSelectListAsync(string tableName)` | `Task<List<KeyValuePair<string, string>>> GetSelectList(string tableName, CancellationToken cancellationToken)` |
| `Task RefreshTokenRevokeAll(Guid userId, CancellationToken ct)` | `Task<int> RefreshTokenRevokeAll(Guid userId, CancellationToken ct)` (section 3.4) |

```csharp
// 1.x
context.RefreshTokenRevoke(token);
(ResponseStatus status, string? message) = await context.Complete();

// 2.0.0
context.RefreshTokenRevoke(token);
(ResponseStatus status, string? message) = await context.Complete(cancellationToken);
```

The other `IIdentityContext` members already took a token in 1.x and had no `Async` suffix;
they are unchanged.

### 3.3 Services

**`N2AuthenticationService`.** `AuthenticateAsync(IUserLogin, CancellationToken)` is renamed to
`Authenticate(IUserLogin, CancellationToken)`. The overload without a token
(`AuthenticateAsync(IUserLogin)`, which passed `CancellationToken.None`) is **removed**.

```csharp
public async Task<IUserContext?> Authenticate(IUserLogin userLogin, CancellationToken cancellationToken)
```

```csharp
// 1.x
IUserContext? user = await authenticator.AuthenticateAsync(login);

// 2.0.0
IUserContext? user = await authenticator.Authenticate(login, cancellationToken);
```

**`UserContextFactory`.** `CreateAsync()` -> `Create(CancellationToken)`.

```csharp
public async Task<IUserContext> Create(CancellationToken cancellationToken)
```

```csharp
// 1.x
IUserContext userContext = await userContextFactory.CreateAsync();

// 2.0.0
IUserContext userContext = await userContextFactory.Create(cancellationToken);
```

**`N2UserManager`** (`IN2UserManager`, `IUserManager<ApplicationUser>`). Parameters unchanged
except where noted:

| 1.x member | 2.0.0 member |
| --- | --- |
| `AddToRoleAsync` | `AddToRole` |
| `CanSignInAsync` | `CanSignIn` (explicit `IUserManager<ApplicationUser>` implementation) |
| `ConfirmEmailAsync` | `ConfirmEmail` |
| `CreateAsync` | `Create` |
| `CreateRoleAsync` | `CreateRole` |
| `DeleteAsync` | `Delete` |
| `FindByEmailAsync` | `FindByEmail` |
| `FindByIdAsync` | `FindById` |
| `FindByNameAsync` | `FindByName` (explicit `IUserManager<ApplicationUser>` implementation) |
| `GenerateConfirmationTokenAsync` | `GenerateConfirmationToken` |
| `GetRolesAsync` | `GetRoles` |
| `GetTenantMembershipsAsync(ApplicationUser, CancellationToken)` | `GetTenantMemberships(ApplicationUser, CancellationToken)` |
| `GetUserIdAsync` | `GetUserId` |
| `IsInRoleAsync` | `IsInRole` |
| `RemoveFromRoleAsync` | `RemoveFromRole` |
| `RemoveRoleAsync` | `RemoveRole` |
| `RoleExistsAsync` | `RoleExists` |
| `RotateMfaSecretsAsync(CancellationToken cancellationToken = default)` | `RotateMfaSecrets(CancellationToken ct)` -- the token is now required |
| `SetEmailAsync` | `SetEmail` |
| `SetMultifactorAsync` | `SetMultifactor` |
| `SetUserNameAsync` | `SetUserName` |
| `ValidateAsync` | `Validate` |
| `ValidateMultifactorAsync` | `ValidateMultifactor` |
| `Task CreateUserAlert(Guid, UserAlert, CancellationToken)` | `Task<ResponseStatus> CreateUserAlert(Guid, UserAlert, CancellationToken)` (section 3.4) |

`CanSignIn` and `FindByName` are explicit interface implementations, as in 1.x: call them
through `IUserManager<ApplicationUser>` or `IN2UserManager`, not through a variable of type
`N2UserManager`.

```csharp
// 1.x
ICommandResponse result = await userManager.ValidateAsync(user, password, cancellationToken);
int rotated = await userManager.RotateMfaSecretsAsync();
var memberships = await userManager.GetTenantMembershipsAsync(user, cancellationToken);

// 2.0.0
ICommandResponse result = await userManager.Validate(user, password, cancellationToken);
int rotated = await userManager.RotateMfaSecrets(cancellationToken);
var memberships = await userManager.GetTenantMemberships(user, cancellationToken);
```

**`IApplicationManager` / `N2ApplicationManager`** (parameters unchanged):

| 1.x member | 2.0.0 member |
| --- | --- |
| `CreateAsync` | `Create` |
| `DeleteAsync` | `Delete` |
| `UpdateAsync` | `Update` |
| `FindByIdAsync` | `FindById` |
| `FindByNameAsync` | `FindByName` |
| `LockAsync` | `Lock` |
| `UnlockAsync` | `Unlock` |

`GetApplicationGetSelectList(Guid, CancellationToken)` is unchanged.

**`ITenantManager` / `N2TenantManager`** (parameters unchanged):

| 1.x member | 2.0.0 member |
| --- | --- |
| `CreateAsync` | `Create` |
| `DeleteAsync` | `Delete` |
| `UpdateAsync` | `Update` |
| `FindByIdAsync` | `FindById` |
| `FindByNameAsync` | `FindByName` |
| `FindByEmailAsync` | `FindByEmail` |
| `GetTenantsAsync` | `GetTenants` |
| `LockAsync` | `Lock` |
| `UnlockAsync` | `Unlock` |
| `AddUserAsync` (both overloads) | `AddUser` |
| `RemoveUserAsync` | `RemoveUser` |
| `GetUsersForTenantAsync` | `GetUsersForTenant` |
| `GetTenantIdsForUserAsync` | `GetTenantIdsForUser` |
| `SetAdminAsync` | `SetAdmin` |
| `IsAdminAsync` | `IsAdmin` |
| `GetAdminsForTenantAsync` | `GetAdminsForTenant` |

**`ISecretManager` / `N2SecretManager`** (parameters unchanged):

| 1.x member | 2.0.0 member |
| --- | --- |
| `CreateAsync` | `Create` |
| `RevokeAsync` | `Revoke` |
| `SetValueAsync` | `SetValue` |
| `ValidateAsync` | `Validate` |
| `FindByIdAsync` | `FindById` |
| `GetSelectListAsync` | `GetSelectList` |
| `GetPolicyAsync<T>` | `GetPolicy<T>` |
| `SetPolicyAsync<T>` | `SetPolicy<T>` |

```csharp
// 1.x
await tenantManager.AddUserAsync(user, tenant, isAdmin: true, cancellationToken);
ICommandResponse<ApplicationSecretDto> secret = await secretManager.ValidateAsync(plainToken, cancellationToken);

// 2.0.0
await tenantManager.AddUser(user, tenant, isAdmin: true, cancellationToken);
ICommandResponse<ApplicationSecretDto> secret = await secretManager.Validate(plainToken, cancellationToken);
```

### 3.4 Bare Task -> result

| Member | 1.x return | 2.0.0 return | Meaning |
| --- | --- | --- | --- |
| `N2UserManager.CreateUserAlert` | `Task` | `Task<ResponseStatus>` | the persistence status from `Complete` |
| `IIdentityContext.RefreshTokenRevokeAll` / `N2IdentityContext.RefreshTokenRevokeAll` | `Task` | `Task<int>` | the number of refresh tokens marked as revoked (not yet saved) |
| `TimeoutTimer.Wait` (internal) | `Task Wait()` | `Task<bool> Wait(CancellationToken)` | `true` when it padded, `false` when the time budget was already used |

`TimeoutTimer` is `internal`; it is listed only because it explains the cancellation behaviour
in section 5.2. Implementers and mocks of `IIdentityContext` must change the return type of
`RefreshTokenRevokeAll`.

```csharp
// 1.x
await context.RefreshTokenRevokeAll(userId, cancellationToken);
await context.Complete();

// 2.0.0
int revoked = await context.RefreshTokenRevokeAll(userId, cancellationToken);
(ResponseStatus status, _) = await context.Complete(cancellationToken);
```

```csharp
// 1.x
await userManager.CreateUserAlert(userId, alert, cancellationToken);

// 2.0.0
ResponseStatus status = await userManager.CreateUserAlert(userId, alert, cancellationToken);
if (!status.IsSuccess()) { /* the alert was not stored */ }
```

`RefreshTokenRevokeAll` still only marks the tokens; call `Complete` to persist, as in 1.x.

### 3.5 Logging extension

`UserManagerLoggerExtensions.LogMfaVerificationWarning` no longer logs the multifactor code or
the user name; it logs the user id only.

```csharp
// 1.x
public static void LogMfaVerificationWarning(this ILogger logger, string message, string mfaCode, string userName, Exception ex)

// 2.0.0
public static void LogMfaVerificationWarning(this ILogger logger, string message, Guid userId, Exception ex)
```

The message template changes from
`Error {Message} while verifying MFA token [{MultifactorCode}] for user [{UserName}].` to
`Error {Message} while verifying an MFA token for user {UserId}.` (event id 2, unchanged).
Update log queries and alerts that matched `MultifactorCode` or `UserName` on this event.

New: `LogAccessFailedCountNotPersisted(this ILogger logger, Guid userId, ResponseStatus status)`,
event id 11, level Error. `N2UserManager.Validate` writes it when the lockout counter write did
not succeed.

## 4. MySQL support removed (known limitation)

### 4.1 What changed

`Pomelo.EntityFrameworkCore.MySql` has no stable release for EF Core 10, so the MySQL provider
is removed. N2.Core.Identity 2.0.0 supports SQL Server only.

```csharp
// 1.x
public enum DatabaseProvider {
    SqlServer,
    MySql
}

// 2.0.0
public enum DatabaseProvider {
    SqlServer = 0
}
```

The factory no longer has a MySQL branch: no `UseMySql`, no parsing of the custom `Version=`
connection-string key, no `PendingModelChangesWarning` suppression.

### 4.2 Fail-fast behaviour

Any value other than `DatabaseProvider.SqlServer` (for example a configuration or cast that
still produces the old value 1) throws the new `IdentityConfigurationException`
(namespace `N2.Core.Identity`, derives from `Exception`):

- from the `N2IdentityContextFactory` constructor, for its default provider;
- from `N2IdentityContextFactory.Create`, for the provider argument.

The message names the value and the supported provider:

```
Database provider value '1' is not supported by N2.Core.Identity 2.0.0. Only 'SqlServer' is
supported; MySQL support was removed in 2.0.0 and is planned as a separate package
(N2.Core.Identity.MySql).
```

The service constructors (`N2UserManager`, `N2ApplicationManager`, `N2TenantManager`,
`N2SecretManager`) accept a `DatabaseProvider` and do not validate it themselves. A service
constructed with an unsupported value fails on its first call, when it creates a context.

### 4.3 What MySQL users should do

Stay on N2.Core.Identity **1.7.5** until N2.Core.Identity.MySql exists. 1.7.5 depends on
N2.Core.Abstractions 1.7.1 and implements its 1.x interfaces, so keep N2.Core.Abstractions on
1.7.x as well in the same application. Pin both versions explicitly so a floating version or a
bulk update does not pull in 2.0.0:

```xml
<PackageReference Include="N2.Core.Identity" Version="[1.7.5]" />
<PackageReference Include="N2.Core.Abstractions" Version="[1.7.1]" />
```

1.7.5 targets `net8.0` and `net10.0` and uses EF Core 9 on `net10.0`.

MySQL support is planned to return as a separate package, N2.Core.Identity.MySql, once a stable
EF Core 10 MySQL provider exists. The migrations in N2.Core.Identity stay provider-neutral (no
explicit column types, no partial-index filters) so that package can reuse them.

### 4.4 Migrations and model snapshot

- Migration `20260511094137_InitialCreate` lost its two `MySql:ValueGenerationStrategy`
  annotations. SQL Server ignores these annotations, so the SQL Server DDL and the migration id
  are unchanged. Databases already migrated need no action, and the `__EFMigrationsHistory`
  table needs no change. There were no MySQL-only migrations.
- The model has no pending changes against EF Core 10 (verified with the 2.0.0 release).
- The model snapshot (`N2IdentityContextModelSnapshot`) still carries
  `ProductVersion` `9.0.14`. It changes to the EF Core 10 version with the next migration that is
  added; this has no effect at run time.
- Design time: `AgnosticMigrationOperationGenerator` no longer adds the
  `MySql:ValueGenerationStrategy` annotation to new migrations.

## 5. Behaviour changes

### 5.1 Security writes are committed even when the caller cancels

The following writes run with `CancellationToken.None` once they start, so cancelling the
request cannot skip them. Each is one bounded single-row read and update, or one bounded query
and update.

| Member | Write that is no longer cancellable |
| --- | --- |
| `N2UserManager.Validate` | the failed-access increment after a wrong password (and the lockout it may set), and the reset after a correct password |
| `N2UserManager.ValidateMultifactor` | the failed-attempt record in the MFA rate limiter, now made before the cancellable padding wait |
| `N2TokenService.RevokeRefreshToken` | the commit of the revocation (the lookup still uses the caller's token) |
| `N2TokenService.Refresh` | on a security-stamp mismatch: revoking all the user's refresh tokens and the commit |
| `N2TokenService.Logoff` | the whole revocation: context creation, `RefreshTokenRevokeAll` and the commit |

In 1.x the exception handlers around the lockout counter and the MFA validation also caught
`OperationCanceledException`. They no longer do: a cancellation propagates to the caller.

### 5.2 Constant-time padding ends early on cancellation

`N2AuthenticationService.Authenticate`, `N2UserManager.Validate` and
`N2UserManager.ValidateMultifactor` pad their response time to a fixed budget so that timing does
not reveal whether a user exists or a code was close. In 1.x the padding ignored cancellation.
In 2.0.0 it observes the caller's token: a cancelled request ends the delay early with
`OperationCanceledException`. Only a caller that has already abandoned the request sees the
shorter time, and the security writes of section 5.1 happen before the wait.

`N2IdentityContextFactory.Create` throws `OperationCanceledException` when the token is already
cancelled. `UserContextFactory.Create` stops waiting for the authentication state when its
token is cancelled; the authentication state is still resolved once and shared by later calls.

### 5.3 `RevokeRefreshToken` returns false when the commit fails

`N2TokenService.RevokeRefreshToken(string, CancellationToken)` returned `true` in 1.x as soon as
the token was found. In 2.0.0 it returns `true` only when the revocation was persisted:

| Result | Condition |
| --- | --- |
| `false` | the token does not exist or is already revoked |
| `false` | the token was found but `Complete` did not return a success status (new) |
| `true` | the token was found and the revocation was persisted |

Treat `false` as "this token may still be valid" and do not report a successful logout for it.

### 5.4 `Complete` maps EF Core update errors to a status

`N2IdentityContext.Complete(CancellationToken)` now catches the EF Core update exceptions and
returns a status, as N2.Core.Entity does:

| Exception from `SaveChangesAsync` | 1.x | 2.0.0 |
| --- | --- | --- |
| `DbUpdateConcurrencyException` | thrown to the caller | `(ResponseStatus.Conflict, exception message)` |
| `DbUpdateException` | thrown to the caller | `(ResponseStatus.ServerError, inner exception message, or the exception message when there is no inner exception)` |
| `DbException` | `(ResponseStatus.ServerError, exception message)` | unchanged |
| `OperationCanceledException` | thrown | thrown (not caught) |

Code that wrapped `Complete()` in `try`/`catch (DbUpdateException)` must check the returned
status instead.

**Security note.** The message returned with `Conflict` and `ServerError` can contain provider
error text, such as SQL Server constraint, index, table or column names and values. Log it; do
not return it to end users or put it in an API response.

```csharp
(ResponseStatus status, string? message) = await context.Complete(cancellationToken);
if (!status.IsSuccess())
{
    logger.LogWarning("Identity update failed: {Status} {Message}", status, message);
    return new RequestResult(status, "The change could not be saved.");   // illustrative
}
```

## 6. Package source and dependencies

### 6.1 Package source

2.0.0 is published to the `vault-packages` Azure Artifacts feed only; there is no nuget.org
release. The consuming solution's `nuget.config` needs this source:

```xml
<configuration>
  <packageSources>
    <add key="vault-packages" value="https://pkgs.dev.azure.com/gjkaal/N2%20Vault%20services/_packaging/vault-packages/nuget/v3/index.json" />
  </packageSources>
</configuration>
```

Keep credentials out of `nuget.config`. Authenticate with the Azure Artifacts credential
provider locally, and in CI or Docker builds with a personal access token with the
Packaging (Read) scope, supplied as a pipeline secret or BuildKit secret.

### 6.2 Dependencies

| Package | 1.7.5 (`net10.0`) | 2.0.0 (both targets) |
| --- | --- | --- |
| `N2.Core.Abstractions` | 1.7.1 | 2.0.0 |
| `Microsoft.AspNetCore.Diagnostics.EntityFrameworkCore` | 9.0.14 | 10.0.15 |
| `Microsoft.AspNetCore.Identity.EntityFrameworkCore` | 9.0.14 | 10.0.15 |
| `Microsoft.EntityFrameworkCore.Relational` | 9.0.14 | 10.0.15 |
| `Microsoft.EntityFrameworkCore.SqlServer` | 9.0.14 | 10.0.15 |
| `Microsoft.EntityFrameworkCore.Tools` / `.Design` (private assets) | 9.0.14 | 10.0.15 |
| `Pomelo.EntityFrameworkCore.MySql` | 9.0.0 | removed |
| `Microsoft.AspNetCore.Authentication.JwtBearer` | 10.0.7 | 10.0.15 |
| `Microsoft.Extensions.Configuration.UserSecrets` | 10.0.* | 10.0.15 |
| `Microsoft.IdentityModel.Tokens` | 8.18.0 | 8.23.0 |
| `System.IdentityModel.Tokens.Jwt` | 8.18.0 | 8.23.0 |
| `QRCoder` | 1.8.0 | 1.8.1 |
| `Otp.NET` | 1.4.1 | 1.4.1 |

On `net8.0`, 1.7.5 used the 8.0.26 ASP.NET Core packages and EF Core SqlServer 9.0.15; that
target no longer exists.

If your own projects run `dotnet ef` against this context, use the EF Core 10 tools
(`dotnet tool update --global dotnet-ef --version 10.0.15`).

## 7. Where to get a CancellationToken

Pass the token of the outermost caller down through every layer; the Abstractions guide,
section 5, covers this in full. In short:

- **ASP.NET Core minimal API or controller:** a `CancellationToken` parameter (binds to
  `HttpContext.RequestAborted`).
- **Middleware, filters, authentication handlers:** `HttpContext.RequestAborted`.
- **Blazor component:** a `CancellationTokenSource` owned by the component and cancelled in
  `Dispose`.
- **Background service:** the `stoppingToken` of `BackgroundService.ExecuteAsync`, for example
  for a scheduled `RotateMfaSecrets` run.
- **Tests:** the test framework's token (MSTest `TestContext.CancellationToken`). In Moq setups,
  match the new parameter with `It.IsAny<CancellationToken>()`:

```csharp
factory.Setup(f => f.Create(It.IsAny<DatabaseProvider>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
       .ReturnsAsync(context);
```

Do not compensate for section 5.1 by passing `CancellationToken.None` yourself: the library
already shields the security writes from cancellation.

## 8. Finding affected call sites

The compiler finds every break; these searches help to scope the work up front and to catch
behaviour changes the compiler does not report. Patterns are regular expressions (for example
`git grep -nE '<pattern>' -- '*.cs' '*.razor' '*.json'`). BCL and EF Core methods keep their
`Async` suffix, so expect hits that need no change.

| Pattern | Finds |
| --- | --- |
| `DatabaseProvider\.MySql\|"MySql"` | MySQL configuration: do not upgrade (section 4) |
| `Pomelo` | MySQL provider references and usings |
| `\.CreateAsync\(` | factory, `UserContextFactory`, user/tenant/application/secret manager `CreateAsync` calls |
| `(AuthenticateAsync\|GetTenantMembershipsAsync\|RotateMfaSecretsAsync)\(` | renamed `N2AuthenticationService` / `N2UserManager` members |
| `(FindBy(Id\|Name\|Email)\|Lock\|Unlock\|Update\|Delete\|AddUser\|RemoveUser\|SetAdmin\|IsAdmin)Async\(` | renamed manager members |
| `(GetUsersForTenant\|GetTenantIdsForUser\|GetAdminsForTenant\|GetTenants)Async\(` | renamed `ITenantManager` members |
| `(Revoke\|SetValue\|Validate\|GetSelectList\|ValidateMultifactor)Async\(` | renamed secret manager, user manager and context members |
| `(GetPolicy\|SetPolicy)Async<` | renamed generic `ISecretManager` members |
| `(FindRecord\|Delete)Async<` | renamed generic `N2IdentityContext` members |
| `\.Complete\(\)` | `IUnitOfWork.Complete()` calls without a token |
| `catch \(DbUpdate(Concurrency)?Exception` | handlers around `Complete` that no longer fire (section 5.4) |
| `RevokeRefreshToken\(` | callers that ignored the result (section 5.3) |
| `RefreshTokenRevokeAll\(` | implementers and mocks of the `Task<int>` return |
| `CreateUserAlert\(` | callers of the `Task<ResponseStatus>` return |
| `LogMfaVerificationWarning\(\|MultifactorCode` | the logging extension and log queries on its old template |
| `CancellationToken\s+\w+\s*=\s*default` | implementations that still declare an optional token |
| `CancellationToken\.None\|default\(CancellationToken\)` | placeholder tokens to replace (section 7) |
| `<TargetFrameworks?>.*net[89]\.0` | projects that must be retargeted |
