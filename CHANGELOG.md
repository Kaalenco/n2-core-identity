# Changelog

All notable changes to N2.Core.Identity are documented here.
Versions follow [Semantic Versioning](https://semver.org/).

---

## 3.0.1 - 2026-11-24

Version unification release: all N2 packages move to 3.0.1. Major bump from 2.0.1 because the
package moves to N2.Core.Abstractions 3.0.0 (token format v2) and EF Core 11 on net11.0.
No public API of N2.Core.Identity changed.

Upgrade guide: [MIGRATION-3.0.md](MIGRATION-3.0.md).

### Version metadata

- `Version`/`PackageVersion` 3.0.1, `AssemblyVersion` 3.0.0.0 (stable across patch releases),
  `FileVersion` 3.0.1.0, `ProductVersion` 3.0.1.

### Targets

- `net10.0` and `net11.0` (unchanged). `netstandard2.0` is not added: ASP.NET Core Identity,
  EF Core 10/11 and JwtBearer do not support it.

### Dependencies

- `N2.Core.Abstractions` 2.0.0 -> 3.0.0 (3.0.1 follows once published).
- Per-TFM conditional groups: `net10.0` uses the 10.0.15 band, `net11.0` uses 11.0.0 for
  `Microsoft.AspNetCore.*`, `Microsoft.EntityFrameworkCore.*` and
  `Microsoft.Extensions.Configuration.UserSecrets` (was 10.0.15 for both).
- `QRCoder` 1.8.1 -> 1.9.0. `Microsoft.IdentityModel.Tokens` and `System.IdentityModel.Tokens.Jwt`
  stay at 8.23.0, `Otp.NET` at 1.4.1.
- Unit tests: `Microsoft.EntityFrameworkCore.InMemory` and `.Design` per TFM (10.0.15 / 11.0.0).

### Publishing

- Source of truth is GitHub (`Kaalenco/n2-core-identity`). The GitHub Actions workflow
  `.github/workflows/dotnet.yml` builds, runs the unit tests and publishes to the `vault-packages`
  feed on pushes to `trunk` (`--skip-duplicate`). nuget.org is handled by n2-publishing from the feed.
- `src/nuget.config` maps `N2.*` to `vault-packages` and everything else to nuget.org.
- CodeQL workflow restored to `.github/workflows/codeql.yml` (.NET 10 and 11, feed authentication).

---

## 2.0.1 - 2026-11-18

### Security

- `N2UserManager.Validate`: the wrong-password path now takes the same padded time as the
  unknown-user and locked-out paths (user enumeration by timing, CWE-208); present since 1.x.
  The failed-attempt counter is still written before the cancellable padding wait.
- `N2UserManager.ValidateMultifactor`: the "MFA type not available" failure path is now padded
  like the other MFA failure paths.
- `N2AuthenticationService.Authenticate`: the unknown-user branch now calls `Validate` with a
  user object that is not in the database (its own padded unknown-user path; no counter write)
  instead of waiting on the outer timer. Both branches now cost `FindByName` plus one padded
  `Validate`, so unknown-user and wrong-password logins stay indistinguishable through
  `Authenticate`.

### Changed

- `N2UserManager.Validate` with a wrong password and an already cancelled token now throws
  `OperationCanceledException` during the padding wait instead of returning NotAccepted. The
  failed-attempt counter is still written first.

---

## 2.0.0 - 2026-11-18

Major release. Moves to N2.Core.Abstractions 2.0.0 and applies its convention to this library:
every asynchronous member takes a required `CancellationToken` as its last parameter (no default
value, no overload without it) and no member name ends in `Async`. All changes below are
breaking unless stated otherwise.

Upgrade guide: [MIGRATION-2.0.md](MIGRATION-2.0.md).

### Targets and packaging

- **Breaking:** target frameworks are now `net10.0` and `net11.0`; `net8.0` is dropped. The
  test project targets `net10.0` and `net11.0`.
- `N2.Core.Abstractions` 1.7.1 -> 2.0.0.
- Both targets share one dependency set:
  - EF Core and ASP.NET Core Identity EF move to 10.0.15 (from 9.0.14 on net10.0; 8.0.26 /
    9.0.x on net8.0): `Microsoft.AspNetCore.Diagnostics.EntityFrameworkCore`,
    `Microsoft.AspNetCore.Identity.EntityFrameworkCore`, `Microsoft.EntityFrameworkCore.Relational`,
    `Microsoft.EntityFrameworkCore.SqlServer`, `Microsoft.EntityFrameworkCore.Tools`,
    `Microsoft.EntityFrameworkCore.Design`.
  - **Breaking:** `Pomelo.EntityFrameworkCore.MySql` 9.0.0 is removed (see "MySQL support
    removed").
  - `Microsoft.AspNetCore.Authentication.JwtBearer` 10.0.7 -> 10.0.15.
  - `Microsoft.Extensions.Configuration.UserSecrets` 10.0.* -> 10.0.15 (no floating version).
  - `Microsoft.IdentityModel.Tokens`, `System.IdentityModel.Tokens.Jwt` 8.18.0 -> 8.23.0.
  - `QRCoder` 1.8.0 -> 1.8.1. `Otp.NET` stays 1.4.1.
- Test packages: `Microsoft.NET.Test.Sdk` 18.5.1 -> 18.12.0, `MSTest.TestAdapter` and
  `MSTest.TestFramework` 4.2.2 -> 4.5.3, `coverlet.collector` 10.0.0 -> 10.1.1, `Moq` 4.20.72 ->
  4.21.0, `Microsoft.EntityFrameworkCore.InMemory` 9.0.15 -> 10.0.15,
  `Microsoft.EntityFrameworkCore.Design` 9.0.14 -> 10.0.15.
- `dotnet list src package --vulnerable --include-transitive` reports no vulnerable packages.
- Pipelines: the .NET SDK 11.0.x replaces 8.0.x (10.0.x kept); coverage runs on net10.0; the
  MySQL Integration Tests stage is removed from the publish pipeline (Publish no longer depends
  on it); tool versions are pinned: `dotnet-reportgenerator-globaltool` 5.6.0 and `lizard`
  1.25.0. Publishing stays on the `vault-packages` Azure Artifacts feed.
- Internal (no behaviour change): methods over the pipeline's cyclomatic complexity limit of 10
  (`lizard -C 10`) were split into private methods: `N2IdentityContext.UserCanSignInTenant`,
  `N2SecretManager.SetValue` and `Validate`, `N2TokenService.Refresh`, `N2UserManager.Validate`
  and `ValidateMultifactor`, and the `IdentityUserContext` constructor.

### MySQL support removed (known limitation)

- **Breaking:** the MySQL provider (Pomelo) is removed, because there is no stable Pomelo release
  for EF Core 10. N2.Core.Identity 2.0.0 supports SQL Server only. MySQL support is planned to
  return as a separate package, N2.Core.Identity.MySql, once a stable EF Core 10 MySQL provider
  exists.
- **Breaking:** `DatabaseProvider.MySql` is removed; `DatabaseProvider` has only `SqlServer` (0).
  Configuring any other value (for example the old value 1) fails fast: the
  `N2IdentityContextFactory` constructor and `Create` throw the new
  `IdentityConfigurationException` with a message that names the supported provider.
- The factory no longer has a MySQL branch (`UseMySql`, `Version=` connection-string parsing,
  `PendingModelChangesWarning` suppression).
- Design time: `AgnosticMigrationOperationGenerator` no longer adds the
  `MySql:ValueGenerationStrategy` annotation. Column types and partial-index filters are still
  stripped so new migrations stay consistent with the existing, provider-neutral ones.
- Migration `20260511094137_InitialCreate`: the two `MySql:ValueGenerationStrategy` annotations
  (Pomelo types) are removed. SQL Server ignores these annotations, so the generated SQL Server
  DDL and the migration id are unchanged; no database action is needed. There were no
  MySQL-only migrations.
- Removed: the MySQL integration tests (`Integration.MySql`), `src/docker-compose.integration.yml`
  and `src/Dockerfile.integration`.

### Abstractions implementations

- `N2IdentityContext` (`ICoreDataContext`, `IUnitOfWork`):
  - `Complete()` -> `Complete(CancellationToken)`
  - `DeleteAsync<T>(Guid)` -> `Delete<T>(Guid, CancellationToken)`
  - `FindRecordAsync<T>(Guid)` -> `FindRecord<T>(Guid, CancellationToken)`
  - `GetSelectListAsync(string)` -> `GetSelectList(string, CancellationToken)`
- `IIdentityContextFactory` / `N2IdentityContextFactory`:
  - `CreateAsync()` -> `Create(CancellationToken)`
  - `CreateAsync(string)` -> `Create(string, CancellationToken)`
  - `CreateAsync(DatabaseProvider)` -> `Create(DatabaseProvider, CancellationToken)`
  - `CreateAsync(DatabaseProvider, string)` -> `Create(DatabaseProvider, string, CancellationToken)`
- `N2AuthenticationService` (`IAuthenticator`): `AuthenticateAsync(IUserLogin, CancellationToken)`
  -> `Authenticate(IUserLogin, CancellationToken)`. The overload without a token
  (`AuthenticateAsync(IUserLogin)`, which used `CancellationToken.None`) is removed.
- `UserContextFactory` (`IUserContextFactory`): `CreateAsync()` -> `Create(CancellationToken)`.
- `N2UserManager` (`IUserManager<ApplicationUser>`), parameters unchanged: `AddToRoleAsync` ->
  `AddToRole`, `CanSignInAsync` -> `CanSignIn` (explicit implementation), `ConfirmEmailAsync` ->
  `ConfirmEmail`, `CreateAsync` -> `Create`, `CreateRoleAsync` -> `CreateRole`, `DeleteAsync` ->
  `Delete`, `FindByEmailAsync` -> `FindByEmail`, `FindByIdAsync` -> `FindById`, `FindByNameAsync` ->
  `FindByName` (explicit implementation), `GenerateConfirmationTokenAsync` ->
  `GenerateConfirmationToken`, `GetRolesAsync` -> `GetRoles`, `GetUserIdAsync` -> `GetUserId`,
  `IsInRoleAsync` -> `IsInRole`, `RemoveFromRoleAsync` -> `RemoveFromRole`, `RemoveRoleAsync` ->
  `RemoveRole`, `RoleExistsAsync` -> `RoleExists`, `SetEmailAsync` -> `SetEmail`,
  `SetMultifactorAsync` -> `SetMultifactor`, `SetUserNameAsync` -> `SetUserName`, `ValidateAsync`
  -> `Validate`, `ValidateMultifactorAsync` -> `ValidateMultifactor`.

### Library members

- `N2UserManager.GetTenantMembershipsAsync(ApplicationUser, CancellationToken)` ->
  `GetTenantMemberships(ApplicationUser, CancellationToken)`
- `N2UserManager.RotateMfaSecretsAsync(CancellationToken = default)` ->
  `RotateMfaSecrets(CancellationToken)`; the token is now required.
- `IApplicationManager` / `N2ApplicationManager` (parameters unchanged): `CreateAsync` -> `Create`,
  `DeleteAsync` -> `Delete`, `UpdateAsync` -> `Update`, `FindByIdAsync` -> `FindById`,
  `FindByNameAsync` -> `FindByName`, `LockAsync` -> `Lock`, `UnlockAsync` -> `Unlock`.
- `ITenantManager` / `N2TenantManager` (parameters unchanged): `CreateAsync` -> `Create`,
  `DeleteAsync` -> `Delete`, `UpdateAsync` -> `Update`, `FindByIdAsync` -> `FindById`,
  `FindByNameAsync` -> `FindByName`, `FindByEmailAsync` -> `FindByEmail`, `GetTenantsAsync` ->
  `GetTenants`, `LockAsync` -> `Lock`, `UnlockAsync` -> `Unlock`, `AddUserAsync` (2 overloads) ->
  `AddUser`, `RemoveUserAsync` -> `RemoveUser`, `GetUsersForTenantAsync` -> `GetUsersForTenant`,
  `GetTenantIdsForUserAsync` -> `GetTenantIdsForUser`, `SetAdminAsync` -> `SetAdmin`,
  `IsAdminAsync` -> `IsAdmin`, `GetAdminsForTenantAsync` -> `GetAdminsForTenant`.
- `ISecretManager` / `N2SecretManager` (parameters unchanged): `CreateAsync` -> `Create`,
  `RevokeAsync` -> `Revoke`, `SetValueAsync` -> `SetValue`, `ValidateAsync` -> `Validate`,
  `FindByIdAsync` -> `FindById`, `GetSelectListAsync` -> `GetSelectList`, `GetPolicyAsync<T>` ->
  `GetPolicy<T>`, `SetPolicyAsync<T>` -> `SetPolicy<T>`.

### Behaviour

- `N2IdentityContext.FindRecord`, `Delete`, `GetSelectList` and `Complete` pass the token to
  EF Core (`FindAsync`, `ToListAsync`, `SaveChangesAsync`).
- `N2IdentityContextFactory.Create` throws `OperationCanceledException` when the token is already
  cancelled.
- The services pass the caller's token to context creation and `Complete`, and to the
  constant-time padding delay in authentication and password/MFA validation. A cancelled
  request now ends that delay early with `OperationCanceledException`.
- `UserContextFactory.Create` stops waiting for the authentication state when the token is
  cancelled.
- `N2IdentityContext.Complete` no longer throws `DbUpdateException` /
  `DbUpdateConcurrencyException`: it returns `ServerError` / `Conflict` with the message. Callers
  that caught those exceptions must check the returned status instead. The message can contain
  provider error text; do not show it to end users.

### No bare Task returns

- `N2UserManager.CreateUserAlert` returns `Task<ResponseStatus>` (the persistence status); the
  authentication service's alert callback uses it.
- `IIdentityContext.RefreshTokenRevokeAll` / `N2IdentityContext.RefreshTokenRevokeAll` return
  `Task<int>`, the number of refresh tokens marked as revoked.
- Internal: `TimeoutTimer.Wait` returns `Task<bool>` (`true` when it padded, `false` when the
  time budget was already used); the private lockout helpers return the persistence
  `ResponseStatus` and `Validate` logs (event 11) when the lockout counter was not persisted.

### Security hardening

- Lockout counter: the failed-access increment and the reset after a correct password run with
  `CancellationToken.None` (one bounded single-row read and update), so cancelling the request
  cannot skip them. Their exception handlers no longer catch `OperationCanceledException`.
- MFA rate limiter: `ValidateMultifactor` records the attempt before the cancellable
  constant-time padding wait, so cancelling cannot skip the record. The generic exception
  handler no longer catches `OperationCanceledException`.
- **Breaking:** `UserManagerLoggerExtensions.LogMfaVerificationWarning(string, string, string,
  Exception)` -> `LogMfaVerificationWarning(string, Guid, Exception)`. The raw multifactor code
  and user name are no longer logged; only the user id.
- New: `UserManagerLoggerExtensions.LogAccessFailedCountNotPersisted(Guid, ResponseStatus)`.
- `N2TokenService`: revocation writes are not cancellable once started. `RevokeRefreshToken`
  commits with `CancellationToken.None` (the lookup still uses the caller's token); the
  security-stamp-mismatch path in `Refresh` revokes and commits with `CancellationToken.None`;
  `Logoff` runs its whole revocation with `CancellationToken.None`.
- `N2TokenService.RevokeRefreshToken` now returns `false` when the revocation could not be
  persisted (previously always `true` once the token was found).
- `N2IdentityContext.Complete` maps `DbUpdateConcurrencyException` to `Conflict` and
  `DbUpdateException` to `ServerError` with the inner exception message, as N2.Core.Entity
  does; `DbException` still maps to `ServerError`. `OperationCanceledException` is not caught.

---

## 1.7.0 — 2026-04-14

### Added

- **`N2TokenService`** — new service (`IN2TokenService`) that owns the full token lifecycle:
  - `IssueTokenPair` — generates a JWT access token and a persisted refresh token in a single call.
  - `Refresh` — validates and rotates a refresh token atomically. A 2-second in-memory grace window
    handles retries and simultaneous calls without invalidating the token on duplicate requests.
  - `RevokeRefreshToken` — revokes a single refresh token by value.
  - `Logoff` — revokes all active refresh tokens for a user (all sessions).
  - `ReadUserIdFromExpiredToken` — reads the subject claim from an expired JWT without signature or
    lifetime validation; intended for identifying the user at the refresh endpoint.
  - `IssuePreAuthToken` — issues a short-lived JWT containing only identity claims (no roles or
    tenant memberships) for use between credential validation and MFA confirmation.
- **`TokenPairResult`** — DTO returned by `IssueTokenPair` and `Refresh`, carrying
  `AccessToken`, `RefreshToken`, and `RefreshTokenExpiresAt`.
- **`ApplicationRefreshToken.SecurityStamp`** — stores the user's security stamp at token issuance.
  On refresh, a mismatch causes immediate revocation of all sessions for that user.
- **`AspNetUserContext.SecurityStamp`** — surfaces the `ApplicationUser.SecurityStamp` through the
  user context so `N2TokenService` and `WebTokenGenerator` can embed and verify it.
- **`IIdentityContext.RefreshTokenRevokeAll`** — marks all active refresh tokens for a given user as
  revoked without saving; caller calls `Complete()` to persist (unit-of-work pattern).
- **`JwtExtensions.AddN2TokenService()`** — DI registration helper that registers `N2TokenService`
  and ensures `IMemoryCache` is available.
- **`docs/authentication-flow.md`** — Mermaid sequence diagrams documenting the standard login,
  MFA login, token refresh, and logoff flows.
- **Migration `20260414130218_AddSecurityTokens`** — adds the `SecurityStamp` column to the
  `ApplicationRefreshToken` table (nullable; non-breaking for existing rows).
- **`UsingN2TokenService`** — 34 unit tests covering happy paths, invalid inputs, security stamp
  mismatch, grace period behaviour, and misuse scenarios.

### Fixed

- `JwtTimingTests.GenerateToken_ShouldIncludeStandardClaims` and
  `GenerateToken_CrossTimezone_ShouldBeConsistent` were passing `60` as `timeoutInMinutes`,
  which now violates the 15-minute cap introduced in the previous commit. Updated to `5`.

---

## 1.6.5 — 2026-03-11

### Fixed

- `WebTokenGenerator` was encoding the JWT signing key using `Encoding.UTF8.GetBytes` instead of
  `Convert.FromBase64String`, producing a 44-byte key that never matched the 32-byte key used by
  `AddJwtBearerAuthentication` for validation. Every token generated by the library failed
  validation. Both constructors now use `Convert.FromBase64String`.
- **Breaking:** Consumers passing a plain (non-Base64) string as the JWT secret will receive an exception.
  The documented contract already required a Base64-encoded key; this aligns the implementation.
