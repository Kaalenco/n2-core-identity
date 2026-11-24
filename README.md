# N2.Core.Identity

[![Build Status](https://dev.azure.com/gjkaal/N2%20Vault%20services/_apis/build/status%2FN2.Core.Identity%20-%20Publish?branchName=trunk)](https://dev.azure.com/gjkaal/N2%20Vault%20services/_build/latest?definitionId=5&branchName=trunk)

**N2.Core.Identity** is a modular, extensible identity and role management library for .NET, built on top of ASP.NET Core Identity. It provides a strongly-typed database context, a feature-rich user manager, JWT authentication, and multi-factor authentication support — all wired together for production use.

Targets **net10.0** and **net11.0**. Supports SQL Server. MySQL support was removed in 2.0.0 (no stable EF Core 10 MySQL provider yet); it is planned as a separate package, N2.Core.Identity.MySql.

---

## Functional areas

### Identity Context (`N2IdentityContext`)
Extends `IdentityDbContext<ApplicationUser, ApplicationRole, Guid>`. Provides strongly-typed access to users, roles, and user-role mappings. Includes a concurrent change log (capped at 1000 entries) and a built-in health check for database connectivity.

### User Manager (`N2UserManager`)
The core service for all user lifecycle operations. Implements `IUserManager<ApplicationUser>` with thread-safe, lazy-initialized context access via a factory pattern. Key capabilities:
- Create, update, and delete users
- Password hashing with PBKDF2-HMAC-SHA256 (310,000 iterations, OWASP 2023)
- Role assignment and removal
- User lookup by name, email, or ID
- Account lockout tracking (increment / reset failed access counts)
- Rate limiting on authentication attempts

### Email Confirmation and Token Management
Custom HMAC-SHA256 signed tokens with 5-day expiry. Token format: `{base64(nonce:expiry)}.{base64(signature)}`. Signing key is sourced from configuration (`TokenSigningSecret`). Constant-time validation guards against timing attacks.

### Authentication Service (`N2AuthenticationService`)
Implements `IAuthenticator`. Validates user credentials, checks lockout status, retrieves roles, and returns an `IUserContext` containing user details and role claims.

### JWT Token Generation (`WebTokenGenerator`)
Generates signed JWT bearer tokens with configurable timeout (5–1440 minutes; 14400 in debug mode). Encodes user ID and roles as claims.

### Multi-Factor Authentication
Supports SMS, email, and TOTP-based MFA via [Otp.NET](https://github.com/kspearrin/Otp.NET). QR code generation for authenticator app enrollment via [QRCoder](https://github.com/codebude/QRCoder). MFA validation uses constant-time comparison to prevent timing attacks.

### Database Context Factory
Uses `IIdentityContextFactory` to decouple context creation from connection string management, enabling multi-tenancy and flexible deployment scenarios.

### SQL Migration Scripts
Incremental SQL scripts (`Scripts/M00`, `M01`, `M02`) are included in the output directory alongside EF Core migrations for full schema lifecycle support.

---

## Security notes

- Passwords hashed with PBKDF2-HMAC-SHA256, 310,000 iterations (OWASP 2023 recommendation)
- Confirmation tokens signed with HMAC-SHA256; nonces use cryptographically secure random bytes
- Constant-time comparisons used for token and MFA validation to prevent timing-based enumeration
- Account lockout and rate limiting built in

---

## Project documentation

| Document | Description |
|----------|-------------|
| [src/DEVELOPER-GUIDE.md](src/DEVELOPER-GUIDE.md) | Developer guide — build commands, CI/CD pipeline, and maintenance notes. |
| [src/WARNINGS.md](src/WARNINGS.md) | Suppressed analyser warnings — lists every `<NoWarn>` entry with severity rating and guidance. |
| [CHANGELOG.md](CHANGELOG.md) | Full version history. |
| [MIGRATION-2.0.md](MIGRATION-2.0.md) | Code migration guide from 1.x (1.7.5) to 2.0.0. |
| [MIGRATION-3.0.md](MIGRATION-3.0.md) | Migration notes from 2.0.1 to 3.0.1. |

## Upgrading to 3.0

3.0.1 is a major version bump that unifies all N2 packages. N2.Core.Identity has no API changes, but it depends on N2.Core.Abstractions 3.0.0 (token format v2, mandatory purpose) and uses EF Core 11 on net11.0. See [MIGRATION-3.0.md](MIGRATION-3.0.md).

## Upgrading to 2.0

2.0.0 is a breaking release: it targets net10.0 and net11.0, moves to N2.Core.Abstractions 2.0.0 and EF Core 10, renames every `...Async` member and makes the `CancellationToken` required, and removes MySQL support (MySQL users stay on 1.7.5). See [MIGRATION-2.0.md](MIGRATION-2.0.md) for the step-by-step checklist, the old -> new member tables and the behaviour changes.

## Change log

See [CHANGELOG.md](CHANGELOG.md) for the full history. Current version: **3.0.1**.

---

## License

AFL-3.0
