# n2-core-identity

[![.NET Build and test](https://github.com/Kaalenco/n2-core-identity/actions/workflows/dotnet.yml/badge.svg)](https://github.com/Kaalenco/n2-core-identity/actions/workflows/dotnet.yml)
[![CodeQL Advanced](https://github.com/Kaalenco/n2-core-identity/actions/workflows/codeql.yml/badge.svg)](https://github.com/Kaalenco/n2-core-identity/actions/workflows/codeql.yml)
[![NuGet](https://img.shields.io/nuget/v/N2.Core.Identity.svg)](https://www.nuget.org/packages/N2.Core.Identity/)

**N2.Core.Identity** is a modular, extensible identity and role management library for .NET, built on top of ASP.NET Core Identity. It provides a strongly-typed database context, a feature-rich user manager, JWT authentication, and multi-factor authentication support — all wired together for production use.

Targets **net8.0** and **net10.0**. Supports SQL Server and MySQL.

---

## Functional Blocks

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

## Security Notes

- Passwords hashed with PBKDF2-HMAC-SHA256, 310,000 iterations (OWASP 2023 recommendation)
- Confirmation tokens signed with HMAC-SHA256; nonces use cryptographically secure random bytes
- Constant-time comparisons used for token and MFA validation to prevent timing-based enumeration
- Account lockout and rate limiting built in

---

## License

AFL-3.0
