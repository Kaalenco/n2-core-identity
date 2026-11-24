# Migrating to N2.Core.Identity 3.0.1

This guide is for developers upgrading from N2.Core.Identity 2.0.1 to 3.0.1. The full list of
changes is in [CHANGELOG.md](CHANGELOG.md).

3.0.1 is a major version because all N2 packages are unified on 3.0.1 and because the package
depends on N2.Core.Abstractions 3.0.0 (token format v2). N2.Core.Identity itself has no public API
changes: no member was renamed, removed or re-signed, and no database migration is added.

## 1. Summary

- Version 3.0.1 (`AssemblyVersion` 3.0.0.0). Consumers that pin the assembly version must
  rebind from 2.0.1.
- Target frameworks stay `net10.0` and `net11.0`. `netstandard2.0` is not offered: ASP.NET Core
  Identity and EF Core do not support it.
- Dependencies per target framework:

| Package | net10.0 | net11.0 |
|---|---|---|
| Microsoft.AspNetCore.*, Microsoft.EntityFrameworkCore.*, UserSecrets | 10.0.15 | 11.0.0 (was 10.0.15) |
| N2.Core.Abstractions | 3.0.0 (was 2.0.0) | 3.0.0 (was 2.0.0) |
| QRCoder | 1.9.0 (was 1.8.1) | 1.9.0 (was 1.8.1) |

## 2. Breaking changes from N2.Core.Abstractions 3.0.0

These are in the Abstractions package, not in Identity. They affect you only if your application
uses the Abstractions types next to Identity.

- `AuthenticatedValue` token format v2: header `[version=2][key id]`, HKDF-SHA256 key derivation.
  All v1 tokens are rejected (hard cutover). Re-issue every token after upgrading.
- `purpose` is mandatory on `ToTokenString`, `FromTokenString`, `ToAuthenticatedValue` and
  `FromAuthenticatedValue`. A token only verifies for the purpose it was created with.
- `FromTokenString` and `TryFromTokenString` take `IReadOnlyList<byte[]>` for key rotation; the
  key id is the index into the list (append, never reorder). Use `TryFromTokenString` on request
  paths; it never throws on bad input.
- Secrets with fewer than 8 distinct bytes (for example all zero) are rejected.
- `Token.Deserialize` has size and depth limits; `Token.ToString()` is redacted (use
  `Token.Redacted()`); `ExpiresIn` is an absolute timestamp.

N2.Core.Identity itself does not call `AuthenticatedValue`. Its own refresh and confirmation
tokens are unchanged, so existing Identity tokens and stored data stay valid.

## 3. Checklist

1. Update the package reference to `N2.Core.Identity` 3.0.1 (feed `vault-packages`; `N2.*` must map
   to that feed in your `nuget.config`).
2. On net11.0, expect EF Core 11 and ASP.NET Core 11 to come in transitively. Review the
   Microsoft breaking-change notes for EF Core 11 if you ship your own migrations.
3. Re-issue any tokens created through `N2.Core.Abstractions` `AuthenticatedValue` and add a
   purpose to each call site.
4. If you pin `Microsoft.EntityFrameworkCore.*` yourself, keep it on the same major band as
   your target framework (10.x on net10.0, 11.x on net11.0) to avoid NU1605 downgrades.
5. Rebuild; no source changes are required for Identity members.
