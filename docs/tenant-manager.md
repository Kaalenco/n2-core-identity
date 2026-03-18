# ITenantManager — Developer Guide

`ITenantManager` is the interface for managing tenants. The concrete implementation is `N2TenantManager`, which lives in the `N2.Core.Identity.Services` namespace.

`N2TenantManager` manages the lifecycle of `ApplicationTenant` records and user–tenant membership. It also implements `IHaveSecrets`, meaning each tenant can own `ApplicationSecret` records via `ISecretManager`.

---

## Security model

### No rate limiting on tenant operations

`N2TenantManager` does not apply rate limiting. Tenant management is an administrative operation and is expected to be called from privileged back-end code, not from user-facing endpoints. Protect all tenant management operations at the API layer (e.g. require an admin role or a service-to-service token).

### Configuration key validation at startup

The constructor validates `TokenSigningSecret` at startup and throws `InvalidOperationException` if it is absent or shorter than 32 bytes (256 bits). This is a fail-fast check — misconfigured instances will not start.

### Information hiding on cross-tenant operations

When a tenant does not exist, operations return `ResponseStatus.NotFound`. This response is identical to what would be returned for a valid but locked or removed tenant, so the caller cannot distinguish between "does not exist" and "access denied" by observing response codes.

### Name and email normalisation

All name and email lookups normalise the supplied value with `.Trim().ToUpperInvariant()` before comparing. This prevents case-manipulation bypasses on name uniqueness checks.

### Idempotent membership operations

Adding a user who is already assigned or removing a user who is not a member both return success. This prevents information leakage through 409/404 error codes on membership endpoints.

---

## Setup

### Register the service

```csharp
services.AddScoped<ITenantManager, N2TenantManager>(sp =>
    new N2TenantManager(
        sp.GetRequiredService<IIdentityContextFactory>(),
        sp.GetRequiredService<IConfiguration>(),
        connectionName: "IdentityDb",
        sp.GetRequiredService<ILogger<N2TenantManager>>()
    ));
```

### Required configuration

```json
{
  "AuthenticationConfig": {
    "TokenSigningSecret": "<base64-encoded 32+ byte key>"
  }
}
```

See [Generating secrets](#generating-secrets) for tools that help produce these keys.

---

## Usage

### Creating a tenant

```csharp
var tenant = new ApplicationTenant {
    Id = Guid.NewGuid(),
    Name = "Acme Corp",
    AdminEmail = "admin@acme.com",
    UserLimit = 100
};
var result = await tenantManager.CreateAsync(tenant, ct);
// ResponseStatus.NotAcceptable if a tenant with the same normalised name already exists
```

### Updating a tenant

Only mutable properties are applied: `Name`, `Address`, `AdminEmail`, `ContactInfo`, `ImagePath`, `UserLimit`, `IsHidden`, and `MfaSecret`. The entity must carry a valid non-empty `Id` and `Name`.

```csharp
existing.Address = "123 Main St";
existing.UserLimit = 200;
var result = await tenantManager.UpdateAsync(existing, ct);
```

### Deleting a tenant

```csharp
var result = await tenantManager.DeleteAsync(tenant, ct);
// ResponseStatus.NotFound if the tenant does not exist
```

> Deleting a tenant removes all user–tenant associations. This operation is not reversible.

---

## Lookup

```csharp
// By ID
var tenant = await tenantManager.FindByIdAsync(tenantId, ct);

// By name (normalised internally — Trim().ToUpperInvariant())
var tenant = await tenantManager.FindByNameAsync("Acme Corp", ct);

// By admin email (normalised internally)
var tenant = await tenantManager.FindByEmailAsync("admin@acme.com", ct);

// Select list for UI (excludes removed and hidden tenants)
SelectItemList<UserSelectItem> list = await tenantManager.GetTenantsAsync(ct);
```

All `FindBy*` methods return `null` when nothing is found — they never throw for missing records.

---

## Locking and unlocking

Locking a tenant prevents **all users belonging to it** from signing in, even if those users are active in other tenants.

```csharp
var lockResult = await tenantManager.LockAsync(tenant, ct);
var unlockResult = await tenantManager.UnlockAsync(tenant, ct);
// Both return NotFound if the tenant does not exist
```

---

## User–tenant membership

### Assign a user to a tenant

```csharp
var result = await tenantManager.AddUserAsync(user, tenant, ct);
// Idempotent: Success if the user is already assigned
// NotFound if either the user or the tenant does not exist
```

### Remove a user from a tenant

```csharp
var result = await tenantManager.RemoveUserAsync(user, tenant, ct);
// Idempotent: Success if the user was not assigned
```

### Query membership

```csharp
// All normalised usernames belonging to a tenant
IEnumerable<string> userNames = await tenantManager.GetUsersForTenantAsync(tenantId, ct);

// All tenant IDs a user belongs to
IEnumerable<Guid> tenantIds = await tenantManager.GetTenantIdsForUserAsync(userId, ct);
```

### Sign-in eligibility check

Use this before issuing a token to ensure neither the user nor the tenant is locked:

```csharp
bool canSignIn = await tenantManager.ApplicationUserCanSignIn(userId, tenantId, ct);
// Returns false if:
// — the user does not exist or is locked out
// — the user is not a member of the tenant
// — the tenant is locked
```

---

## Secrets (IHaveSecrets)

Each tenant can own `ApplicationSecret` records. See [secret-manager.md](secret-manager.md) for the full guide.

Before creating secrets, the tenant's `SecretKeyMaterial` column must be provisioned with 32 cryptographically random bytes. This is independent of `MfaSecret` — rotating the MFA secret does not affect existing application secrets:

```csharp
existing.SecretKeyMaterial = RandomNumberGenerator.GetBytes(32);
await tenantManager.UpdateAsync(existing, ct);
```

Then resolve the owner and use `ISecretManager`:

```csharp
var owner = await tenantManager.GetSecretOwner(tenantId, ct);
// null if the tenant does not exist
// throws InvalidOperationException if SecretKeyMaterial is not set

var result = await secretManager.CreateAsync(owner!, new CreateSecretDto {
    Name = "Integration Webhook Key",
    Expiration = DateTime.UtcNow.AddYears(1)
}, ct);
```

---

## Generating secrets

The repository contains helper scripts for generating the cryptographic keys required by the configuration:

- **`scripts/Generate-Secrets.ps1`** (PowerShell) — generates and prints all required keys in one step, suitable for Windows and cross-platform PowerShell.
- **`scripts/generate_token_secret.py`** (Python) — lightweight alternative using the Python standard library.

Run either script locally and store the output in your secrets manager (Azure Key Vault, AWS Secrets Manager, or .NET User Secrets during development). Never commit generated keys to source control.

---

## Error responses

| Scenario | `ResponseStatus` |
|---|---|
| Tenant created | `Success` |
| Tenant name already exists | `NotAcceptable` |
| Tenant not found (update/delete/lock) | `NotFound` |
| User not found (AddUser/RemoveUser) | `NotFound` |
| User already assigned to tenant | `Success` (idempotent) |
| User not a member on remove | `Success` (idempotent) |
