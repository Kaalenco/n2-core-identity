# IApplicationManager — Developer Guide

`IApplicationManager` is the interface for managing applications. The concrete implementation is `N2ApplicationManager`, which lives in the `N2.Core.Identity.Services` namespace.

`N2ApplicationManager` manages the lifecycle of `ApplicationDefinition` records — named applications registered under a tenant. All operations are scoped to a `tenantId`. The interface also implements `IHaveSecrets`, meaning each application can own `ApplicationSecret` records via `ISecretManager`, which makes it the primary owner type for issuing API keys and long-lived service credentials.

---

## Security model

### No rate limiting on application operations

`N2ApplicationManager` does not apply rate limiting. Application management is an administrative operation, expected to be called from privileged back-end code, not user-facing endpoints. Protect all application management operations at the API layer (e.g. require an admin role or a service-to-service token).

### Configuration key validation at startup

The constructor validates `TokenSigningSecret` at startup and throws `InvalidOperationException` if it is absent or shorter than 32 bytes (256 bits). This is a fail-fast check — misconfigured instances will not start.

### Tenant scoping as a security boundary

Every method that addresses an existing application requires both `tenantId` and the application reference. If the application exists but belongs to a different tenant, the operation returns `ResponseStatus.NotFound` — identical to the response for a non-existent application. This prevents cross-tenant information leakage: callers cannot determine whether an application ID belongs to a different tenant or does not exist at all.

### Name normalisation

Application names are normalised with `.Trim().ToUpperInvariant()` before uniqueness checks. This prevents case-manipulation bypasses when creating applications with duplicate names.

---

## Setup

### Register the service

```csharp
services.AddScoped<IApplicationManager, N2ApplicationManager>(sp =>
    new N2ApplicationManager(
        sp.GetRequiredService<IIdentityContextFactory>(),
        sp.GetRequiredService<IConfiguration>(),
        connectionName: "IdentityDb",
        sp.GetRequiredService<ILogger<N2ApplicationManager>>()
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

### Creating an application

```csharp
var app = new ApplicationDefinition {
    Id = Guid.NewGuid(),
    Name = "Payment Service"
};
var result = await applicationManager.CreateAsync(tenantId, app, ct);
// NotFound if the tenant does not exist
// NotAcceptable if an application with the same name already exists in the tenant
```

### Updating an application

Only `Name` and `MfaSecret` are written back. The application must have a valid `Id` and `Name`, and must belong to the supplied `tenantId`.

```csharp
app.Name = "Payment Gateway";
var result = await applicationManager.UpdateAsync(tenantId, app, ct);
// NotFound if not found or if the application belongs to a different tenant
```

### Deleting an application

```csharp
var result = await applicationManager.DeleteAsync(tenantId, app, ct);
// NotFound if not found or if the application belongs to a different tenant
```

---

## Lookup

```csharp
// By ID within a tenant
var app = await applicationManager.FindByIdAsync(tenantId, applicationId, ct);
// null if not found or if it belongs to a different tenant

// By name within a tenant (normalised internally — Trim().ToUpperInvariant())
var app = await applicationManager.FindByNameAsync(tenantId, "Payment Service", ct);

// Select list for UI — all applications belonging to a tenant
SelectItemList<HtmlString> list = await applicationManager.GetApplicationGetSelectList(tenantId, ct);
// Locked applications are included in the list with a "(Locked)" suffix
```

---

## Locking and unlocking

Locking an application prevents it from being used without removing it from the system. An application's lock state is independent of its owning tenant's lock state.

```csharp
var lockResult = await applicationManager.LockAsync(tenantId, app, ct);
var unlockResult = await applicationManager.UnlockAsync(tenantId, app, ct);
// Both return NotFound if not found or if the application belongs to a different tenant
```

---

## Secrets (IHaveSecrets)

Issuing API keys and long-lived service credentials is the primary use case for `IApplicationManager`. Each application can own `ApplicationSecret` records. See [secret-manager.md](secret-manager.md) for the full guide.

Before creating secrets, the application's `SecretKeyMaterial` column must be provisioned with 32 cryptographically random bytes. This is separate from `MfaSecret` — rotating the MFA secret does not invalidate existing secrets:

```csharp
app.SecretKeyMaterial = RandomNumberGenerator.GetBytes(32);
await applicationManager.UpdateAsync(tenantId, app, ct);
```

Then resolve the owner and use `ISecretManager`:

```csharp
var owner = await applicationManager.GetSecretOwner(applicationId, ct);
// null if the application does not exist
// throws InvalidOperationException if SecretKeyMaterial is not set
```

> `GetSecretOwner` does not enforce tenant scoping. Only call it with an `applicationId` that belongs to the tenant you are operating under.

### End-to-end: issuing an API key for a service

```csharp
// 1. Look up the application
var app = await applicationManager.FindByNameAsync(tenantId, "Payment Service", ct)
    ?? throw new InvalidOperationException("Application not found");

// 2. Provision key material on first use (one-time setup)
if (app.SecretKeyMaterial == null) {
    app.SecretKeyMaterial = RandomNumberGenerator.GetBytes(32);
    await applicationManager.UpdateAsync(tenantId, app, ct);
}

// 3. Create a named secret with an expiry
var owner = await applicationManager.GetSecretOwner(app.Id, ct);
var created = await secretManager.CreateAsync(owner!, new CreateSecretDto {
    Name = "CI/CD Deploy Key",
    Expiration = DateTime.UtcNow.AddYears(1),
    Description = "Used by the deployment pipeline"
}, ct);

// 4. Hand the plain token to the service — it cannot be retrieved again
var token = created.Value!.PlainToken;
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
| Application created | `Success` |
| Tenant not found on create | `NotFound` |
| Application name already exists in tenant | `NotAcceptable` |
| Application not found or wrong tenant | `NotFound` |
