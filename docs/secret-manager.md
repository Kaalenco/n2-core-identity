# ISecretManager — Developer Guide

`ISecretManager` manages the full lifecycle of `ApplicationSecret` records. Secrets can be owned by any entity that implements `IHaveSecrets` — currently `ApplicationUser`, `ApplicationDefinition` (applications), and `ApplicationTenant` (tenants).

---

## Core concepts

### Token vs. secret value

These are two independent things that are easy to confuse.

| Concept | What it is | Stored as |
|---|---|---|
| **Token** (`PlainToken`) | A fixed-length authentication credential the caller presents | HMAC-SHA256 hash in `ApplicationSecret.HashedToken` |
| **Secret value** | An arbitrary encrypted payload (e.g. an API key, credential, or config blob) | AES-256-GCM ciphertext in `ApplicationSecret.Secret` |

The token's length and content tell an observer **nothing** about the secret value. The two are derived and stored independently.

### Token format

```
{base64url(ownerId)}.{ownerTypeCode}.{base64url(randomBytes)}
```

- `ownerId` — the owner's `Guid`, base64url-encoded. **This segment is not encrypted.** See [Security considerations](#security-considerations).
- `ownerTypeCode` — an 8-character opaque code derived from `SHA-256(typeName)[0..5]`. Does not reveal the owner type name.
- `randomBytes` — cryptographically random bytes (minimum 32). The sole source of entropy for the token.

The full token string is **never stored**. On create, it is HMAC-SHA256 signed (using `TokenSigningSecret`) and only the MAC is persisted in `HashedToken`. On validate, the incoming token is signed the same way and looked up by MAC.

### Encryption of the secret value

The secret value is encrypted with AES-256-GCM. The encryption key is derived via HKDF from:

| HKDF input | Source |
|---|---|
| IKM | System secret from `AuthenticationConfig:TokenSigningSecret` configuration |
| Salt | Per-record random bytes in `ApplicationSecret.EncryptionSalt` |
| Info | `owner.SecretKeyMaterial` concatenated with `HashedToken` |

This means decryption requires **three independent inputs**: the system config, the owner's key material from the database, and the stored HMAC. A database dump alone is not sufficient to recover plaintext secret values.

---

## Setup

### 1. Configuration

Ensure the `AuthenticationConfig` section is present in your application settings:

```json
{
  "AuthenticationConfig": {
    "TokenSigningSecret": "<base64-encoded 32+ byte key>"
  }
}
```

The repository includes helper scripts for generating all required keys in one step:

- **`scripts/Generate-Secrets.ps1`** (PowerShell) — suitable for Windows and cross-platform PowerShell.
- **`scripts/generate_token_secret.py`** (Python) — lightweight alternative using the Python standard library.

Or generate a single key manually:
```csharp
Console.WriteLine(Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)));
```

Store keys in a secrets manager (Azure Key Vault, AWS Secrets Manager, or .NET User Secrets during development) — never commit them to source control.

### 2. Register services

Register `ISecretManager` in your DI container alongside the identity services:

```csharp
services.AddScoped<ISecretManager, YourSecretManagerImplementation>();
```

`IHaveSecrets` is already implemented by `N2UserManager`, `N2ApplicationManager`, and `N2TenantManager`. Inject these as normal.

### 3. Provision key material for owners

Before any secret can be created for an owner, the owner's `SecretKeyMaterial` column must be populated with 32 cryptographically random bytes. This is separate from `MfaSecret` so that rotating the MFA secret does not invalidate existing application secrets.

```csharp
// When creating or onboarding an owner entity, generate key material:
entity.SecretKeyMaterial = RandomNumberGenerator.GetBytes(32);
```

---

## Usage

### Creating a secret

Obtain the owner via `IHaveSecrets.GetSecretOwner`, then call `CreateAsync`. The returned `PlainToken` is shown **once** — it cannot be recovered after this point.

```csharp
// 1. Resolve the owner (e.g. an application)
var owner = await applicationManager.GetSecretOwner(applicationId, ct);
if (owner == null) return NotFound();

// 2. Create the secret
var request = new CreateSecretDto {
    Name = "Production API Key",
    Expiration = DateTime.UtcNow.AddYears(1),
    Description = "Used by the payment service"
};

var result = await secretManager.CreateAsync(owner, request, ct);
if (!result.Status.IsSuccess()) return Problem(result.Message);

// 3. Return the plain token to the caller — this is the only time it is available
var token = result.Value!.PlainToken;  // store securely; cannot be recovered
```

> **Important:** store `PlainToken` in a secrets vault or hand it directly to the caller. It is never retrievable again.

### Validating a token (authenticating a request)

`ValidateAsync` takes only the raw token string. The owner identity is parsed from the token itself — no caller-supplied context is needed or accepted.

```csharp
// Token arrives in e.g. an Authorization: Bearer header
var validation = await secretManager.ValidateAsync(incomingToken, ct);

if (!validation.Status.IsSuccess()) {
    // Both unknown tokens and ownership mismatches return a generic failure
    // to avoid leaking whether a token exists at all.
    return Unauthorized();
}

var secretDto = validation.Value!;
// secretDto.Id, secretDto.Name, secretDto.Expiration are available
```

> **Rate limiting is the caller's responsibility.** The implementation does not enforce per-IP or per-owner throttling. Apply back-off or lockout before calling `ValidateAsync` when you detect repeated failures.

### Revoking a secret

```csharp
var owner = await applicationManager.GetSecretOwner(applicationId, ct);
var response = await secretManager.RevokeAsync(owner!, secretId, ct);
// ResponseStatus.NotFound if the secret does not exist or belongs to a different owner
```

### Listing secrets

```csharp
var owner = await tenantManager.GetSecretOwner(tenantId, ct);
var selectList = await secretManager.GetSelectListAsync(owner!, ct);
// Returns active (non-expired, named) secrets only
```

### Looking up a single secret

```csharp
var secret = await secretManager.FindByIdAsync(owner, secretId, ct);
// Returns null if not found or not owned by owner
```

---

## Policy management

A secret can carry an arbitrary typed policy payload serialised as JSON. Policies are scoped to an owner — you cannot read or write a policy for a secret that does not belong to the supplied owner.

```csharp
// Define a policy type
public record ApiKeyPolicy(string[] AllowedScopes, string[] AllowedIpRanges);

// Write
await secretManager.SetPolicyAsync(owner, secretId, new ApiKeyPolicy(
    AllowedScopes: ["payments:read", "payments:write"],
    AllowedIpRanges: ["10.0.0.0/8"]
), ct);

// Read
var policy = await secretManager.GetPolicyAsync<ApiKeyPolicy>(owner, secretId, ct);
if (policy != null) {
    // enforce policy.AllowedScopes, policy.AllowedIpRanges, etc.
}
```

> Policies are stored as plaintext JSON in `ApplicationSecret.Policies`. If the policy contains sensitive data, encrypt it within the policy object itself before passing it to `SetPolicyAsync`.

---

## Security considerations

### Token handling

- **Never log tokens.** The `ownerId` is embedded in plaintext inside the token. Logging a token exposes the owner's identity.
- **Never include tokens in URLs.** Tokens in query strings appear in server logs, browser history, and HTTP Referer headers.
- **Treat tokens like passwords.** Pass them over TLS only, store them in a secrets vault, and rotate them on suspected compromise.

### Key material lifecycle

- `SecretKeyMaterial` should be generated once at owner creation and never changed. Changing it does not automatically re-derive old encryption keys, which would make previously created secrets undecryptable.
- `MfaSecret` and `SecretKeyMaterial` are independent. Rotating MFA configuration does not affect existing secrets.

### Database compromise

A read-only database dump cannot recover secret values because decryption also requires:
- The `TokenSigningSecret` from application configuration.
- The owner's `SecretKeyMaterial` from the database row (binding the ciphertext to that specific owner record).

An attacker with access to both the database and the application configuration could reconstruct keys. Secrets stored in `ApplicationSecret.Secret` are therefore only as safe as the combination of your database and your configuration store.

### Token expiry

Always set an `Expiration` on secrets used for long-running service-to-service authentication. Tokens without expiry are valid indefinitely and should only be used when an explicit revocation workflow is in place.

---

## Error responses

| Scenario | `ResponseStatus` returned |
|---|---|
| Secret created successfully | `Success` |
| Token not found or expired | `NotFound` |
| Token found but ownership mismatch | `NotFound` (indistinguishable from above by design) |
| Secret ID not found or wrong owner on revoke/lookup | `NotFound` |
| Validation succeeded | `Success` |

Both `NotFound` and ownership mismatch map to the same response code in `ValidateAsync` to prevent callers from inferring whether a token exists.
