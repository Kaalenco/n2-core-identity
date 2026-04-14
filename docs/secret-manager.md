# ISecretManager — Developer Guide

`ISecretManager` manages the full lifecycle of `ApplicationSecret` records. Secrets can be owned by any entity that implements `IHaveSecrets` — currently `ApplicationUser`, `ApplicationDefinition` (applications), and `ApplicationTenant` (tenants).

---

## Core concepts

### Token vs. secret value

These are two independent things that are easy to confuse.

| Concept | What it is | Stored as |
|---|---|---|
| **Token** (`PlainToken`) | A fixed-length authentication credential the caller presents | HMAC-SHA256 hash in `ApplicationSecret.HashedToken` |
| **Secret value** (`Payload`) | An arbitrary encrypted payload (e.g. a connection string, API credential, or base secret) | AES-256-GCM ciphertext in `ApplicationSecret.Secret` |

The token's length and content tell an observer **nothing** about the secret payload. The two are derived and stored independently. A secret may have a payload, a token only, or both — depending on your use case.

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
| IKM | System secret from `AuthenticationConfig:SecretEncryptionKey` configuration |
| Salt | Per-record random bytes in `ApplicationSecret.EncryptionSalt` (refreshed on every `SetValueAsync` call) |
| Info | `owner.SecretKeyMaterial` concatenated with `HashedToken` |

This means decryption requires **three independent inputs**: the system config, the owner's key material from the database, and the stored HMAC. A database dump alone is not sufficient to recover plaintext secret values.

---

## Setup

### 1. Configuration

Ensure the `AuthenticationConfig` section is present in your application settings:

```json
{
  "AuthenticationConfig": {
    "TokenSigningSecret": "<base64-encoded 32+ byte key>",
    "SecretEncryptionKey": "<base64-encoded 32+ byte key>"
  }
}
```

Use two distinct keys — one for HMAC token signing, one for AES value encryption. The repository includes helper scripts for generating all required keys in one step:

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
var owner = await applicationManager.GetSecretOwner(applicationId, ct);
if (owner == null) return NotFound();

var request = new CreateSecretDto {
    Name = "Production API Key",
    Expiration = DateTime.UtcNow.AddYears(1),
    Description = "Used by the payment service"
};

var result = await secretManager.CreateAsync(owner, request, ct);
if (!result.Status.IsSuccess()) return Problem(result.Message);

// Return the plain token to the caller — this is the only time it is available
var token = result.Value!.PlainToken;
```

To store an encrypted payload at creation time, supply a `Value`:

```csharp
var request = new CreateSecretDto {
    Name = "Database connection",
    Description = "Primary SQL Server connection string",
    Value = "Server=prod-db;Database=myapp;User Id=svc;Password=..."  // CreateSecretDto.Value (input)
};

var result = await secretManager.CreateAsync(owner, request, ct);
// result.Value!.PlainToken is the token to store and present on future reads
```

> **Important:** store `PlainToken` in a secrets vault or hand it directly to the caller. It is never retrievable again.

### Storing or updating a secret value

Use `SetValueAsync` to set or replace the encrypted value of an existing secret. The plain token is the sole credential — no owner context is required.

```csharp
var setResult = await secretManager.SetValueAsync(plainToken, newValue, ct);
if (!setResult.Status.IsSuccess()) {
    // Token unknown, expired, or tampered — do not distinguish to the caller
    return Unauthorized();
}
```

Every call re-encrypts with a **fresh random salt**, so repeated calls with the same value produce distinct ciphertexts. Pass `null` to clear a stored value without revoking the token:

```csharp
// Clear the value while keeping the token valid
await secretManager.SetValueAsync(plainToken, null, ct);
```

### Validating a token and retrieving the secret value

`ValidateAsync` authenticates the token and returns the decrypted value in a single step. No owner context is needed — the owner identity is parsed from the token itself.

```csharp
// Token arrives in e.g. an Authorization: Bearer header
var validation = await secretManager.ValidateAsync(incomingToken, ct);

if (!validation.Status.IsSuccess()) {
    // Both unknown tokens and ownership mismatches return a generic failure
    // to avoid leaking whether a token exists at all.
    return Unauthorized();
}

var secretDto = validation.Value!;
// secretDto.Id, Name, Expiration, Description — always populated on success
// secretDto.Payload — decrypted payload, or null if none was stored
var connectionString = secretDto.Payload;
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
// Note: Payload is NOT populated here — use ValidateAsync to retrieve the decrypted payload
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

## Common usage patterns

### Pattern 1 — Token-only API key

The simplest use case: the token itself is the credential. No value is stored. Typically used for service-to-service authentication where you only need to verify "does this caller hold a valid key."

```csharp
// Provisioning
var result = await secretManager.CreateAsync(owner, new CreateSecretDto {
    Name = "Webhook receiver key",
    Expiration = DateTime.UtcNow.AddYears(1)
}, ct);
var apiKey = result.Value!.PlainToken; // hand to the caller once

// Verification (on each incoming request)
var validation = await secretManager.ValidateAsync(incomingApiKey, ct);
if (!validation.Status.IsSuccess()) return Unauthorized();
// No value to read — the successful response is sufficient proof
```

Combine with `GetPolicyAsync` to attach scopes or rate-limit tiers to the key without embedding them in the token.

### Pattern 2 — Encrypted credential store

Use the secret manager as a lightweight vault: store a connection string, third-party API secret, or signing key as the `Value`, and use the token as the retrieval credential. Suitable when the stored value must be rotatable independently of the identity that retrieves it.

```csharp
// Provisioning — store the connection string encrypted
var result = await secretManager.CreateAsync(owner, new CreateSecretDto {
    Name = "Primary DB",
    Description = "Connection string for the reporting database",
    Value = configuration["ConnectionStrings:ReportingDb"]
}, ct);
var retrievalToken = result.Value!.PlainToken;
// Store retrievalToken in the consuming service's config (not the connection string itself)

// At runtime — retrieve and use
var validation = await secretManager.ValidateAsync(retrievalToken, ct);
if (!validation.Status.IsSuccess()) throw new InvalidOperationException("Credential unavailable.");
var connectionString = validation.Value!.Payload!;
```

### Pattern 3 — Value rotation without token rotation

Rotate the stored value (e.g. after a database password change) without invalidating the token already distributed to callers.

```csharp
// Find the token to rotate (stored in your config or key vault)
var existingToken = configuration["Services:ReportingDb:Token"];

// Replace the stored value — fresh salt applied automatically
var setResult = await secretManager.SetValueAsync(existingToken, newConnectionString, ct);
if (!setResult.Status.IsSuccess()) {
    logger.LogError("Credential rotation failed — token may be expired or revoked.");
    return;
}
// Callers holding the existing token will now retrieve the new value on next ValidateAsync
```

This separates **credential identity** (the token) from **credential material** (the value), so you can rotate secrets on a different schedule from tokens.

### Pattern 4 — Full lifecycle with revocation

```csharp
// 1. Create
var created = await secretManager.CreateAsync(owner, new CreateSecretDto {
    Name = "CI deploy key",
    Expiration = DateTime.UtcNow.AddDays(90),
    Value = signingSecret
}, ct);
var token = created.Value!.PlainToken;
var secretId = created.Value.Id;

// 2. Use — validate and read on each request
var validation = await secretManager.ValidateAsync(token, ct);
var currentSecret = validation.Value!.Payload;

// 3. Rotate the value (e.g. scheduled job)
await secretManager.SetValueAsync(token, newSigningSecret, ct);

// 4. Revoke when the key is no longer needed or suspected of compromise
await secretManager.RevokeAsync(owner, secretId, ct);

// After revocation, both ValidateAsync and SetValueAsync return failure
var afterRevoke = await secretManager.ValidateAsync(token, ct);
Assert.IsFalse(afterRevoke.Status.IsSuccess());
```

---

## Best practices

### Token handling

- **Never log tokens.** The `ownerId` is embedded in plaintext inside the token. Logging a token exposes the owner's identity.
- **Never include tokens in URLs.** Tokens in query strings appear in server logs, browser history, and HTTP `Referer` headers. Deliver them in a response body or via a secure out-of-band channel.
- **Treat tokens like passwords.** Transmit over TLS only, store in a secrets vault, and rotate on suspected compromise.

### Choosing between `Payload` and external storage

| Situation | Recommendation |
|---|---|
| The secret is small and changes infrequently (e.g. a connection string, signing key) | Store in `Payload` — rotation via `SetValueAsync` is lightweight |
| The secret is large (e.g. a TLS certificate chain) | Store externally; use the token to gate retrieval from that store |
| The secret must not leave your infrastructure | Store in `Payload` and follow the hardening steps in [Using as a private key vault](#using-as-a-private-key-vault) |
| The secret must stay off third-party cloud infrastructure | Deploy the dedicated vault server — see `vault-server-plan.md` |

### Value rotation cadence

- Rotate the **value** (`SetValueAsync`) on any suspected exposure or as part of a regular schedule.
- Rotate the **token** (revoke and re-create) only when the token itself may be compromised — for example, if it was accidentally logged or sent over an unencrypted channel.
- Prefer rotating values over tokens to avoid coordinating token redistribution across services.

### Expiration policy

- Always set `Expiration` on secrets used for automated service-to-service authentication. Unexpired secrets accumulate and are difficult to audit.
- Use short lifetimes for secrets issued to external parties (webhooks, CI pipelines) and longer lifetimes for internal service credentials where revocation is tightly controlled.
- Build an automated renewal workflow rather than using non-expiring secrets. `GetSelectListAsync` makes it easy to surface secrets nearing expiry in a management UI.

### Rate limiting on validation

`ValidateAsync` does not enforce per-caller throttling. Gate incoming requests with a rate limiter before calling it:

```csharp
// ASP.NET Core example using a fixed-window limiter keyed on the token prefix
app.UseRateLimiter(new RateLimiterOptions().AddFixedWindowLimiter("api-keys", options => {
    options.PermitLimit = 100;
    options.Window = TimeSpan.FromMinutes(1);
}));
```

After a configurable number of consecutive failures for the same token prefix, revoke the secret proactively to limit brute-force exposure.

### Key material lifecycle

- `SecretKeyMaterial` should be generated once at owner creation and **never changed**. Changing it makes all existing ciphertexts for that owner undecryptable.
- `MfaSecret` and `SecretKeyMaterial` are independent. Rotating MFA configuration does not affect existing secrets.

---

## Security considerations

### Database compromise

A read-only database dump cannot recover secret values because decryption also requires:
- The `SecretEncryptionKey` from application configuration.
- The owner's `SecretKeyMaterial` from the database row (binding the ciphertext to that specific owner record).

An attacker with access to both the database and the application configuration could reconstruct keys. Secrets stored in `ApplicationSecret.Secret` are therefore only as safe as the combination of your database and your configuration store. Use separate access controls for each.

### Owner-confusion attacks

`ValidateAsync` and `SetValueAsync` both parse the owner identity from the token itself rather than accepting caller-supplied context. This eliminates the class of attack where a caller presents a valid token from owner A but claims it belongs to owner B.

### Ciphertext freshness

`SetValueAsync` always generates a fresh `EncryptionSalt` before encrypting, even when the value is unchanged. This ensures that two calls with the same plaintext produce distinct ciphertexts, preventing an observer with database read access from detecting whether a value has changed.

---

## Using as a private key vault

This library can serve as a self-hosted alternative to Azure Key Vault, AWS Secrets Manager, or HashiCorp Vault in environments where sending secrets to a third-party cloud service is not acceptable — air-gapped networks, on-premises regulated workloads, or setups where the full data path must remain under your control.

This section describes what the library provides, where it falls short compared to dedicated vaults, and the concrete steps needed to close those gaps in a production deployment.

### What this library provides

| Capability | Status |
|---|---|
| AES-256-GCM encryption with HKDF key derivation | Provided |
| Per-record random salt, refreshed on every update | Provided |
| HMAC-SHA256 token authentication (offline precomputation impossible without the signing key) | Provided |
| Plain token never persisted | Provided |
| Constant-time ownership verification | Provided |
| Owner-confusion attack prevention (owner parsed from token, not supplied by caller) | Provided |
| Ciphertext binding to owner and record (HKDF info includes `SecretKeyMaterial` and `HashedToken`) | Provided |

These properties mean a **database dump alone** is insufficient to recover any secret payload. An attacker needs the database, the `SecretEncryptionKey` from application config, and (per-owner) the `SecretKeyMaterial` rows.

### Risks and gaps compared to dedicated vaults

Understanding these gaps is essential before using this library as your primary secret store.

#### 1. No HSM backing

Azure Key Vault Premium, AWS CloudHSM, and HashiCorp Vault Enterprise can store root keys inside tamper-resistant hardware security modules (HSMs) where the raw key material never leaves the chip — not even to the application process or the operating system. This library stores `SecretEncryptionKey` and `TokenSigningSecret` in application configuration. An attacker with access to the process environment, the config file, or a memory dump of the application process obtains the root keys directly.

**Risk level:** High if your threat model includes server compromise. Low if your threat model is limited to database-only access.

#### 2. No key versioning or rotation with re-encryption

Professional vaults maintain key versions. When a key is rotated, old ciphertexts remain decryptable under the previous key version; new writes use the new key; and a background job can re-encrypt old records at a controlled pace. This library has no key versioning. Rotating `SecretEncryptionKey` immediately makes every existing ciphertext undecryptable. Until re-encryption is implemented at the application level, key rotation is a destructive, all-or-nothing operation.

**Risk level:** Medium. Without a rotation plan, a compromised key cannot safely be replaced without downtime and data migration.

#### 3. No built-in audit log

HashiCorp Vault produces a tamper-evident audit log of every operation — who called what, when, from which address, and whether it succeeded. AWS Secrets Manager writes to CloudTrail; Azure Key Vault writes to Activity Log. This library logs structural events via `ILogger<T>` but does not produce an access audit trail. Without one, you cannot detect or investigate unauthorised access after the fact.

**Risk level:** High for any regulated workload (PCI-DSS, HIPAA, SOC 2 all require key management audit trails).

#### 4. No access policy enforcement

The library enforces owner isolation — owner A cannot read owner B's secrets — but it has no concept of roles or policies within an owner context. Any code that holds a reference to `ISecretManager` can call `CreateAsync`, `SetValueAsync`, or `RevokeAsync` for any owner it can supply. Access control is entirely the caller's responsibility. Dedicated vaults have fine-grained policy engines: policy A may read, policy B may read and write, policy C may only list.

**Risk level:** Medium. Mitigated by deploying the secret manager as a dedicated service and controlling which callers can reach it.

#### 5. No secret versioning or point-in-time recovery

HashiCorp Vault KV v2 retains previous secret versions and allows rollback. `SetValueAsync` is destructive — the previous payload is overwritten immediately with no recovery path. A bad rotation that writes incorrect or corrupted data cannot be undone.

**Risk level:** Medium. Mitigated by keeping an out-of-band encrypted backup before every rotation.

#### 6. Managed memory — secrets not explicitly zeroed

After `ValidateAsync` decrypts a payload, the plaintext exists as a .NET `string` on the managed heap. .NET strings are immutable; the GC may not collect them promptly; and if swap is enabled, they may be written to disk in plaintext before collection. Dedicated vaults and HSMs keep sensitive material in hardware or in pinned native memory that is explicitly zeroed after use. This is a fundamental limitation of the .NET managed runtime, not specific to this library.

**Risk level:** Low to medium depending on your swap and memory dump policy. On systems without swap and with restricted dump access, the exposure window is bounded.

#### 7. In-process, not network-isolated

Dedicated vaults expose a TLS-terminated network endpoint. The application contacts the vault over the network, and network controls (firewalls, mutual TLS, VNet rules) limit which callers can reach it. This library runs in-process with the host application. Any code in the same process can call `ISecretManager` without any network boundary. If the application is compromised, the vault is compromised. Running it as a dedicated microservice (see below) closes this gap.

**Risk level:** High if the host application has a large attack surface. Low if the host is a minimal, hardened service.

#### 8. No dynamic or ephemeral credential generation

Professional vaults can generate short-lived, dynamic credentials — for example, a temporary database user with a 15-minute TTL that is automatically revoked at expiry. This library stores static payloads only. Ephemeral credentials must be generated and rotated by application code.

#### 9. Compliance considerations

.NET's `AesGcm` and `HKDF` implementations use the operating system's cryptography provider. On Windows this is CNG; on Linux it is OpenSSL. Neither is FIPS 140-2 validated out of the box in all configurations. For workloads that require FIPS-validated cryptography (US federal, certain financial), verify that the runtime and OS configuration meets your requirements before deployment.

#### 10. Configuration bootstrapping

`SecretEncryptionKey` and `TokenSigningSecret` must be loaded from somewhere at startup. If they are stored in `appsettings.json`, they are as secure as the file and its ACLs. If in environment variables, they may be visible via process listings or container inspection. You need a secure bootstrap mechanism to load them — which itself raises the question of where that mechanism's credentials are stored.

---

### Steps to harden a self-hosted deployment

The following steps address the gaps above. Not all steps are required for every deployment — choose based on your threat model and compliance requirements.

#### Step 1 — Protect the root keys

Never store `SecretEncryptionKey` or `TokenSigningSecret` in source control or unencrypted config files. In order of increasing strength:

- **Development:** .NET User Secrets (`dotnet user-secrets`).
- **On-premises production:** Load from the OS keystore — Windows DPAPI (`ProtectedData.Protect`) or Linux `keyctl` / a TPM-backed key — and inject at startup via a custom `IConfigurationProvider`.
- **Cloud-connected on-premises:** Use your cloud provider's KMS (Azure Key Vault, AWS KMS, Google Cloud KMS) exclusively for **key wrapping** — the root key is stored encrypted in the KMS and decrypted into process memory at startup. Secret payloads never leave your infrastructure; only the wrapping call goes to the cloud.
- **Air-gapped / highest security:** Use a local HSM (Thales, Entrust, nCipher) via PKCS#11 to perform decryption inside the hardware. The root key never enters process memory.

#### Step 2 — Isolate the database

- Run the identity database on a **dedicated SQL Server instance** accessible only from the application hosts, not from the general network.
- Enable **Transparent Data Encryption (TDE)** to encrypt data files and backups at rest.
- Use a **dedicated low-privilege SQL login** for the application with permissions limited to the identity tables. No `sysadmin`, no `db_owner`.
- Separate the secret manager's database from application data if possible — different instance, different backup retention, different access controls.

#### Step 3 — Deploy as a dedicated microservice

Rather than embedding `ISecretManager` in your main application, deploy it as a dedicated, minimal ASP.NET Core service:

- No business logic, no user-facing routes — only the secret management endpoints.
- Authenticate callers with **mutual TLS** (client certificates) so only authorised services can connect.
- Expose it only on an internal network interface, not on a public IP.
- This gives you a clear blast radius: compromising the main application does not automatically grant access to the vault service.

#### Step 4 — Add an audit log

Wrap `ISecretManager` in a decorator that records every operation to an append-only audit sink:

```csharp
public class AuditingSecretManager : ISecretManager {
    private readonly ISecretManager inner;
    private readonly ILogger<AuditingSecretManager> logger;
    private readonly IHttpContextAccessor httpContext;

    public async Task<ICommandResponse<ApplicationSecretDto>> ValidateAsync(
            string plainToken, CancellationToken ct) {
        var result = await inner.ValidateAsync(plainToken, ct);
        logger.LogInformation(
            "SecretValidate status={Status} caller={Caller} tokenPrefix={Prefix}",
            result.Status,
            httpContext.HttpContext?.Connection.RemoteIpAddress,
            plainToken.Length > 8 ? plainToken[..8] : "short");
        return result;
    }

    // ... wrap all other methods similarly
}
```

Write audit records to a destination that the application cannot delete or modify — a dedicated append-only database table (INSERT-only permission), Azure Monitor / AWS CloudWatch Logs, or a WORM-compliant log sink.

#### Step 5 — Enforce authorisation before the library

Add a thin authorisation layer in front of `ISecretManager` that enforces which callers may perform which operations:

| Operation | Permitted callers |
|---|---|
| `CreateAsync`, `SetValueAsync`, `RevokeAsync` | Vault admin service account only |
| `ValidateAsync` | Any authenticated internal service |
| `FindByIdAsync`, `GetSelectListAsync` | Vault admin or the owning service |

Implement this as a policy-checked wrapper, an ASP.NET Core `[Authorize]` policy on the vault endpoints, or mutual TLS certificate policies.

#### Step 6 — Plan key rotation before you need it

Without a rotation plan, a compromised `SecretEncryptionKey` cannot safely be replaced. Document and test the following procedure before going to production:

1. Generate a new `SecretEncryptionKey` (keep the old one available temporarily).
2. Decrypt every existing `ApplicationSecret.Secret` using the old key.
3. Re-encrypt each payload under the new key with a fresh `EncryptionSalt`.
4. Once all records are migrated, remove the old key from configuration and redeploy.
5. Verify `ValidateAsync` succeeds for a representative sample of secrets.

Run this as a maintenance migration, not live traffic. Take a verified encrypted backup before starting.

#### Step 7 — Disable swap on vault hosts

On Linux hosts, disable swap entirely or use encrypted swap to prevent GC-collected decrypted payloads from being paged to disk:

```bash
# Disable swap immediately
sudo swapoff -a

# Persist across reboots — remove or comment out swap entries in /etc/fstab
```

If encrypted swap is required, use `dm-crypt` with a per-boot random key.

#### Step 8 — Monitor and alert

Instrument the audit log to trigger alerts on:

| Event | Suggested threshold |
|---|---|
| `ValidateAsync` failures from a single source | > 10 in 60 seconds |
| `SetValueAsync` or `RevokeAsync` from an unexpected caller | Any occurrence |
| Secrets expiring within 7 days without renewal | Daily report |
| Host process restarted (potential key re-load from config) | Any occurrence in production |

Repeated `ValidateAsync` failures for the same token prefix indicate a brute-force attempt. After a configurable threshold, auto-revoke the secret and alert an operator.

#### Step 9 — Backup and recovery

- Take an encrypted backup of the database daily, retaining at least 30 days.
- Store key material backups **separately** from database backups — a combined backup of database + keys in the same location gives an attacker both pieces at once.
- Test restoration quarterly: restore a backup to a staging environment and verify that `ValidateAsync` returns the expected payload.
- Document the RTO and RPO for your vault — losing the database and keys simultaneously means all stored secrets are permanently unrecoverable.

### Comparison summary

| Capability | This library | Dedicated vault |
|---|---|---|
| Encryption at rest | AES-256-GCM (software) | AES-256-GCM, optionally HSM-backed |
| Root key protection | Config / OS keystore | HSM / cloud KMS with hardware boundary |
| Key versioning and rotation | Manual migration required | Built-in, online rotation |
| Audit log | Must be added | Built-in, tamper-evident |
| Access policy engine | Caller's responsibility | Built-in RBAC / ACL |
| Secret versioning | No | Yes (HashiCorp KV v2) |
| Dynamic / ephemeral credentials | No | Yes |
| Network isolation | Optional (microservice deployment) | Default (dedicated network endpoint) |
| HA / clustering | Depends on SQL Server | Built-in |
| FIPS 140-2 validation | OS/runtime dependent | Configurable |
| Operational complexity | Low | Medium to high |
| External dependency | None (self-contained) | Cloud provider or self-hosted Vault |

This library is a reasonable choice for **low-to-medium sensitivity secrets** on self-hosted infrastructure where external dependencies must be minimised, and where the hardening steps above can be applied. For secrets that underpin payment processing, healthcare data, or regulated financial systems, evaluate whether the gaps above — particularly the lack of HSM backing, built-in audit logging, and key versioning — are acceptable before proceeding.

---

## Error responses

| Scenario | `ResponseStatus` returned |
|---|---|
| Secret created successfully | `Success` |
| Token not found or expired | `NotFound` |
| Token found but ownership mismatch | `NotFound` (indistinguishable from above by design) |
| Secret ID not found or wrong owner on revoke / lookup | `NotFound` |
| `SetValueAsync` — token unknown, tampered, or expired | `NotFound` |
| `SetValueAsync` — owner key material missing | `NotFound` |
| Validation succeeded | `Success` |
| `SetValueAsync` succeeded | `Success` |

Both `NotFound` and ownership mismatch map to the same response code in `ValidateAsync` and `SetValueAsync` to prevent callers from inferring whether a token exists.
