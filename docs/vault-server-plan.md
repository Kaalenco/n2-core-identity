# N2 Vault Server — Implementation Plan

This document covers the changes required to `n2-core-identity` (this library) and the full functional specification for the dedicated vault server application, which will live in a separate repository and run on a private Kubernetes cluster with a MySQL database.

---

## Overview

The vault server is a minimal, hardened ASP.NET Core Web API that exposes `ISecretManager` over a private network endpoint. It replaces the need for Azure Key Vault, AWS Secrets Manager, or HashiCorp Vault in environments where all secret material must remain on privately controlled infrastructure.

```
┌─────────────────────────────────────────────────────────┐
│  Private K8s cluster                                    │
│                                                         │
│  ┌──────────────┐    mTLS     ┌────────────────────┐   │
│  │  Consuming   │ ──────────► │   Vault Server     │   │
│  │  services    │             │   (new repo)       │   │
│  └──────────────┘             │                    │   │
│                               │  n2-core-identity  │   │
│                               │  (this library)    │   │
│                               └────────┬───────────┘   │
│                                        │               │
│                               ┌────────▼───────────┐   │
│                               │   MySQL (private)  │   │
│                               └────────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

The consuming services never touch the database directly. They hold a `PlainToken` and call the vault API to create, update, validate, or revoke secrets.

---

## Part 1 — Changes required to this library

These are changes that must be made to `n2-core-identity` before or alongside building the vault server.

> **Status:** All library changes are **complete** as of 2026-03-18.

### 1.1 ✅ Add IChangeLogWriter — a single-method delegate service

**Problem solved:** `N2IdentityContext.AddChangeLog<T>` enqueues entries into an in-memory `ConcurrentQueue<IChangeLog>` that is scoped to the context instance. `N2SecretManager` creates and disposes its own context per method call, so any entries queued inside the manager are lost on disposal. The host never sees them.

**Implemented:** `IChangeLogWriter` interface (`Services/IChangeLogWriter.cs`):

```csharp
public interface IChangeLogWriter {
    void Add(IChangeLog entry);
}
```

`N2SecretManager`, `N2UserManager`, `N2ApplicationManager`, and `N2TenantManager` each accept an optional `IChangeLogWriter?` as a constructor parameter. When present, the secret manager calls `Add` after each operation. When absent, it operates silently with no behaviour change for existing consumers.

The `ConcurrentQueue` in `N2IdentityContext` and the existing `AddChangeLog` methods are left unchanged. `IChangeLogWriter` is a parallel, independent route for services that manage their own context lifetimes.

### 1.2 ✅ N2SecretManager emits changelog entries

`N2SecretManager` calls `IChangeLogWriter.Add` (via a private `Log()` helper) after each operation:

| Operation | Message logged |
|---|---|
| `CreateAsync` — success | `"Secret created: {Name}"` |
| `CreateAsync` — failure | `"Secret create failed: {reason}"` |
| `SetValueAsync` — success | `"Secret value updated"` |
| `SetValueAsync` — failure | `"Secret value update failed: {reason}"` |
| `RevokeAsync` — success | `"Secret revoked"` |
| `RevokeAsync` — failure | `"Secret revoke failed: {reason}"` |
| `ValidateAsync` — success | `"Secret validated"` |
| `ValidateAsync` — meaningful failure | `"Secret validation failed: {reason}"` |

Early-exit failures (garbage token format, token not found) are not logged to avoid noise from invalid inputs.

### 1.3 ✅ New interface: IVaultCallerContext

**Implemented:** `IVaultCallerContext` interface (`Services/IVaultCallerContext.cs`):

```csharp
public interface IVaultCallerContext {
    Guid CallerId { get; }
    string CallerName { get; }
}
```

`N2SecretManager` accepts `IVaultCallerContext?` as a constructor parameter and reads from it when composing `QueueLogEntry`. Falls back to `Guid.Empty` / `"system"` when not registered. The vault server registers a concrete implementation backed by the verified client certificate or JWT claims.

### 1.4 ✅ SecretAdd is tracking-only (breaking change)

`IIdentityContext.SecretAdd` signature changed from `Task<int> SecretAdd(ApplicationSecret, CancellationToken)` to `void SecretAdd(ApplicationSecret)`.

`N2IdentityContext.SecretAdd` now calls `ApplicationSecrets.Add(secret)` only — no `SaveChangesAsync`. `N2SecretManager.CreateAsync` calls `ctx.SecretAdd(secret)` followed by `await ctx.Complete()`, which persists the entity and any other tracked changes in a single round-trip.

All test call sites updated accordingly. **Bump library minor version.**

### 1.5 ✅ KeyVersion on ApplicationSecret

`ApplicationSecret` has a new `int KeyVersion { get; set; } = 1` property. `AuthenticationConfig` has a matching `int SecretEncryptionKeyVersion { get; set; } = 1`.

`N2SecretManager.CreateAsync` and `SetValueAsync` both write `configuration.SecretEncryptionKeyVersion` to `secret.KeyVersion` whenever a value is encrypted. This lets the key rotation tool (§2.10) query for rows with a stale `KeyVersion` and re-encrypt only those records.

Migration `AddSecretKeyVersion` has been generated and is included in the repository.

### 1.6 Summary of library changes

| # | Change | Status | Breaking |
|---|---|---|---|
| 1.1 | Add `IChangeLogWriter` interface; inject optionally into manager classes | ✅ Done | No |
| 1.2 | `N2SecretManager` emits changelog entries via `IChangeLogWriter` | ✅ Done | No |
| 1.3 | Add `IVaultCallerContext` interface; inject optionally into manager classes | ✅ Done | No |
| 1.4 | `SecretAdd` — tracking-only, signature changed to `void SecretAdd(ApplicationSecret)` | ✅ Done | Yes |
| 1.5 | `KeyVersion` on `ApplicationSecret`; `SecretEncryptionKeyVersion` in `AuthenticationConfig` | ✅ Done | No |

---

## Part 2 — Vault server functional requirements

### 2.1 Technology stack

| Concern | Choice |
|---|---|
| Framework | ASP.NET Core 9+ minimal API |
| ORM | EF Core with Pomelo MySQL provider (`Pomelo.EntityFrameworkCore.MySql` — already referenced by the library) |
| Database | MySQL 8.x (private, K8s-hosted) |
| Authentication | Mutual TLS (client certificates) — primary; JWT bearer — optional for tooling |
| Authorisation | ASP.NET Core policy-based (`[Authorize(Policy = "...")]`) |
| Audit | `IChangeLogWriter` → MySQL `AuditLog` table |
| Rate limiting | ASP.NET Core `RateLimiterMiddleware` |
| Health | ASP.NET Core health checks (`/health/live`, `/health/ready`) |
| Observability | OpenTelemetry (traces + metrics) exported to cluster collector |
| Containerisation | Single-stage Docker image, non-root user, read-only root filesystem |

**MySQL provider note:** No library changes are required for MySQL support. The library's `ProviderAgnosticDesignTimeServices` already ensures all migrations are provider-neutral — column types are omitted (each provider resolves its own DDL type at execution time), SQL Server index filters are stripped, and MySQL auto-increment annotations are added alongside SQL Server identity annotations. The vault server selects the MySQL provider purely through host configuration at startup:

```csharp
options.UseMySql(connectionString, ServerVersion.AutoDetect(connectionString));
```

### 2.2 Authentication

All requests must be authenticated. Two modes:

**Mutual TLS (primary):** The server requires a client certificate on all non-health endpoints. The certificate's `Subject` is the caller's identity. CN is the service name; a custom OID or SAN carries the caller GUID. The K8s ingress or service mesh (e.g. Istio) terminates mTLS and forwards the verified certificate in a header (`X-Client-Cert-Subject` or similar).

**JWT bearer (tooling / admin CLI):** An optional second scheme for human operators using an admin CLI. The JWT is issued by the vault server's own `/auth/token` endpoint, which is itself protected by mTLS or a pre-shared admin credential stored in a K8s Secret.

The `IVaultCallerContext` implementation reads the CN/OID from the verified certificate or the JWT `sub` claim, resolves it to a `Guid` and name, and makes it available to `N2SecretManager`.

### 2.3 Authorisation policies

| Policy | Permitted callers | Allowed operations |
|---|---|---|
| `vault:admin` | Registered admin service accounts | All operations |
| `vault:write` | Registered service accounts with write access | Create, SetValue, Revoke |
| `vault:read` | Any authenticated caller | Validate, FindById, GetSelectList |

Caller registrations are stored in the vault's own configuration (a small YAML or JSON file mounted as a K8s ConfigMap). Callers are identified by their certificate CN. For the initial version, this can be a static list; later it can be managed via an admin API.

### 2.4 API endpoints

All endpoints are under `/api/v1`. All request and response bodies are `application/json`. All timestamps are UTC ISO 8601.

#### Secrets

| Method | Path | Policy | Description |
|---|---|---|---|
| `POST` | `/api/v1/owners/{ownerType}/{ownerId}/secrets` | `vault:write` | Create a new secret. Returns `PlainToken` once. |
| `DELETE` | `/api/v1/owners/{ownerType}/{ownerId}/secrets/{secretId}` | `vault:write` | Revoke a secret. |
| `GET` | `/api/v1/owners/{ownerType}/{ownerId}/secrets` | `vault:read` | List active secrets for an owner (metadata only). |
| `GET` | `/api/v1/owners/{ownerType}/{ownerId}/secrets/{secretId}` | `vault:read` | Get metadata for a single secret. |
| `PUT` | `/api/v1/secrets/value` | `vault:write` | Set or replace the encrypted payload. Body contains `{ "token": "...", "value": "..." }`. |
| `POST` | `/api/v1/secrets/validate` | `vault:read` | Validate a token and return metadata + decrypted payload. Body: `{ "token": "..." }`. |
| `GET` | `/api/v1/owners/{ownerType}/{ownerId}/secrets/{secretId}/policy` | `vault:read` | Get JSON policy attached to a secret. |
| `PUT` | `/api/v1/owners/{ownerType}/{ownerId}/secrets/{secretId}/policy` | `vault:write` | Set JSON policy on a secret. |

#### Owners

| Method | Path | Policy | Description |
|---|---|---|---|
| `POST` | `/api/v1/owners/users` | `vault:admin` | Register a user as a secret owner (generates `SecretKeyMaterial`). |
| `POST` | `/api/v1/owners/applications` | `vault:admin` | Register an application as a secret owner. |
| `POST` | `/api/v1/owners/tenants` | `vault:admin` | Register a tenant as a secret owner. |
| `DELETE` | `/api/v1/owners/{ownerType}/{ownerId}` | `vault:admin` | Remove an owner and revoke all their secrets. |

#### Infrastructure

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/health/live` | None | Liveness probe — returns 200 if the process is running. |
| `GET` | `/health/ready` | None | Readiness probe — returns 200 only if the database is reachable. |
| `GET` | `/metrics` | Cluster-internal only | OpenTelemetry Prometheus scrape endpoint. |

### 2.5 Audit log

The vault server implements `IChangeLogWriter` and persists every entry to a dedicated `AuditLog` table in MySQL. This table must be:

- **INSERT-only from the application** — the application user has `INSERT` permission only. No `UPDATE` or `DELETE`. Rotation/purge is done by a DBA or a separate maintenance job.
- **Schema:**

```sql
CREATE TABLE AuditLog (
    Id          BIGINT        NOT NULL AUTO_INCREMENT PRIMARY KEY,
    LogRecordId CHAR(36)      NOT NULL,
    TableName   VARCHAR(128)  NOT NULL,
    ReferenceId CHAR(36)      NOT NULL,
    Message     VARCHAR(1024) NOT NULL,
    CreatedBy   CHAR(36)      NOT NULL,
    CreatedByName VARCHAR(256) NOT NULL,
    Created     DATETIME(6)   NOT NULL,
    CallerIp    VARCHAR(45)   NULL,        -- added by vault server middleware
    RequestId   VARCHAR(64)   NULL         -- correlation ID from X-Request-ID header
);
```

The vault server middleware enriches each log entry with `CallerIp` and `RequestId` before `IChangeLogWriter.Add` is called.

### 2.6 Rate limiting

Apply a sliding-window rate limiter on `/api/v1/secrets/validate`, keyed on the caller certificate CN (or JWT subject):

- **Normal callers:** 300 requests per minute.
- **Burst:** Allow up to 50 concurrent in-flight requests per caller.
- **On limit exceeded:** Return `429 Too Many Requests` with a `Retry-After` header.

After 20 consecutive `NotFound` responses for the same token prefix within 60 seconds, emit a high-severity alert log entry and optionally trigger an automatic revocation (configurable — off by default).

### 2.7 Configuration

All configuration is provided via environment variables or a mounted ConfigMap. No secrets in the ConfigMap.

| Variable | Source | Description |
|---|---|---|
| `VAULT_DB_CONNECTION` | K8s Secret | MySQL connection string |
| `VAULT_TOKEN_SIGNING_SECRET` | K8s Secret | Base64 32-byte HMAC key |
| `VAULT_ENCRYPTION_KEY` | K8s Secret | Base64 32-byte AES encryption key |
| `VAULT_ENCRYPTION_KEY_VERSION` | ConfigMap | Integer version of the active encryption key (default: `1`). Increment on rotation. |
| `VAULT_CALLER_REGISTRY` | ConfigMap | Path to YAML file listing authorised callers and their policies |
| `VAULT_RATE_LIMIT_WINDOW` | ConfigMap | Rate limit window in seconds (default: 60) |
| `VAULT_RATE_LIMIT_MAX` | ConfigMap | Max requests per window per caller (default: 300) |
| `ASPNETCORE_URLS` | ConfigMap | Binding address (e.g. `https://+:8443`) |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | ConfigMap | OpenTelemetry collector endpoint |

Keys are never written to disk. They are injected as environment variables from K8s Secrets into the pod at startup. On startup, the application validates that all required secrets are present and non-empty; if any are missing, it exits immediately with a non-zero code (fail-fast).

### 2.8 Key bootstrapping sequence

On pod start:

1. Read `VAULT_TOKEN_SIGNING_SECRET` and `VAULT_ENCRYPTION_KEY` from environment.
2. Validate both are valid base64-encoded 32-byte arrays. Exit with code 1 if not.
3. Bind them to `AuthenticationConfig` in the DI container (not written to any file).
4. Attempt database connection. Retry 3 times with 5-second backoff. Exit with code 1 if all attempts fail.
5. Run pending EF Core migrations automatically on startup (controlled by `VAULT_AUTO_MIGRATE=true`; off by default in production).
6. Start accepting requests.

### 2.9 Kubernetes deployment

#### Deployment manifest requirements

- **Replicas:** 2 minimum for availability.
- **Pod security:**
  - `runAsNonRoot: true`
  - `runAsUser: 1000`
  - `readOnlyRootFilesystem: true`
  - `allowPrivilegeEscalation: false`
  - `capabilities.drop: ["ALL"]`
- **Resource limits:** Set explicit CPU and memory limits. The vault server is stateless between requests; memory usage should be predictable.
- **Volume mounts:** Mount a writable `emptyDir` at `/tmp` only (needed by the ASP.NET runtime). Everything else is read-only.
- **Liveness probe:** `GET /health/live` — start after 10s, period 15s.
- **Readiness probe:** `GET /health/ready` — start after 5s, period 10s.

#### Network policy

Restrict ingress to the vault pods:

```yaml
# Only allow ingress from namespaces labelled vault-client=true
# and from the monitoring namespace for metrics scraping
ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          vault-client: "true"
  - from:
    - namespaceSelector:
        matchLabels:
          name: monitoring
    ports:
      - port: 9090   # metrics only
```

No egress except to the MySQL service and the OpenTelemetry collector.

#### Secrets mount

```yaml
env:
  - name: VAULT_TOKEN_SIGNING_SECRET
    valueFrom:
      secretKeyRef:
        name: vault-keys
        key: tokenSigningSecret
  - name: VAULT_ENCRYPTION_KEY
    valueFrom:
      secretKeyRef:
        name: vault-keys
        key: encryptionKey
  - name: VAULT_DB_CONNECTION
    valueFrom:
      secretKeyRef:
        name: vault-db-credentials
        key: connectionString
```

The `vault-keys` Secret is created once during cluster provisioning and never updated in-place. Key rotation requires creating a new Secret, running the re-encryption migration (see §2.10), then updating the Secret reference and rolling the deployment.

### 2.10 Key rotation procedure

This procedure rotates `VAULT_ENCRYPTION_KEY` without downtime:

1. Generate a new key: `openssl rand -base64 32`.
2. Increment `VAULT_ENCRYPTION_KEY_VERSION` (maps to `AuthenticationConfig.SecretEncryptionKeyVersion`) to the next integer (e.g. `2`).
3. Create a new K8s Secret `vault-keys-v2` with the new key and new version. Keep the old `vault-keys` Secret.
4. Deploy a one-shot migration job that:
   - Reads all `ApplicationSecret` rows where `Secret IS NOT NULL` and `KeyVersion < {new version}`.
   - Decrypts each payload using the old key and the existing `EncryptionSalt` / HKDF inputs.
   - Re-encrypts under the new key with a fresh `EncryptionSalt` and updates `KeyVersion` to the new version.
   - Writes the row. Any row already at the new version is skipped (idempotent).
5. Verify the migration on a staging restore before running in production.
6. Once the migration job completes successfully, update the vault deployment to use `vault-keys-v2`.
7. Roll the deployment. Delete `vault-keys` after confirming all pods are healthy.

The `KeyVersion` column (§1.5) is what makes step 4 efficient — the job never needs to attempt decryption to determine whether a row needs rotation.

This migration job is a separate tool in the vault server repository, not part of the running server.

---

## Part 3 — Implementation phases

Build and ship in this order to keep each phase independently deployable and testable.

### Phase 1 — Library changes (n2-core-identity) ✅ Complete

1. ✅ Add `IChangeLogWriter` interface (single `Add` method).
2. ✅ Add `IVaultCallerContext` interface.
3. ✅ Update `N2SecretManager` to inject both as optional dependencies and call `IChangeLogWriter.Add` after each operation.
4. ✅ Fix `SecretAdd` to tracking-only (remove auto-save; change signature to `void`).
5. ✅ Add `KeyVersion` to `ApplicationSecret` and `SecretEncryptionKeyVersion` to `AuthenticationConfig`.
6. ✅ Run `dotnet ef migrations add AddSecretKeyVersion` and publish updated NuGet package.

### Phase 2 — Vault server scaffold (new repository)

1. Create `N2.VaultServer` ASP.NET Core minimal API project.
2. Wire up MySQL, `N2IdentityContext`, `N2SecretManager`, `IChangeLogWriter`.
3. Implement `IVaultCallerContext` backed by a placeholder (fixed identity).
4. Implement `/health/live` and `/health/ready`.
5. Implement all secret and owner endpoints (no auth yet).
6. Write integration tests against a real MySQL instance (Testcontainers).

### Phase 3 — Authentication and authorisation

1. Implement mTLS client certificate validation middleware.
2. Implement `IVaultCallerContext` reading from the verified certificate.
3. Implement caller registry (YAML ConfigMap).
4. Apply `vault:admin`, `vault:write`, `vault:read` policies to all endpoints.
5. Implement JWT bearer scheme for admin tooling.

### Phase 4 — Audit and rate limiting

1. Implement `IChangeLogWriter` → MySQL `AuditLog` table.
2. Implement request middleware to enrich log entries with `CallerIp` and `RequestId`.
3. Apply rate limiting on `/secrets/validate`.
4. Implement brute-force detection and alert logging.

### Phase 5 — Kubernetes deployment

1. Write Dockerfile (non-root, read-only root filesystem).
2. Write Helm chart: Deployment, Service, NetworkPolicy, ConfigMap, Secret templates.
3. Write GitHub Actions workflow: build → test → push image → helm lint.
4. Document cluster provisioning steps (MySQL setup, Secret creation, initial owner registration).

### Phase 6 — Hardening and observability

1. Add OpenTelemetry traces and metrics (request count, latency, validation failure rate).
2. Add startup key validation (fail-fast on missing/invalid keys).
3. Write the key rotation migration tool.
4. Load test the validate endpoint; tune rate limiter thresholds.
5. Security review: confirm no secrets in logs, no swap on nodes, network policy enforced.

---

## Part 4 — Open questions

These must be decided before Phase 3 begins:

1. **mTLS termination point:** Does the K8s ingress controller terminate mTLS and forward the cert in a header, or does the vault pod terminate TLS directly? The answer affects how `IVaultCallerContext` reads the caller identity.

2. **MySQL HA:** Single MySQL instance or a Percona XtraDB Cluster / MySQL InnoDB Cluster? A single instance is a HA risk for the vault.

3. **Owner registration:** Will owners (users, applications, tenants) be managed via the vault API (§2.4 owner endpoints), or will they be pre-populated by a separate provisioning process? This affects Phase 2 scope.

4. **Audit retention:** How long are `AuditLog` rows retained, and who/what runs the purge? Compliance requirements may mandate a minimum retention period.

5. **`VAULT_AUTO_MIGRATE`:** Should migrations run automatically on startup in production, or via a separate pre-install job? The pre-install job is safer (stops the deployment if migration fails before old pods are stopped) but adds pipeline complexity.
