# IUserManager\<ApplicationUser\> — Developer Guide

`IUserManager<ApplicationUser>` is the interface for user management. The concrete implementation is `N2UserManager`, which lives in the `N2.Core.Identity.Services` namespace.

`N2UserManager` manages the full lifecycle of `ApplicationUser` records: creation, authentication, email confirmation, role management, multi-factor authentication, and application secrets. It also implements `IHaveSecrets`, meaning each user can own `ApplicationSecret` records via `ISecretManager`.

---

## Security model

### Password hashing — OWASP 2023

Passwords are hashed using PBKDF2-HMAC-SHA256 with **310,000 iterations**, which meets the OWASP 2023 recommendation. This is configured through ASP.NET Core Identity's `PasswordHasher<ApplicationUser>` with `CompatibilityMode.IdentityV3`. If a stored hash was produced at a lower iteration count, `ValidateAsync` detects this on the next successful login and automatically re-hashes the password to the current standard.

### Timing attack protection — constant-time responses

`N2UserManager.ValidateAsync` and `N2UserManager.ValidateMultifactorAsync` always take **at least 500 ms** to return, regardless of whether the user exists or the credentials are correct. This is enforced by an internal `TimeoutTimer` that pads short execution paths to the configured minimum. The same 500 ms floor is applied independently by `N2AuthenticationService.AuthenticateAsync` (the recommended authentication entry point).

This prevents user enumeration by measuring the time difference between "user not found" and "wrong password" responses.

### Account lockout — PCI-DSS aligned

After **5 consecutive failed password attempts**, the account is locked for **15 minutes**. The threshold is set at 5 because PCI-DSS allows up to 6; staying below that limit keeps the system compliant.

Both values are configurable in `AuthenticationConfig`:

```json
{
  "AuthenticationConfig": {
    "MaxFailedAccessAttempts": 5,
    "LockoutDurationMinutes": 15,
    "EnableAccountLockout": true
  }
}
```

Lockout is tracked in the database (`LockoutEnd`, `AccessFailedCount` on `ApplicationUser`), which means it survives process restarts. On a successful login, the failed count is reset to zero.

### MFA rate limiting — in-process

MFA code validation uses an injected `IRateLimiter`. The built-in `RateLimiter` implementation uses `IMemoryCache` with a sliding expiration window, protected by a `lock` for thread safety.

After **5 failed MFA attempts**, the user's MFA is blocked for **15 minutes** (configurable):

```json
{
  "AuthenticationConfig": {
    "MfaMaxAttempts": 5,
    "MfaLockoutMinutes": 15
  }
}
```

> **Important:** the default `RateLimiter` is **in-process only**. In a multi-instance deployment (load balanced, Kubernetes, etc.), each instance has its own memory cache and will not see attempts recorded by other instances. For distributed environments, provide an `IRateLimiter` implementation backed by a shared store such as Redis or SQL Server.

### MFA secret encryption — AES-256-GCM

TOTP and email/SMS secrets are encrypted with **AES-256-GCM** before storage. The encryption key comes from `MfaTokenSecret`. A second key, `MfaTokenSecret2`, is supported for zero-downtime key rotation. Plaintext secrets are never persisted.

### Email/SMS confirmation tokens — HMAC-SHA256

Email and SMS confirmation tokens are signed with **HMAC-SHA256** using `TokenSigningSecret`. The token format is:

```
{base64({nonce}:{expirationTicks})}.{base64(HMAC-SHA256 signature)}
```

The signature covers the nonce, expiration ticks, and the user's `SecurityStamp`. Because `SecurityStamp` is rotated whenever the username or email changes, previously issued tokens are automatically invalidated.

Tokens are valid for **5 days**.

### Security stamp rotation

`SetEmailAsync` and `SetUserNameAsync` both rotate the `SecurityStamp` to a new cryptographically random value. Any confirmation token or session tied to the old stamp is immediately invalidated.

---

## Setup

### Register the services

```csharp
// Password hasher — must match the iteration count used when hashing passwords
services.AddSingleton<IPasswordHasher<ApplicationUser>>(_ =>
    new PasswordHasher<ApplicationUser>(
        new OptionsWrapper<PasswordHasherOptions>(new PasswordHasherOptions {
            CompatibilityMode = PasswordHasherCompatibilityMode.IdentityV3,
            IterationCount = 310_000
        })));

// Rate limiter for MFA (in-process — see note above for distributed deployments)
services.AddMemoryCache();
services.AddSingleton<IRateLimiter>(sp =>
    new RateLimiter(
        sp.GetRequiredService<IMemoryCache>(),
        sp.GetRequiredService<ILogger<RateLimiter>>(),
        maxAttempts: 5,
        lockoutMinutes: 15));

// User manager
services.AddScoped<IUserManager<ApplicationUser>, N2UserManager>(sp =>
    new N2UserManager(
        sp.GetRequiredService<IIdentityContextFactory>(),
        sp.GetRequiredService<IConfiguration>(),
        sp.GetRequiredService<IRateLimiter>(),
        sp.GetRequiredService<IPasswordHasher<ApplicationUser>>(),
        connectionName: "IdentityDb",
        sp.GetRequiredService<ILogger<N2UserManager>>()
    ));
```

### Required configuration

The constructor validates `TokenSigningSecret` at startup and throws `InvalidOperationException` if it is absent or shorter than 32 bytes (256 bits).

```json
{
  "AuthenticationConfig": {
    "TokenSigningSecret": "<base64-encoded 32+ byte key>",
    "MfaTokenSecret": "<base64-encoded 32+ byte key>",
    "TwoFactorTotpName": "MyApp",
    "MaxFailedAccessAttempts": 5,
    "LockoutDurationMinutes": 15,
    "EnableAccountLockout": true,
    "MfaMaxAttempts": 5,
    "MfaLockoutMinutes": 15
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

Store all keys in a secrets manager (Azure Key Vault, AWS Secrets Manager, or .NET User Secrets during development) — never commit them to source control.

---

## Authentication entry point

For end-user authentication, prefer `N2AuthenticationService` over calling `N2UserManager` directly. It wires together the user lookup, password validation, sign-in eligibility check, and role retrieval in one call, and applies its own 500 ms timing floor independently of `N2UserManager`:

```csharp
services.AddScoped<IAuthenticator, N2AuthenticationService>();
```

```csharp
// Returns null on any failure — no status code to leak which step failed
IUserContext? context = await authenticator.AuthenticateAsync(userLogin, ct);
if (context == null) return Unauthorized();

// context.User — the authenticated ApplicationUser
// context.Roles — the user's role names
```

All failed authentication attempts are logged as warnings with a structured `LoginAttempt` log event.

---

## User lifecycle

### Creating a user

```csharp
var user = new ApplicationUser {
    Id = Guid.NewGuid(),
    UserName = "jane.doe",
    Email = "jane@example.com",
    MfaType = MultiFactorType.Email
};
var result = await userManager.CreateAsync(user, "StrongP@ssword1!", ct);
// ResponseStatus 406 if the username already exists
```

`CreateAsync` sets `NormalizedUserName`, `NormalizedEmail`, `SecurityStamp`, `PasswordHash`, `MfaSecret` (new random 32-byte secret, AES-256-GCM encrypted), and `EmailConfirmed = false`. The user cannot sign in until email is confirmed.

### Deleting a user

```csharp
var result = await userManager.DeleteAsync(user, ct);
```

### Updating the username

```csharp
var result = await userManager.SetUserNameAsync(user, "jane.smith", ct);
// 406 if the new username is already taken by a different user
// Rotates SecurityStamp — invalidates any pending confirmation tokens
```

### Updating the email

```csharp
var result = await userManager.SetEmailAsync(user, "new@example.com", ct);
// 406 if the email is already taken by a different user
// Sets EmailConfirmed = false and rotates SecurityStamp
// Send a new confirmation token after this call
```

---

## Lookup

```csharp
// By ID
ICommandResponse<ApplicationUser> response = await userManager.FindByIdAsync(userId, ct);

// By username (normalised internally — Trim().ToUpperInvariant())
ICommandResponse<ApplicationUser> response = await userManager.FindByNameAsync("jane.doe", ct);

// By email address (normalised internally)
ICommandResponse<ApplicationUser> response = await userManager.FindByEmailAsync("jane@example.com", ct);

// Sign-in eligibility (not locked, email or phone confirmed)
bool canSignIn = await userManager.CanSignInAsync(user, ct);
```

`FindBy*` methods wrap the result in `ICommandResponse<ApplicationUser>`. Check `response.Status.IsSuccess()` and access `response.Value` when found.

---

## Authentication

### Step 1 — Validate password

```csharp
var result = await userManager.ValidateAsync(user, password, ct);
// Returns after at least 500ms regardless of outcome
// ResponseStatus 423 Locked — account is locked; message contains the lockout end time
// ResponseStatus NotAccepted — wrong password (also increments the failed count)
// ResponseStatus Success — password correct; failed count reset to zero
```

### Step 2 — Validate MFA (if required)

```csharp
if (user.MfaType != MultiFactorType.None) {
    var mfaResult = await userManager.ValidateMultifactorAsync(user, mfaCode, ct);
    // Returns after at least 500ms
    // ResponseStatus Unauthorized — rate-limited, wrong code, or expired token
    // ResponseStatus Accepted — no MFA configured (MultiFactorType.None)
    // ResponseStatus Success — MFA passed
    if (!mfaResult.Status.IsSuccess()) return Unauthorized();
}
```

---

## Email confirmation

### 1. Generate and send a token

```csharp
var tokenResult = await userManager.GenerateConfirmationTokenAsync(user, ct);
var token = tokenResult.Value!;
// Send via email / SMS depending on user.MfaType
```

Token lifetimes and formats by MFA type:

| `MultiFactorType` | Token format | Validity |
|---|---|---|
| `Email` or `Sms` | `{base64(nonce:ticks)}.{base64(HMAC-SHA256)}` | 5 days |
| `Totp` | Current TOTP code (6 digits) | ~30 s |
| `None` | Empty string | — |

### 2. Confirm the email

```csharp
var result = await userManager.ConfirmEmailAsync(user, confirmationToken, ct);
// Sets EmailConfirmed = true and LockoutEnabled = true on success
```

---

## Multi-factor authentication

### Enrol a user

```csharp
var result = await userManager.SetMultifactorAsync(user, MultiFactorType.Totp, mfaToken, ct);
if (result.Status.IsSuccess()) {
    var props = result.Value!;
    // props.QrCode — PNG bytes for rendering a QR code (TOTP only)
    // props.Uri    — otpauth:// URI for manual entry
}
```

For `Email` or `Sms`, `props.Uri` is a `mailto://` or `phone://` URI rather than a QR code.

### TOTP verification window

TOTP validation uses a `VerificationWindow(1, 1)`, meaning codes from the current, previous, and next 30-second step are accepted. This accommodates minor clock drift on the user's device. Clock skew outside that window returns an informative message (`"Otp time skew error"` vs `"invalid OTP code"`).

---

## Role management

```csharp
// Create / delete roles
await userManager.CreateRoleAsync("Admin", ct);
await userManager.RemoveRoleAsync("Admin", ct);

// Assign / remove a user from a role (both idempotent)
await userManager.AddToRoleAsync(user, "Admin", ct);
await userManager.RemoveFromRoleAsync(user, "Admin", ct);

// Check membership
var inRole = await userManager.IsInRoleAsync(user, "Admin", ct);
// Success = in role, NotAccepted = not in role

// List all roles for a user
IListResponse<string> rolesResponse = await userManager.GetRolesAsync(user, ct);

bool exists = await userManager.RoleExistsAsync("Admin", ct);
```

---

## MFA key rotation

`N2UserManager` supports zero-downtime rotation of `MfaTokenSecret`. While rotating, both the old key (`MfaTokenSecret2`) and the new key (`MfaTokenSecret`) are accepted for decryption. After rotation, the old key is removed.

**Procedure:**

1. Set `MfaTokenSecret2` to the current value of `MfaTokenSecret`.
2. Set `MfaTokenSecret` to the new key.
3. Deploy the updated configuration.
4. Call `RotateMfaSecretsAsync` once to re-encrypt all rows:

```csharp
int count = await userManager.RotateMfaSecretsAsync(ct);
// count = number of MfaSecret rows re-encrypted
```

5. Clear `MfaTokenSecret2` from configuration and redeploy.

> **Do not remove `MfaTokenSecret2` before step 4.** Doing so will make any MFA secret still encrypted under the old key unreadable.

---

## Secrets (IHaveSecrets)

Each user can own `ApplicationSecret` records. See [secret-manager.md](secret-manager.md) for the full guide.

`SecretKeyMaterial` (32 bytes) must be set on the user before creating secrets. It is separate from `MfaSecret` so that MFA key rotation does not affect existing secrets:

```csharp
user.SecretKeyMaterial = RandomNumberGenerator.GetBytes(32);
// persist the user via your context or an update path

var owner = await userManager.GetSecretOwner(userId, ct);
// null if the user does not exist
// throws InvalidOperationException if SecretKeyMaterial is not set

var result = await secretManager.CreateAsync(owner!, new CreateSecretDto {
    Name = "Personal Access Token",
    Expiration = DateTime.UtcNow.AddYears(1)
}, ct);
```

---

## Error responses

| Scenario | `ResponseStatus` / status code |
|---|---|
| User created | `Success` |
| Username already exists | `406 NotAcceptable` |
| Wrong password | `NotAccepted` |
| Account locked | `423 Locked` |
| MFA rate-limited | `Unauthorized` |
| MFA code invalid or expired | `Unauthorized` |
| Role does not exist on assign | `NotAcceptable` |
| User not in role on check | `NotAccepted` |
| User or record not found | `NotFound` |
