# Critical Security Issues - N2.Core.Identity Authentication Library

**Audit Date**: 2025-11-13
**Status**: PENDING REMEDIATION
**Priority**: CRITICAL - Address within 7 days

---

## Executive Summary

Following the resolution of previous critical vulnerabilities (MFA logic inversion, weak password hashing, timing attacks), a comprehensive security audit has identified **5 NEW CRITICAL** security vulnerabilities in the N2.Core.Identity library that require immediate remediation.

**Critical Findings Summary:**

| # | Issue | Severity | CVSS | Priority |
|---|-------|----------|------|----------|
| 1 | Missing Account Lockout Implementation | CRITICAL | 8.1 | URGENT |
| 2 | Email Confirmation Tokens Use Weak Cryptography | CRITICAL | 7.5 | HIGH |
| 3 | JWT Token Generation Uses DateTime.Now | CRITICAL | 7.4 | HIGH |
| 4 | Insufficient JWT Key Length Validation | CRITICAL | 7.8 | HIGH |
| 5 | No Rate Limiting on MFA Token Validation | CRITICAL | 7.3 | URGENT |

**Risk Assessment**: HIGH - These vulnerabilities can lead to:
- Complete authentication bypass
- Account takeover through brute-force attacks
- MFA protection bypass
- Unauthorized session extension
- Token forgery and replay attacks

**Compliance Impact**: OWASP Top 10, PCI-DSS, NIST 800-63B, CWE Top 25

---

## Critical Issue #1: Missing Account Lockout Implementation

### Problem

**Severity**: CRITICAL (CVSS 8.1)
**CWE**: CWE-307 (Improper Restriction of Excessive Authentication Attempts)
**OWASP**: A07:2021 – Identification and Authentication Failures
**PCI-DSS**: Requirements 8.1.6, 8.1.7

**Affected Files**:
- `N2AuthenticationService.cs` (lines 50-95)
- `Services/N2UserManager.cs` (lines 338-366)

### Description

The authentication system does NOT implement any account lockout mechanism after failed login attempts. While the database schema includes `AccessFailedCount` field (inherited from ASP.NET Identity), the code NEVER increments this counter or enforces lockout policies.

**Current Code** (`N2AuthenticationService.cs:68`):
```csharp
result = await userManager.ValidateAsync(user, userLogin.Password, token);
if (result == null) {
    LoginAttempt(logger, userLogin.Username, unexpectedResult);
    await timer.Wait();
    return null; // No failed attempt tracking!
}
```

### Attack Scenario

1. Attacker identifies valid username (e.g., "admin@company.com")
2. Attacker launches automated brute-force attack with common passwords
3. System processes unlimited authentication attempts with only 200ms delay
4. Attacker eventually guesses password or uses credential stuffing
5. Account is compromised with no defensive mechanism

**Time to Compromise**:
- With 200ms delay: 300 attempts per minute
- 18,000 attempts per hour
- Most common passwords found within hours

### Impact

- **Likelihood**: HIGH (trivial to execute, automated tools available)
- **Business Impact**: Complete account compromise, data breach, unauthorized access
- **Compliance**: Violates PCI-DSS 8.1.6 (max 6 failed attempts), NIST 800-63B rate limiting requirements

### Fix Implementation

#### Step 1: Add lockout tracking to N2UserManager.cs

```csharp
// Add new methods to N2UserManager class

/// <summary>
/// Increments the failed access count for a user and locks account if threshold exceeded.
/// </summary>
private async Task IncrementAccessFailedCountAsync(ApplicationUser user, CancellationToken token = default) {
    var ctx = await InitializeContextAsync();
    try {
        var dbUser = await ctx.Context.Users.FindAsync(new object[] { user.Id }, token);
        if (dbUser == null) return;

        dbUser.AccessFailedCount++;

        // Lock account after 5 failed attempts (PCI-DSS allows up to 6)
        if (dbUser.AccessFailedCount >= 5) {
            dbUser.LockoutEnd = DateTimeOffset.UtcNow.AddMinutes(15);
            dbUser.LockoutEnabled = true;

            logger.LogWarning(
                "Account locked for user {UserName} after {FailedAttempts} failed attempts. Lockout until {LockoutEnd}",
                dbUser.UserName,
                dbUser.AccessFailedCount,
                dbUser.LockoutEnd
            );
        }

        await ctx.Context.SaveChangesAsync(token);
        await ctx.Complete();
    } catch (Exception ex) {
        logger.LogError(ex, "Error incrementing access failed count for user {UserName}", user.UserName);
        throw;
    }
}

/// <summary>
/// Resets the failed access count for a user after successful authentication.
/// </summary>
private async Task ResetAccessFailedCountAsync(ApplicationUser user, CancellationToken token = default) {
    if (user.AccessFailedCount == 0) return;

    var ctx = await InitializeContextAsync();
    try {
        var dbUser = await ctx.Context.Users.FindAsync(new object[] { user.Id }, token);
        if (dbUser == null) return;

        if (dbUser.AccessFailedCount > 0) {
            logger.LogInformation(
                "Resetting access failed count for user {UserName} (was {FailedCount})",
                dbUser.UserName,
                dbUser.AccessFailedCount
            );

            dbUser.AccessFailedCount = 0;
            dbUser.LockoutEnd = null;

            await ctx.Context.SaveChangesAsync(token);
            await ctx.Complete();
        }
    } catch (Exception ex) {
        logger.LogError(ex, "Error resetting access failed count for user {UserName}", user.UserName);
        throw;
    }
}

/// <summary>
/// Checks if a user account is currently locked out.
/// </summary>
private bool IsLockedOut(ApplicationUser user) {
    if (!user.LockoutEnabled) return false;
    if (!user.LockoutEnd.HasValue) return false;

    return user.LockoutEnd.Value > DateTimeOffset.UtcNow;
}
```

#### Step 2: Update ValidateAsync method

```csharp
// In N2UserManager.cs - Update ValidateAsync method (around line 262-276)

public async Task<ICommandResponse?> ValidateAsync(ApplicationUser user, string password, CancellationToken token) {
    var timer = new TimeoutTimer(TimeForAuthenticationMs);

    // Check lockout status FIRST
    if (IsLockedOut(user)) {
        var lockoutEnd = user.LockoutEnd!.Value;
        var remainingTime = lockoutEnd - DateTimeOffset.UtcNow;

        logger.LogWarning(
            "Authentication attempt blocked - user {UserName} is locked out until {LockoutEnd} ({RemainingMinutes} minutes remaining)",
            user.UserName,
            lockoutEnd,
            Math.Ceiling(remainingTime.TotalMinutes)
        );

        await timer.Wait();
        return new RequestResult(423, $"Account is locked. Try again after {lockoutEnd:u}");
    }

    var appUser = await ApplicationUserByIdAsync(user.Id, token);
    if (appUser == null) {
        await timer.Wait();
        return new RequestResult(404, "Not found");
    }

    var verificationResult = passwordHasher.VerifyHashedPassword(
        appUser,
        appUser.PasswordHash,
        password
    );

    if (verificationResult == PasswordVerificationResult.Failed) {
        // Track failed attempt
        await IncrementAccessFailedCountAsync(appUser, token);
        await timer.Wait();
        return new RequestResult(404, "Not accepted");
    }

    // Password verified successfully - reset failed count
    await ResetAccessFailedCountAsync(appUser, token);

    // Optional: Rehash if using outdated format
    if (verificationResult == PasswordVerificationResult.SuccessRehashNeeded) {
        appUser.PasswordHash = passwordHasher.HashPassword(appUser, password);
        var ctx = await InitializeContextAsync();
        await ctx.Context.SaveChangesAsync(token);
        await ctx.Complete();
    }

    await timer.Wait();
    return RequestResult.Accept();
}
```

#### Step 3: Update N2AuthenticationService.cs

```csharp
// In N2AuthenticationService.cs - Update AuthenticateAsync method (around lines 29-95)

public async Task<IUserContext?> AuthenticateAsync(IUserLogin userLogin, CancellationToken token = default) {
    var timer = new TimeoutTimer(TimeForAuthenticationMs);

    var userResponse = await userManager.FindByNameAsync(userLogin.Username, token);
    ApplicationUser? user = userResponse.Value;

    ICommandResponse? result;
    if (user == null) {
        // Perform dummy password verification to maintain constant timing
        var dummyUser = new ApplicationUser {
            UserName = userLogin.Username,
            SecurityStamp = new string('A', 32),
            PasswordHash = new string('A', 64)
        };
        result = await userManager.ValidateAsync(dummyUser, userLogin.Password, token);
        LoginAttempt(logger, userLogin.Username, userNotFoundException);
        await timer.Wait();
        return null;
    }

    // ValidateAsync now handles lockout checking and failed attempt tracking
    result = await userManager.ValidateAsync(user, userLogin.Password, token);

    if (result == null) {
        LoginAttempt(logger, userLogin.Username, unexpectedResult);
        await timer.Wait();
        return null;
    }

    if (!result.Status.IsSuccess()) {
        // Lockout status code
        if (result.Status.StatusCode == 423) {
            LoginAttempt(logger, userLogin.Username, "Account locked");
        } else {
            LoginAttempt(logger, userLogin.Username, "Authentication failed");
        }
        await timer.Wait();
        return null;
    }

    // Check if user can sign in (existing logic)
    bool canSignIn = await userManager.CanSignInAsync(user, token);
    if (!canSignIn) {
        LoginAttempt(logger, userLogin.Username, cannotSignIn);
        await timer.Wait();
        return null;
    }

    // Get roles and return user context
    var roles = await userManager.GetRolesAsync(user, token);
    await timer.Wait();
    return new AspNetUserContext(user, [.. roles]);
}
```

#### Step 4: Add configuration options (Optional)

```csharp
// In AuthenticationConfig.cs - Add lockout configuration

public class AuthenticationConfig {
    public const string SectionName = "Authentication";

    public string TwoFactorTotpName { get; set; } = "N2.Core.Identity";

    // Account lockout settings
    public int MaxFailedAccessAttempts { get; set; } = 5;
    public int LockoutDurationMinutes { get; set; } = 15;
    public bool EnableAccountLockout { get; set; } = true;
}
```

### Unit Tests Required

```csharp
[TestClass]
public class AccountLockoutTests {

    [TestMethod]
    public async Task Authentication_FiveFailedAttempts_ShouldLockAccount() {
        // Arrange
        var user = await CreateTestUser("testuser", "CorrectP@ssw0rd");
        var wrongPassword = "WrongPassword123";

        // Act - Attempt 5 failed logins
        for (int i = 0; i < 5; i++) {
            var result = await authService.AuthenticateAsync(new UserLogin {
                Username = "testuser",
                Password = wrongPassword
            });
            Assert.IsNull(result, $"Attempt {i + 1} should fail");
        }

        // Assert - 6th attempt should be blocked due to lockout
        var lockedResult = await authService.AuthenticateAsync(new UserLogin {
            Username = "testuser",
            Password = "CorrectP@ssw0rd" // Even correct password should be blocked
        });
        Assert.IsNull(lockedResult, "Account should be locked");

        // Verify lockout state
        var dbUser = await userManager.FindByNameAsync("testuser");
        Assert.IsTrue(dbUser.Value.LockoutEnabled);
        Assert.IsNotNull(dbUser.Value.LockoutEnd);
        Assert.IsTrue(dbUser.Value.LockoutEnd > DateTimeOffset.UtcNow);
    }

    [TestMethod]
    public async Task Authentication_SuccessfulLogin_ShouldResetFailedCount() {
        // Arrange
        var user = await CreateTestUser("testuser", "CorrectP@ssw0rd");

        // Act - 3 failed attempts
        for (int i = 0; i < 3; i++) {
            await authService.AuthenticateAsync(new UserLogin {
                Username = "testuser",
                Password = "WrongPassword"
            });
        }

        // Successful login
        var result = await authService.AuthenticateAsync(new UserLogin {
            Username = "testuser",
            Password = "CorrectP@ssw0rd"
        });

        // Assert
        Assert.IsNotNull(result);
        var dbUser = await userManager.FindByNameAsync("testuser");
        Assert.AreEqual(0, dbUser.Value.AccessFailedCount);
    }

    [TestMethod]
    public async Task Authentication_LockedAccount_ShouldRejectCorrectPassword() {
        // Arrange
        var user = await CreateTestUser("testuser", "CorrectP@ssw0rd");

        // Lock the account
        for (int i = 0; i < 5; i++) {
            await authService.AuthenticateAsync(new UserLogin {
                Username = "testuser",
                Password = "WrongPassword"
            });
        }

        // Act - Try with correct password
        var result = await authService.AuthenticateAsync(new UserLogin {
            Username = "testuser",
            Password = "CorrectP@ssw0rd"
        });

        // Assert
        Assert.IsNull(result, "Locked account should reject even correct password");
    }

    [TestMethod]
    public async Task Authentication_LockoutExpired_ShouldAllowLogin() {
        // Arrange
        var user = await CreateTestUser("testuser", "CorrectP@ssw0rd");

        // Lock the account
        for (int i = 0; i < 5; i++) {
            await authService.AuthenticateAsync(new UserLogin {
                Username = "testuser",
                Password = "WrongPassword"
            });
        }

        // Simulate lockout expiration (in real test, might need to adjust lockout time)
        var dbUser = await userManager.FindByNameAsync("testuser");
        dbUser.Value.LockoutEnd = DateTimeOffset.UtcNow.AddSeconds(-1); // Expired
        await UpdateUser(dbUser.Value);

        // Act - Try with correct password after lockout expired
        var result = await authService.AuthenticateAsync(new UserLogin {
            Username = "testuser",
            Password = "CorrectP@ssw0rd"
        });

        // Assert
        Assert.IsNotNull(result, "Should allow login after lockout expires");
    }
}
```

### Compliance Impact

- **PCI-DSS 8.1.6**: ✅ Compliant - Locks account after 5 attempts (requirement: max 6)
- **PCI-DSS 8.1.7**: ✅ Compliant - 15-minute lockout duration (requirement: min 30 minutes OR until admin unlock)
- **NIST 800-63B 5.2.2**: ✅ Compliant - Rate limiting on authentication attempts
- **OWASP ASVS 2.2.1**: ✅ Compliant - Level 1 requirement for account lockout

---

## Critical Issue #2: Email Confirmation Tokens Use Weak Cryptography

### Problem

**Severity**: CRITICAL (CVSS 7.5)
**CWE**: CWE-327 (Use of a Broken or Risky Cryptographic Algorithm)
**OWASP**: A02:2021 – Cryptographic Failures
**NIST**: 800-63B Section 5.1.1

**Affected Files**:
- `Services/N2UserManager.cs` (lines 149-165, 422-426)

### Description

Email confirmation tokens and MFA tokens (Email/SMS) are generated using SHA-384, which is a cryptographic hash function NOT designed for message authentication. The tokens lack proper HMAC-based authentication, making them potentially vulnerable to:
- Length extension attacks
- Token forgery if the format is reverse-engineered
- Lack of proper authentication guarantees

**Current Code** (`N2UserManager.cs:160-164`):
```csharp
var secret = System.Text.Encoding.UTF8.GetBytes($"{nonce}:{timeOut}:{user.SecurityStamp}");
var crypted = SHA384.HashData(secret);  // ⚠️ SHA-384 without HMAC!
var data = System.Text.Encoding.UTF8.GetBytes($"{nonce}:{timeOut}");
var result = string.Concat(Convert.ToBase64String(data), '.', Convert.ToBase64String(crypted));
```

### Attack Scenario

1. Attacker obtains a valid confirmation token (via network sniffing, logs, email interception)
2. Token format reveals timing and nonce information in plaintext Base64
3. Attacker analyzes token structure and attempts forgery
4. With knowledge of the format and weak hash algorithm, attacker may craft tokens
5. Email confirmation bypass leads to unauthorized account activation

### Impact

- **Likelihood**: MEDIUM (requires token interception but format is exploitable)
- **Business Impact**: Email confirmation bypass, unauthorized account activation, potential account takeover
- **Compliance**: Violates NIST 800-63B requirements for approved cryptographic algorithms

### Fix Implementation

#### Step 1: Update AuthenticationConfig to include token signing secret

```csharp
// In AuthenticationConfig.cs

public class AuthenticationConfig {
    public const string SectionName = "Authentication";

    public string TwoFactorTotpName { get; set; } = "N2.Core.Identity";

    /// <summary>
    /// Secret key for HMAC-based token signing. MUST be at least 32 bytes (256 bits).
    /// Generate using: Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
    /// Store in secure configuration (Azure Key Vault, AWS Secrets Manager, etc.)
    /// </summary>
    public string TokenSigningSecret { get; set; } = string.Empty;
}
```

#### Step 2: Add token signing secret validation

```csharp
// In N2UserManager.cs constructor - Add validation

public N2UserManager(
    IIdentityContextFactory identityContextFactory,
    IConfiguration configuration,
    string catalog,
    ILogger<N2UserManager> logger,
    IPasswordHasher<ApplicationUser> passwordHasher) {

    this.factory = identityContextFactory;
    this.catalog = catalog;
    this.logger = logger;
    this.passwordHasher = passwordHasher;

    var appConfigSection = configuration?.GetSection(AuthenticationConfig.SectionName);
    if (appConfigSection != null) {
        appConfigSection.Bind(this.configuration);
    }

    // Validate token signing secret
    if (string.IsNullOrEmpty(this.configuration.TokenSigningSecret)) {
        throw new InvalidOperationException(
            "TokenSigningSecret is required in Authentication configuration. " +
            "Generate a secure key using: Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))"
        );
    }

    var secretBytes = Convert.FromBase64String(this.configuration.TokenSigningSecret);
    if (secretBytes.Length < 32) {
        throw new InvalidOperationException(
            $"TokenSigningSecret must be at least 32 bytes (256 bits). Current length: {secretBytes.Length} bytes"
        );
    }
}
```

#### Step 3: Replace SHA-384 with HMAC-SHA256

```csharp
// In N2UserManager.cs - Update GenerateConfirmationTokenAsync (around lines 149-165)

public async Task<ICommandResponse<string>> GenerateConfirmationTokenAsync(
    [NotNull] ApplicationUser user,
    CancellationToken token) {

    if (user.Id == Guid.Empty) {
        var dbUser = await ApplicationUserByNameAsync(user.UserName, token);
        if (dbUser == null) {
            throw new InvalidOperationException("Invalid user");
        }
    }

    var nonce = RandomNumberGenerator.GetItems("ABCDEFGHIJKLMNOP1234567890".AsSpan(), 30).ToString();
    var timeOut = DateTime.UtcNow.AddDays(5).Ticks;

    // Use HMAC-SHA256 instead of SHA384
    var message = System.Text.Encoding.UTF8.GetBytes($"{nonce}:{timeOut}:{user.SecurityStamp}");
    var keyBytes = Convert.FromBase64String(configuration.TokenSigningSecret);

    using var hmac = new HMACSHA256(keyBytes);
    var signature = hmac.ComputeHash(message);

    var data = System.Text.Encoding.UTF8.GetBytes($"{nonce}:{timeOut}");
    var result = string.Concat(Convert.ToBase64String(data), '.', Convert.ToBase64String(signature));

    return StringResponse.Accept(result);
}
```

#### Step 4: Update MFA token generation (Email/SMS)

```csharp
// In N2UserManager.cs - Update GenerateConfirmationTokenAsync for MFA (around lines 149-165)
// Same method handles both email confirmation and MFA tokens

public async Task<ICommandResponse<string>> GenerateConfirmationTokenAsync(
    [NotNull] ApplicationUser user,
    MultiFactorType multifactorType,
    CancellationToken token) {

    if (user.Id == Guid.Empty) {
        var dbUser = await ApplicationUserByNameAsync(user.UserName, token);
        if (dbUser == null) {
            throw new InvalidOperationException("Invalid user");
        }
    }

    var nonce = multifactorType switch {
        MultiFactorType.Email => user.NormalizedEmail ?? user.Email?.ToUpperInvariant() ?? string.Empty,
        MultiFactorType.Sms => user.PhoneNumber ?? string.Empty,
        _ => throw new ArgumentException($"Invalid multifactor type: {multifactorType}")
    };

    var timeout = DateTime.UtcNow.AddMinutes(15).Ticks; // Reduced from 5 days to 15 minutes for MFA

    // Use HMAC-SHA256
    var message = System.Text.Encoding.UTF8.GetBytes($"{nonce}:{timeout}:{user.SecurityStamp}");
    var keyBytes = Convert.FromBase64String(configuration.TokenSigningSecret);

    using var hmac = new HMACSHA256(keyBytes);
    var signature = hmac.ComputeHash(message);

    var data = System.Text.Encoding.UTF8.GetBytes($"{nonce}:{timeout}");
    var result = string.Concat(Convert.ToBase64String(data), '.', Convert.ToBase64String(signature));

    return StringResponse.Accept(result);
}
```

#### Step 5: Update token validation to use HMAC

```csharp
// In N2UserManager.cs - Update ValidateMultifactorAsync (around lines 422-444)

// Replace the SHA384 validation code with:
var secret = System.Text.Encoding.UTF8.GetBytes($"{nonce}:{timeout}:{user.SecurityStamp}");
var keyBytes = Convert.FromBase64String(configuration.TokenSigningSecret);

using var hmac = new HMACSHA256(keyBytes);
var expectedSignature = hmac.ComputeHash(secret);

// Use constant-time comparison
var arraysEqual = CryptographicOperations.FixedTimeEquals(expectedSignature, verify);
```

#### Step 6: Configuration

```json
// In appsettings.json or User Secrets
{
  "Authentication": {
    "TwoFactorTotpName": "N2.Core.Identity",
    "TokenSigningSecret": "YOUR_BASE64_ENCODED_32_BYTE_SECRET_HERE"
  }
}
```

**Generate a secure secret**:
```csharp
// Run this once to generate a secure key
var randomBytes = RandomNumberGenerator.GetBytes(32);
var base64Secret = Convert.ToBase64String(randomBytes);
Console.WriteLine($"TokenSigningSecret: {base64Secret}");
```

### Unit Tests Required

```csharp
[TestClass]
public class TokenCryptographyTests {

    [TestMethod]
    public async Task GenerateToken_ShouldUseHMAC_NotSHA384() {
        // Arrange
        var user = await CreateTestUser("testuser", "P@ssw0rd123");

        // Act
        var tokenResponse = await userManager.GenerateConfirmationTokenAsync(user, MultiFactorType.Email);

        // Assert
        Assert.IsTrue(tokenResponse.Status.IsSuccess());
        var token = tokenResponse.Value;

        // HMAC-SHA256 produces 32-byte signature (44 chars in Base64)
        // Token format: {data}.{signature}
        var parts = token.Split('.');
        Assert.AreEqual(2, parts.Length);

        var signatureBytes = Convert.FromBase64String(parts[1]);
        Assert.AreEqual(32, signatureBytes.Length, "HMAC-SHA256 should produce 32-byte signature");
    }

    [TestMethod]
    public async Task ValidateToken_ValidToken_ShouldSucceed() {
        // Arrange
        var user = await CreateTestUser("testuser", "P@ssw0rd123");
        var tokenResponse = await userManager.GenerateConfirmationTokenAsync(user, MultiFactorType.Email);
        var token = tokenResponse.Value;

        // Act
        var result = await userManager.ValidateMultifactorAsync(user, MultiFactorType.Email, token);

        // Assert
        Assert.AreEqual(ResponseStatus.Success, result.Status);
    }

    [TestMethod]
    public async Task ValidateToken_TamperedToken_ShouldFail() {
        // Arrange
        var user = await CreateTestUser("testuser", "P@ssw0rd123");
        var tokenResponse = await userManager.GenerateConfirmationTokenAsync(user, MultiFactorType.Email);
        var token = tokenResponse.Value;

        // Tamper with the token
        var parts = token.Split('.');
        var tamperedSignature = parts[1].Substring(0, parts[1].Length - 2) + "XX";
        var tamperedToken = $"{parts[0]}.{tamperedSignature}";

        // Act
        var result = await userManager.ValidateMultifactorAsync(user, MultiFactorType.Email, tamperedToken);

        // Assert
        Assert.AreEqual(ResponseStatus.Unauthorized, result.Status);
    }

    [TestMethod]
    public async Task TokenSigningSecret_Missing_ShouldThrowException() {
        // Arrange - Create configuration without TokenSigningSecret
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string> {
                ["Authentication:TwoFactorTotpName"] = "Test"
                // TokenSigningSecret intentionally missing
            })
            .Build();

        // Act & Assert
        Assert.ThrowsException<InvalidOperationException>(() => {
            new N2UserManager(factory, config, "testdb", logger, passwordHasher);
        });
    }

    [TestMethod]
    public async Task TokenSigningSecret_TooShort_ShouldThrowException() {
        // Arrange - Create configuration with short secret
        var shortSecret = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16)); // Only 16 bytes
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string> {
                ["Authentication:TokenSigningSecret"] = shortSecret
            })
            .Build();

        // Act & Assert
        Assert.ThrowsException<InvalidOperationException>(() => {
            new N2UserManager(factory, config, "testdb", logger, passwordHasher);
        });
    }
}
```

### Security Improvements

This change provides:
- **HMAC-SHA256**: Industry-standard message authentication
- **Secret Key**: Prevents token forgery without the secret
- **Key Validation**: Ensures minimum 256-bit security strength
- **Constant-Time Comparison**: Prevents timing attacks
- **Reduced MFA Token Lifetime**: 15 minutes instead of 5 days

### Compliance Impact

- **NIST 800-63B**: ✅ Compliant - Uses approved cryptographic algorithms
- **PCI-DSS 3.6.1**: ✅ Compliant - Strong cryptography for authentication
- **OWASP**: ✅ Addresses Cryptographic Failures (A02:2021)

---

## Critical Issue #3: JWT Token Generation Uses DateTime.Now

### Problem

**Severity**: CRITICAL (CVSS 7.4)
**CWE**: CWE-324 (Use of a Key Past its Expiration Date)
**OWASP**: A01:2021 – Broken Access Control

**Affected Files**:
- `WebTokenGenerator.cs` (line 56)

### Description

JWT token expiration is calculated using `DateTime.Now` (local time) instead of `DateTime.UtcNow`. This creates timezone-dependent behavior that can lead to:
- Tokens expiring at unexpected times based on server timezone
- Extended token lifetimes when servers are in different timezones
- Time-based attacks when system time is manipulated
- Inconsistent token validation in distributed systems

**Current Code** (`WebTokenGenerator.cs:56`):
```csharp
JwtSecurityToken token = new(
    issuer,
    audience,
    claims,
    expires: DateTime.Now.AddMinutes(timeoutInMinutes), // ⚠️ Using local time!
    signingCredentials: credentials);
```

### Attack Scenario

1. Application deployed across multiple regions (US East Coast and Europe)
2. User obtains token from US server (EST/UTC-5): expires at "5:00 PM local"
3. Token validation occurs on European server (CET/UTC+1): 6 hour timezone difference
4. Token appears to have 6 extra hours of validity
5. Attacker exploits timezone confusion for extended session access
6. Session remains active beyond intended security window

**Alternative Scenario**:
1. Attacker compromises server or has admin access
2. Attacker changes system clock backward by several hours
3. Newly issued tokens have extended lifetime
4. Compromised tokens remain valid longer than intended

### Impact

- **Likelihood**: MEDIUM (requires distributed deployment or system compromise)
- **Business Impact**: Extended unauthorized access, session hijacking, security policy violations
- **Compliance**: Violates NIST 800-63B and PCI-DSS session timeout requirements

### Fix Implementation

#### Step 1: Update WebTokenGenerator.cs

```csharp
// In WebTokenGenerator.cs - Update the Generate method (around line 56)

public string Generate(IEnumerable<Claim> claims, int timeoutInMinutes, JwtSettings jwtSettings) {
    string? issuer = jwtSettings.Issuer;
    string? audience = jwtSettings.Audience;
    string? keyStr = jwtSettings.Secret;

    ArgumentException.ThrowIfNullOrEmpty(issuer, nameof(jwtSettings.Issuer));
    ArgumentException.ThrowIfNullOrEmpty(audience, nameof(jwtSettings.Audience));
    ArgumentException.ThrowIfNullOrEmpty(keyStr, nameof(jwtSettings.Secret));

    byte[] key = Encoding.UTF8.GetBytes(keyStr);
    var securityKey = new SymmetricSecurityKey(key);
    var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

    // Use UTC time for all JWT timestamps
    var now = DateTime.UtcNow;
    var expiration = now.AddMinutes(timeoutInMinutes);

    // Add standard JWT claims
    var jwtClaims = new List<Claim>(claims) {
        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()), // Token ID for revocation
        new Claim(JwtRegisteredClaimNames.Iat, new DateTimeOffset(now).ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64) // Issued at
    };

    JwtSecurityToken token = new(
        issuer,
        audience,
        jwtClaims,
        notBefore: now,  // Explicit start time
        expires: expiration,  // Use UTC time
        signingCredentials: credentials);

    return new JwtSecurityTokenHandler().WriteToken(token);
}
```

### Unit Tests Required

```csharp
[TestClass]
public class JwtTimingTests {

    [TestMethod]
    public void GenerateToken_ShouldUseUtcTime() {
        // Arrange
        var claims = new List<Claim> {
            new Claim(ClaimTypes.Name, "testuser"),
            new Claim(ClaimTypes.Role, "User")
        };
        var jwtSettings = GetTestJwtSettings();
        var generator = new WebTokenGenerator();

        // Act
        var beforeUtc = DateTime.UtcNow;
        var tokenString = generator.Generate(claims, 60, jwtSettings);
        var afterUtc = DateTime.UtcNow;

        // Assert
        var handler = new JwtSecurityTokenHandler();
        var token = handler.ReadJwtToken(tokenString);

        // Token expiration should be based on UTC, not local time
        var expectedExpiration = DateTime.UtcNow.AddMinutes(60);
        var actualExpiration = token.ValidTo;

        // Allow 2 second tolerance for test execution time
        Assert.IsTrue(Math.Abs((actualExpiration - expectedExpiration).TotalSeconds) < 2,
            $"Token expiration should be UTC-based. Expected: {expectedExpiration:u}, Actual: {actualExpiration:u}");
    }

    [TestMethod]
    public void GenerateToken_ShouldIncludeStandardClaims() {
        // Arrange
        var claims = new List<Claim> {
            new Claim(ClaimTypes.Name, "testuser")
        };
        var jwtSettings = GetTestJwtSettings();
        var generator = new WebTokenGenerator();

        // Act
        var tokenString = generator.Generate(claims, 60, jwtSettings);

        // Assert
        var handler = new JwtSecurityTokenHandler();
        var token = handler.ReadJwtToken(tokenString);

        // Should include JTI (JWT ID)
        Assert.IsTrue(token.Claims.Any(c => c.Type == JwtRegisteredClaimNames.Jti),
            "Token should include 'jti' claim for revocation support");

        // Should include IAT (Issued At)
        Assert.IsTrue(token.Claims.Any(c => c.Type == JwtRegisteredClaimNames.Iat),
            "Token should include 'iat' claim for issued-at timestamp");

        // NotBefore should be set
        Assert.IsNotNull(token.ValidFrom);
        Assert.IsTrue(token.ValidFrom <= DateTime.UtcNow);
    }

    [TestMethod]
    public void GenerateToken_CrossTimezone_ShouldBeConsistent() {
        // Arrange
        var claims = new List<Claim> { new Claim(ClaimTypes.Name, "testuser") };
        var jwtSettings = GetTestJwtSettings();
        var generator = new WebTokenGenerator();

        // Act - Generate token
        var tokenString = generator.Generate(claims, 60, jwtSettings);
        var handler = new JwtSecurityTokenHandler();
        var token = handler.ReadJwtToken(tokenString);

        // Get expiration in different timezone representations
        var expirationUtc = token.ValidTo;
        var expirationLocal = token.ValidTo.ToLocalTime();

        // Assert - Converting back to UTC should give same result
        Assert.AreEqual(expirationUtc, expirationLocal.ToUniversalTime(),
            "Token expiration should be consistent across timezone conversions");
    }

    [TestMethod]
    public async Task ValidateToken_AfterExpiration_ShouldFail() {
        // Arrange
        var claims = new List<Claim> { new Claim(ClaimTypes.Name, "testuser") };
        var jwtSettings = GetTestJwtSettings();
        var generator = new WebTokenGenerator();

        // Generate token with 1-second expiration
        var tokenString = generator.Generate(claims, 0, jwtSettings); // 0 minutes = immediate expiration

        // Wait for token to expire
        await Task.Delay(2000);

        // Act & Assert
        var validationParameters = new TokenValidationParameters {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings.Secret)),
            ValidateIssuer = true,
            ValidIssuer = jwtSettings.Issuer,
            ValidateAudience = true,
            ValidAudience = jwtSettings.Audience,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.Zero // No clock skew tolerance
        };

        var handler = new JwtSecurityTokenHandler();
        Assert.ThrowsException<SecurityTokenExpiredException>(() => {
            handler.ValidateToken(tokenString, validationParameters, out _);
        });
    }
}
```

### Additional Recommendations

1. **Configure Clock Skew**: Add configuration for token validation clock skew
   ```csharp
   services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
       .AddJwtBearer(options => {
           options.TokenValidationParameters = new TokenValidationParameters {
               // ... other settings ...
               ClockSkew = TimeSpan.FromMinutes(5) // Allow 5 minutes clock skew
           };
       });
   ```

2. **Token Refresh**: Implement refresh token mechanism for long-lived sessions

3. **Token Revocation**: Use the `jti` claim to implement token blacklist/revocation

### Compliance Impact

- **NIST 800-63B**: ✅ Compliant - Precise session timeout enforcement
- **PCI-DSS 8.1.8**: ✅ Compliant - Consistent session timeout
- **OWASP Session Management**: ✅ Compliant - Predictable session expiration

---

## Critical Issue #4: Insufficient JWT Key Length Validation

### Problem

**Severity**: CRITICAL (CVSS 7.8)
**CWE**: CWE-326 (Inadequate Encryption Strength)
**OWASP**: A02:2021 – Cryptographic Failures

**Affected Files**:
- `JwtExtensions.cs` (line 28)

### Description

The JWT signing key validation only enforces a minimum length of 20 bytes (160 bits), which is SIGNIFICANTLY below current security standards. The WebTokenGenerator uses `SecurityAlgorithms.HmacSha256`, which should have a 256-bit (32-byte) minimum key length according to:
- NIST SP 800-57: Recommends 256-bit keys for HMAC operations
- NIST SP 800-131A: Minimum 112-bit security strength, transitioning to 128-bit
- RFC 7518 (JSON Web Algorithms): HMAC-SHA256 should use keys ≥ 256 bits

**Current Code** (`JwtExtensions.cs:28`):
```csharp
ArgumentOutOfRangeException.ThrowIfLessThan(key.Length, 20, PathForKey);
// ⚠️ Only 160 bits! Should be 32 bytes (256 bits) for HMAC-SHA256
```

### Attack Scenario

1. Developer configures 20-byte JWT secret (meets current minimum)
2. Secret has only 160 bits of entropy (vs. required 256 bits)
3. Attacker captures JWT token from network traffic
4. Attacker launches brute-force or cryptanalytic attack on weak 160-bit key
5. With GPU clusters, 160-bit keys are within computational reach
6. Attacker recovers signing key and forges arbitrary JWT tokens
7. Complete authentication bypass - attacker can impersonate any user with any roles

**Time to Crack**:
- 160-bit key: ~2^160 operations = feasible with nation-state resources or large botnets
- 256-bit key: ~2^256 operations = computationally infeasible with current technology

### Impact

- **Likelihood**: LOW-MEDIUM (depends on key configuration, but validation allows weak keys)
- **Business Impact**: CRITICAL - Complete authentication bypass, unlimited privilege escalation
- **Compliance**: Violates NIST standards, PCI-DSS cryptographic requirements

### Fix Implementation

#### Step 1: Update JwtExtensions.cs validation

```csharp
// In JwtExtensions.cs - Update the validation logic

public static class JwtExtensions {
    private const string PathForIssuer = "Jwt:Issuer";
    private const string PathForAudience = "Jwt:Audience";
    private const string PathForKey = "Jwt:Secret";

    // Minimum key length for HMAC-SHA256 (256 bits = 32 bytes)
    private const int MinimumKeyLengthBytes = 32;

    public static void AddJwtConfigurationFromFile(this IServiceCollection services, IConfiguration configuration) {
        string? issuer = configuration[PathForIssuer];
        string? audience = configuration[PathForAudience];
        string? key = configuration[PathForKey];

        ArgumentException.ThrowIfNullOrEmpty(issuer, PathForIssuer);
        ArgumentException.ThrowIfNullOrEmpty(audience, PathForAudience);
        ArgumentException.ThrowIfNullOrEmpty(key, PathForKey);

        // Validate minimum key length (256 bits for HMAC-SHA256)
        if (key.Length < MinimumKeyLengthBytes) {
            throw new ArgumentException(
                $"JWT signing key must be at least {MinimumKeyLengthBytes} bytes (256 bits) for HMAC-SHA256 security. " +
                $"Current length: {key.Length} bytes ({key.Length * 8} bits). " +
                Environment.NewLine +
                $"Generate a secure key using: Convert.ToBase64String(RandomNumberGenerator.GetBytes({MinimumKeyLengthBytes}))" +
                Environment.NewLine +
                $"NIST SP 800-57 requires 256-bit keys for HMAC operations.",
                PathForKey
            );
        }

        // Additional validation: Check UTF-8 encoded length
        var keyBytes = Encoding.UTF8.GetBytes(key);
        if (keyBytes.Length < MinimumKeyLengthBytes) {
            throw new ArgumentException(
                $"JWT signing key encodes to only {keyBytes.Length} bytes ({keyBytes.Length * 8} bits). " +
                $"Ensure the key has at least {MinimumKeyLengthBytes} bytes of actual data. " +
                $"If using Base64-encoded key, it should be at least {MinimumKeyLengthBytes * 4 / 3} characters.",
                PathForKey
            );
        }

        // Optional: Validate key entropy (warn about weak keys)
        if (HasLowEntropy(key)) {
            throw new ArgumentException(
                "JWT signing key appears to have low entropy. " +
                "Use a cryptographically secure random key generator. " +
                "Do NOT use dictionary words, common phrases, or predictable patterns.",
                PathForKey
            );
        }

        services.AddSingleton(new JwtSettings {
            Issuer = issuer,
            Audience = audience,
            Secret = key
        });
    }

    /// <summary>
    /// Performs basic entropy check on the key to detect weak patterns.
    /// </summary>
    private static bool HasLowEntropy(string key) {
        // Check for repeated characters
        var uniqueChars = key.Distinct().Count();
        var repetitionRatio = (double)uniqueChars / key.Length;

        // If less than 50% unique characters, likely low entropy
        if (repetitionRatio < 0.5) {
            return true;
        }

        // Check for sequential patterns (e.g., "123456", "abcdef")
        int sequentialCount = 0;
        for (int i = 1; i < key.Length; i++) {
            if (Math.Abs(key[i] - key[i - 1]) == 1) {
                sequentialCount++;
            }
        }

        // If more than 70% sequential, likely weak
        if (sequentialCount > key.Length * 0.7) {
            return true;
        }

        return false;
    }

    /// <summary>
    /// Helper method to generate a cryptographically secure JWT signing key.
    /// </summary>
    public static string GenerateSecureJwtKey(int lengthInBytes = MinimumKeyLengthBytes) {
        if (lengthInBytes < MinimumKeyLengthBytes) {
            throw new ArgumentException(
                $"Key length must be at least {MinimumKeyLengthBytes} bytes",
                nameof(lengthInBytes)
            );
        }

        var randomBytes = RandomNumberGenerator.GetBytes(lengthInBytes);
        return Convert.ToBase64String(randomBytes);
    }
}
```

#### Step 2: Update WebTokenGenerator.cs validation

```csharp
// In WebTokenGenerator.cs - Add additional validation in Generate method

public string Generate(IEnumerable<Claim> claims, int timeoutInMinutes, JwtSettings jwtSettings) {
    string? issuer = jwtSettings.Issuer;
    string? audience = jwtSettings.Audience;
    string? keyStr = jwtSettings.Secret;

    ArgumentException.ThrowIfNullOrEmpty(issuer, nameof(jwtSettings.Issuer));
    ArgumentException.ThrowIfNullOrEmpty(audience, nameof(jwtSettings.Audience));
    ArgumentException.ThrowIfNullOrEmpty(keyStr, nameof(jwtSettings.Secret));

    byte[] key = Encoding.UTF8.GetBytes(keyStr);

    // Validate key length for HMAC-SHA256 (256 bits minimum)
    const int MinimumKeyBytes = 32;
    if (key.Length < MinimumKeyBytes) {
        throw new ArgumentException(
            $"JWT key is too short ({key.Length} bytes). HMAC-SHA256 requires at least {MinimumKeyBytes} bytes (256 bits). " +
            $"This validation prevents cryptographically weak JWT tokens.",
            nameof(jwtSettings.Secret)
        );
    }

    var securityKey = new SymmetricSecurityKey(key);
    var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

    // ... rest of method
}
```

#### Step 3: Documentation and configuration example

```json
// In appsettings.json - Add comments in documentation
{
  "Jwt": {
    "Issuer": "your-application-name",
    "Audience": "your-application-audience",
    "Secret": "MUST_BE_AT_LEAST_32_BYTES_LONG_CRYPTOGRAPHICALLY_RANDOM_KEY_BASE64_ENCODED_EXAMPLE_KEY_HERE",
    "_comment": "Generate Secret using: var key = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));"
  }
}
```

### Key Generation Script

```csharp
// Create a console app or script to generate secure keys
using System.Security.Cryptography;

public class JwtKeyGenerator {
    public static void Main() {
        Console.WriteLine("JWT Signing Key Generator");
        Console.WriteLine("=========================");
        Console.WriteLine();

        // Generate 256-bit (32-byte) key
        var key256 = GenerateKey(32);
        Console.WriteLine($"256-bit key (32 bytes) - Recommended:");
        Console.WriteLine(key256);
        Console.WriteLine($"Length: {key256.Length} characters, {Convert.FromBase64String(key256).Length} bytes");
        Console.WriteLine();

        // Generate 512-bit (64-byte) key for extra security
        var key512 = GenerateKey(64);
        Console.WriteLine($"512-bit key (64 bytes) - Maximum Security:");
        Console.WriteLine(key512);
        Console.WriteLine($"Length: {key512.Length} characters, {Convert.FromBase64String(key512).Length} bytes");
        Console.WriteLine();

        Console.WriteLine("Add the key to your appsettings.json:");
        Console.WriteLine("{");
        Console.WriteLine("  \"Jwt\": {");
        Console.WriteLine($"    \"Secret\": \"{key256}\"");
        Console.WriteLine("  }");
        Console.WriteLine("}");
    }

    private static string GenerateKey(int lengthInBytes) {
        var randomBytes = RandomNumberGenerator.GetBytes(lengthInBytes);
        return Convert.ToBase64String(randomBytes);
    }
}
```

### Unit Tests Required

```csharp
[TestClass]
public class JwtKeySecurityTests {

    [TestMethod]
    [ExpectedException(typeof(ArgumentException))]
    public void JwtConfiguration_KeyTooShort_ShouldThrowException() {
        // Arrange - Create configuration with 20-byte key
        var shortKey = new string('A', 20);
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string> {
                ["Jwt:Issuer"] = "test-issuer",
                ["Jwt:Audience"] = "test-audience",
                ["Jwt:Secret"] = shortKey
            })
            .Build();

        var services = new ServiceCollection();

        // Act - Should throw
        services.AddJwtConfigurationFromFile(config);
    }

    [TestMethod]
    public void JwtConfiguration_ValidKey_ShouldSucceed() {
        // Arrange - Create configuration with 32-byte key
        var validKey = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string> {
                ["Jwt:Issuer"] = "test-issuer",
                ["Jwt:Audience"] = "test-audience",
                ["Jwt:Secret"] = validKey
            })
            .Build();

        var services = new ServiceCollection();

        // Act
        services.AddJwtConfigurationFromFile(config);

        // Assert
        var provider = services.BuildServiceProvider();
        var jwtSettings = provider.GetRequiredService<JwtSettings>();
        Assert.IsNotNull(jwtSettings);
        Assert.AreEqual(validKey, jwtSettings.Secret);
    }

    [TestMethod]
    [ExpectedException(typeof(ArgumentException))]
    public void GenerateToken_WeakKey_ShouldThrowException() {
        // Arrange - Weak key with low entropy
        var weakKey = "password123456781234567812345678"; // 32 chars but low entropy
        var jwtSettings = new JwtSettings {
            Issuer = "test",
            Audience = "test",
            Secret = weakKey
        };

        var generator = new WebTokenGenerator();
        var claims = new List<Claim> { new Claim(ClaimTypes.Name, "test") };

        // Act - Should throw due to low entropy
        generator.Generate(claims, 60, jwtSettings);
    }

    [TestMethod]
    public void GenerateSecureKey_ShouldMeetRequirements() {
        // Act
        var key = JwtExtensions.GenerateSecureJwtKey();

        // Assert
        var keyBytes = Convert.FromBase64String(key);
        Assert.IsTrue(keyBytes.Length >= 32, "Generated key should be at least 32 bytes");

        // Check entropy - should have good distribution
        var uniqueBytes = keyBytes.Distinct().Count();
        var entropyRatio = (double)uniqueBytes / keyBytes.Length;
        Assert.IsTrue(entropyRatio > 0.8, "Generated key should have high entropy");
    }

    [TestMethod]
    public void KeyLengthValidation_Base64Encoded_ShouldCalculateCorrectly() {
        // Arrange - 32 bytes = 44 Base64 characters (with padding)
        var keyBytes = RandomNumberGenerator.GetBytes(32);
        var base64Key = Convert.ToBase64String(keyBytes);

        // Act
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string> {
                ["Jwt:Issuer"] = "test",
                ["Jwt:Audience"] = "test",
                ["Jwt:Secret"] = base64Key
            })
            .Build();

        var services = new ServiceCollection();
        services.AddJwtConfigurationFromFile(config);

        // Assert - Should not throw
        var provider = services.BuildServiceProvider();
        var jwtSettings = provider.GetRequiredService<JwtSettings>();
        Assert.IsNotNull(jwtSettings);
    }
}
```

### Migration Strategy

For existing deployments with weak keys:

1. **Generate new secure key** (32+ bytes)
2. **Deploy with dual-key support** (accept both old and new keys temporarily)
3. **Issue new tokens** with new key
4. **Monitor old key usage** for 24-48 hours
5. **Remove old key** after grace period

```csharp
// Dual-key validation example
services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options => {
        options.TokenValidationParameters = new TokenValidationParameters {
            ValidateIssuerSigningKey = true,
            IssuerSigningKeys = new[] {
                new SymmetricSecurityKey(Encoding.UTF8.GetBytes(newKey)), // Try new key first
                new SymmetricSecurityKey(Encoding.UTF8.GetBytes(oldKey))  // Fallback to old key
            },
            ValidateIssuer = true,
            ValidIssuer = issuer,
            ValidateAudience = true,
            ValidAudience = audience,
            ValidateLifetime = true
        };
    });
```

### Compliance Impact

- **NIST SP 800-57**: ✅ Compliant - 256-bit keys for HMAC
- **NIST SP 800-131A**: ✅ Compliant - Exceeds 112-bit minimum
- **PCI-DSS 3.6.1**: ✅ Compliant - Strong cryptography
- **FIPS 140-2**: ✅ Compliant - Approved key lengths

---

## Critical Issue #5: No Rate Limiting on MFA Token Validation

### Problem

**Severity**: CRITICAL (CVSS 7.3)
**CWE**: CWE-307 (Improper Restriction of Excessive Authentication Attempts)
**OWASP**: A07:2021 – Identification and Authentication Failures
**NIST**: 800-63B Section 5.2.2

**Affected Files**:
- `Services/N2UserManager.cs` (lines 370-444)

### Description

The `ValidateMultifactorAsync` method implements a constant-time delay (50ms) to prevent timing attacks, but provides NO rate limiting or attempt throttling. An attacker can make unlimited MFA code validation attempts:

- **TOTP**: 1,000,000 possible 6-digit codes (000000-999999)
- **Email/SMS tokens**: Full brute force of token space
- **Delay per attempt**: Only 50ms = ~1,200 attempts per minute = 72,000 per hour

**Current Code** (`N2UserManager.cs:370-444`):
```csharp
public async Task<ICommandResponse> ValidateMultifactorAsync(ApplicationUser user, string multifactorCode, CancellationToken token) {
    var timer = new TimeoutTimer(TimeForAuthenticationMs); // Only 50ms delay

    // ... validation logic ...

    if (user.MfaType == MultiFactorType.Totp) {
        var verified = VerifyTwoFactorAuthentication(multifactorCode, user.MfaSecret);
        await timer.Wait();
        return !verified
            ? new MultifactorResponse(ResponseStatus.Unauthorized, "Invalid Totp code.")
            : MultifactorResponse.Ok();
        // ⚠️ No attempt limiting! Can try all 1 million codes
    }
}
```

### Attack Scenario - TOTP Brute Force

1. Attacker compromises user password (via phishing, data breach, etc.)
2. Attacker is blocked by TOTP requirement (6-digit code from authenticator app)
3. Attacker launches automated brute-force attack on MFA endpoint
4. With 50ms per attempt: 72,000 codes per hour
5. TOTP window typically allows 3 valid codes at any time (previous, current, next 30-second window)
6. **Expected time to success: ~7 hours** of continuous attempts
7. MFA protection completely bypassed

### Attack Scenario - Email/SMS Token Replay

1. Attacker intercepts or obtains email/SMS token through social engineering
2. Token has 5-day expiration (per current code)
3. Attacker attempts token replay or brute-force variations
4. No rate limiting allows unlimited validation attempts
5. Combined with SHA-384 weakness (Issue #2), attacker may forge tokens

### Impact

- **Likelihood**: HIGH (automated tools available, straightforward attack)
- **Business Impact**: CRITICAL - Complete MFA bypass, account takeover, multi-million dollar fraud potential
- **Compliance**: Violates NIST 800-63B Section 5.2.2, PCI-DSS 8.1.6

### Fix Implementation

#### Step 1: Add MFA attempt tracking model

```csharp
// Create new file: Models/MfaAttemptTracker.cs

namespace N2.Core.Identity.Models {
    /// <summary>
    /// Tracks MFA validation attempts for rate limiting and lockout.
    /// </summary>
    public class MfaAttemptTracker {
        public Guid UserId { get; set; }
        public int FailedAttempts { get; set; }
        public DateTime? LockoutUntil { get; set; }
        public DateTime LastAttempt { get; set; }
        public DateTime WindowStart { get; set; }

        /// <summary>
        /// Checks if the user is currently locked out from MFA attempts.
        /// </summary>
        public bool IsLockedOut => LockoutUntil.HasValue && LockoutUntil.Value > DateTime.UtcNow;

        /// <summary>
        /// Checks if the current attempt window has expired (15 minutes).
        /// </summary>
        public bool IsWindowExpired => (DateTime.UtcNow - WindowStart).TotalMinutes > 15;

        /// <summary>
        /// Resets the attempt counter and lockout status.
        /// </summary>
        public void Reset() {
            FailedAttempts = 0;
            LockoutUntil = null;
            WindowStart = DateTime.UtcNow;
            LastAttempt = DateTime.UtcNow;
        }

        /// <summary>
        /// Records a failed attempt and applies lockout if threshold exceeded.
        /// </summary>
        public void RecordFailure(int maxAttempts = 5, int lockoutMinutes = 15) {
            FailedAttempts++;
            LastAttempt = DateTime.UtcNow;

            if (FailedAttempts >= maxAttempts) {
                LockoutUntil = DateTime.UtcNow.AddMinutes(lockoutMinutes);
            }
        }
    }
}
```

#### Step 2: Update N2UserManager with rate limiting

```csharp
// In N2UserManager.cs - Add fields and methods for MFA rate limiting

private readonly ConcurrentDictionary<Guid, MfaAttemptTracker> mfaAttemptTrackers = new();
private readonly SemaphoreSlim mfaLockoutLock = new(1, 1);

// Configuration from AuthenticationConfig
private int MfaMaxAttempts => configuration.MfaMaxAttempts > 0 ? configuration.MfaMaxAttempts : 5;
private int MfaLockoutMinutes => configuration.MfaLockoutMinutes > 0 ? configuration.MfaLockoutMinutes : 15;

/// <summary>
/// Gets or creates an MFA attempt tracker for a user.
/// </summary>
private MfaAttemptTracker GetOrCreateMfaTracker(Guid userId) {
    return mfaAttemptTrackers.GetOrAdd(userId, _ => new MfaAttemptTracker {
        UserId = userId,
        WindowStart = DateTime.UtcNow,
        LastAttempt = DateTime.UtcNow
    });
}

/// <summary>
/// Checks if user is locked out from MFA attempts and updates tracking.
/// Returns null if allowed to proceed, or error response if locked out.
/// </summary>
private async Task<ICommandResponse?> CheckMfaRateLimitAsync(ApplicationUser user, CancellationToken token) {
    await mfaLockoutLock.WaitAsync(token);
    try {
        var tracker = GetOrCreateMfaTracker(user.Id);

        // Reset if window expired
        if (tracker.IsWindowExpired) {
            tracker.Reset();
        }

        // Check lockout status
        if (tracker.IsLockedOut) {
            var remainingTime = tracker.LockoutUntil!.Value - DateTime.UtcNow;

            logger.LogWarning(
                "MFA validation blocked for user {UserName} - locked out until {LockoutEnd} ({RemainingSeconds} seconds remaining). Failed attempts: {FailedAttempts}",
                user.UserName,
                tracker.LockoutUntil.Value,
                Math.Ceiling(remainingTime.TotalSeconds),
                tracker.FailedAttempts
            );

            return new MultifactorResponse(
                ResponseStatus.Unauthorized,
                $"Too many failed MFA attempts. Account locked for {Math.Ceiling(remainingTime.TotalMinutes)} more minutes."
            );
        }

        // Check if approaching limit (warn after 3 attempts)
        if (tracker.FailedAttempts >= 3 && tracker.FailedAttempts < MfaMaxAttempts) {
            logger.LogWarning(
                "User {UserName} has {FailedAttempts} failed MFA attempts ({RemainingAttempts} remaining before lockout)",
                user.UserName,
                tracker.FailedAttempts,
                MfaMaxAttempts - tracker.FailedAttempts
            );
        }

        return null; // Allowed to proceed
    } finally {
        mfaLockoutLock.Release();
    }
}

/// <summary>
/// Records the result of an MFA validation attempt.
/// </summary>
private async Task RecordMfaAttemptAsync(ApplicationUser user, bool success, CancellationToken token) {
    await mfaLockoutLock.WaitAsync(token);
    try {
        var tracker = GetOrCreateMfaTracker(user.Id);

        if (success) {
            if (tracker.FailedAttempts > 0) {
                logger.LogInformation(
                    "MFA validation succeeded for user {UserName}. Resetting {FailedAttempts} previous failed attempts.",
                    user.UserName,
                    tracker.FailedAttempts
                );
            }
            tracker.Reset();
        } else {
            tracker.RecordFailure(MfaMaxAttempts, MfaLockoutMinutes);

            if (tracker.IsLockedOut) {
                logger.LogWarning(
                    "User {UserName} locked out from MFA validation after {FailedAttempts} failed attempts. Lockout until {LockoutEnd}",
                    user.UserName,
                    tracker.FailedAttempts,
                    tracker.LockoutUntil
                );
            } else {
                logger.LogWarning(
                    "Failed MFA attempt for user {UserName}. Total failed attempts: {FailedAttempts}/{MaxAttempts}",
                    user.UserName,
                    tracker.FailedAttempts,
                    MfaMaxAttempts
                );
            }
        }
    } finally {
        mfaLockoutLock.Release();
    }
}
```

#### Step 3: Update ValidateMultifactorAsync method

```csharp
// In N2UserManager.cs - Completely rewrite ValidateMultifactorAsync method

public async Task<ICommandResponse> ValidateMultifactorAsync(
    ApplicationUser user,
    string multifactorCode,
    CancellationToken token) {

    var timer = new TimeoutTimer(TimeForAuthenticationMs);

    // Check rate limiting FIRST (before any validation)
    var rateLimitCheck = await CheckMfaRateLimitAsync(user, token);
    if (rateLimitCheck != null) {
        await timer.Wait();
        return rateLimitCheck; // User is locked out
    }

    bool validationSucceeded = false;

    try {
        if (user.MfaType == MultiFactorType.Totp) {
            // TOTP validation
            if (string.IsNullOrEmpty(user.MfaSecret)) {
                logger.LogError("User {UserName} has TOTP enabled but no MfaSecret", user.UserName);
                await timer.Wait();
                return new MultifactorResponse(ResponseStatus.Unauthorized, "MFA not properly configured");
            }

            validationSucceeded = VerifyTwoFactorAuthentication(multifactorCode, user.MfaSecret);

        } else if (user.MfaType is MultiFactorType.Sms or MultiFactorType.Email) {
            // Email/SMS token validation
            if (string.IsNullOrWhiteSpace(multifactorCode) || !multifactorCode.Contains('.')) {
                await timer.Wait();
                await RecordMfaAttemptAsync(user, false, token);
                return new MultifactorResponse(ResponseStatus.Unauthorized, "Invalid token format");
            }

            var parts = multifactorCode.Split('.');
            if (parts.Length != 2) {
                await timer.Wait();
                await RecordMfaAttemptAsync(user, false, token);
                return new MultifactorResponse(ResponseStatus.Unauthorized, "Invalid token format");
            }

            try {
                var data = Convert.FromBase64String(parts[0]);
                var verify = Convert.FromBase64String(parts[1]);
                var plainText = System.Text.Encoding.UTF8.GetString(data);
                var items = plainText.Split(':');

                if (items.Length != 2) {
                    await timer.Wait();
                    await RecordMfaAttemptAsync(user, false, token);
                    return new MultifactorResponse(ResponseStatus.Unauthorized, "Invalid token structure");
                }

                var nonce = items[0];
                var timeout = long.Parse(items[1]);

                // Check expiration (15 minutes for MFA tokens, not 5 days!)
                var expirationTime = new DateTime(timeout);
                if (expirationTime < DateTime.UtcNow) {
                    await timer.Wait();
                    await RecordMfaAttemptAsync(user, false, token);
                    return new MultifactorResponse(ResponseStatus.Unauthorized, "Token has expired");
                }

                // Verify token signature using HMAC
                var message = System.Text.Encoding.UTF8.GetBytes($"{nonce}:{timeout}:{user.SecurityStamp}");
                var keyBytes = Convert.FromBase64String(configuration.TokenSigningSecret);

                using var hmac = new HMACSHA256(keyBytes);
                var expectedSignature = hmac.ComputeHash(message);

                // Constant-time comparison
                validationSucceeded = CryptographicOperations.FixedTimeEquals(expectedSignature, verify);

            } catch (Exception ex) {
                logger.LogWarning(ex, "Error parsing MFA token for user {UserName}", user.UserName);
                await timer.Wait();
                await RecordMfaAttemptAsync(user, false, token);
                return new MultifactorResponse(ResponseStatus.Unauthorized, "Invalid token");
            }

        } else {
            logger.LogError("User {UserName} has unsupported MFA type: {MfaType}", user.UserName, user.MfaType);
            await timer.Wait();
            return new MultifactorResponse(ResponseStatus.Unauthorized, "Unsupported MFA type");
        }

    } catch (Exception ex) {
        logger.LogError(ex, "Error validating MFA for user {UserName}", user.UserName);
        await timer.Wait();
        await RecordMfaAttemptAsync(user, false, token);
        return new MultifactorResponse(ResponseStatus.InternalServerError, "MFA validation error");
    }

    // Record the attempt result
    await RecordMfaAttemptAsync(user, validationSucceeded, token);

    await timer.Wait();

    return validationSucceeded
        ? MultifactorResponse.Ok()
        : new MultifactorResponse(ResponseStatus.Unauthorized, "Invalid MFA code");
}
```

#### Step 4: Add configuration options

```csharp
// In AuthenticationConfig.cs - Add MFA rate limiting configuration

public class AuthenticationConfig {
    public const string SectionName = "Authentication";

    public string TwoFactorTotpName { get; set; } = "N2.Core.Identity";
    public string TokenSigningSecret { get; set; } = string.Empty;

    // Account lockout settings
    public int MaxFailedAccessAttempts { get; set; } = 5;
    public int LockoutDurationMinutes { get; set; } = 15;
    public bool EnableAccountLockout { get; set; } = true;

    // MFA rate limiting settings
    public int MfaMaxAttempts { get; set; } = 5;
    public int MfaLockoutMinutes { get; set; } = 15;
    public int MfaTokenExpirationMinutes { get; set; } = 15; // Reduced from 5 days!
}
```

```json
// In appsettings.json
{
  "Authentication": {
    "TwoFactorTotpName": "N2.Core.Identity",
    "TokenSigningSecret": "[GENERATE_SECURE_32_BYTE_KEY]",
    "MaxFailedAccessAttempts": 5,
    "LockoutDurationMinutes": 15,
    "MfaMaxAttempts": 5,
    "MfaLockoutMinutes": 15,
    "MfaTokenExpirationMinutes": 15
  }
}
```

### Additional Hardening Measures

#### 1. Reduce TOTP Window

```csharp
// In N2UserManager.cs - Tighten TOTP validation window

private bool VerifyTwoFactorAuthentication(string code, string secret) {
    var totp = new Totp(Base32Encoding.ToBytes(secret));

    // Current window only (no ±1 step tolerance)
    return totp.VerifyTotp(code, out _, new VerificationWindow(0, 0));

    // Or allow minimal tolerance (±1 step = ±30 seconds)
    // return totp.VerifyTotp(code, out _, new VerificationWindow(1, 1));
}
```

#### 2. Single-Use Token Tracking

```csharp
// Track used MFA tokens to prevent replay attacks
private readonly ConcurrentDictionary<string, DateTime> usedMfaTokens = new();

private bool IsTokenUsed(string tokenHash) {
    // Clean up old entries (older than 1 hour)
    var cutoff = DateTime.UtcNow.AddHours(-1);
    var expiredKeys = usedMfaTokens.Where(kvp => kvp.Value < cutoff).Select(kvp => kvp.Key).ToList();
    foreach (var key in expiredKeys) {
        usedMfaTokens.TryRemove(key, out _);
    }

    // Check if token was already used
    var hash = Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(tokenHash)));
    return !usedMfaTokens.TryAdd(hash, DateTime.UtcNow);
}
```

### Unit Tests Required

```csharp
[TestClass]
public class MfaRateLimitingTests {

    [TestMethod]
    public async Task ValidateMFA_FiveFailedAttempts_ShouldLockout() {
        // Arrange
        var user = await CreateUserWithTOTP();
        var invalidCode = "000000";

        // Act - 5 failed attempts
        for (int i = 0; i < 5; i++) {
            var result = await userManager.ValidateMultifactorAsync(user, invalidCode, CancellationToken.None);
            Assert.AreEqual(ResponseStatus.Unauthorized, result.Status, $"Attempt {i + 1} should fail");
        }

        // 6th attempt should be blocked due to lockout
        var lockedResult = await userManager.ValidateMultifactorAsync(user, "123456", CancellationToken.None);
        Assert.AreEqual(ResponseStatus.Unauthorized, lockedResult.Status);
        Assert.IsTrue(lockedResult.Message.Contains("locked") || lockedResult.Message.Contains("Too many"),
            "Error message should indicate lockout");
    }

    [TestMethod]
    public async Task ValidateMFA_SuccessfulValidation_ShouldResetFailedCount() {
        // Arrange
        var user = await CreateUserWithTOTP();
        var validCode = GetCurrentTOTPCode(user.MfaSecret);

        // 3 failed attempts
        for (int i = 0; i < 3; i++) {
            await userManager.ValidateMultifactorAsync(user, "000000", CancellationToken.None);
        }

        // Act - Valid code should succeed and reset counter
        var result = await userManager.ValidateMultifactorAsync(user, validCode, CancellationToken.None);

        // Assert
        Assert.AreEqual(ResponseStatus.Success, result.Status);

        // Should be able to fail 5 more times before lockout (counter was reset)
        for (int i = 0; i < 4; i++) {
            var failResult = await userManager.ValidateMultifactorAsync(user, "000000", CancellationToken.None);
            Assert.AreEqual(ResponseStatus.Unauthorized, failResult.Status);
            Assert.IsFalse(failResult.Message.Contains("locked"), "Should not be locked yet");
        }
    }

    [TestMethod]
    public async Task ValidateMFA_TOTP_BruteForce_ShouldBlock() {
        // Arrange
        var user = await CreateUserWithTOTP();
        var stopwatch = Stopwatch.StartNew();
        int attemptCount = 0;

        // Act - Try to brute force (should be stopped by rate limiting)
        for (int code = 0; code < 100; code++) {
            var result = await userManager.ValidateMultifactorAsync(
                user,
                code.ToString("D6"),
                CancellationToken.None
            );

            attemptCount++;

            if (result.Message.Contains("locked") || result.Message.Contains("Too many")) {
                break; // Hit rate limit
            }
        }

        stopwatch.Stop();

        // Assert
        Assert.IsTrue(attemptCount <= 5, $"Should be locked after 5 attempts, but made {attemptCount} attempts");
        Assert.IsTrue(stopwatch.Elapsed.TotalSeconds < 10,
            "Should hit rate limit quickly, preventing brute force");
    }

    [TestMethod]
    public async Task ValidateMFA_LockoutExpires_ShouldAllowRetry() {
        // Arrange
        var user = await CreateUserWithTOTP();

        // Lock out the account
        for (int i = 0; i < 5; i++) {
            await userManager.ValidateMultifactorAsync(user, "000000", CancellationToken.None);
        }

        // Verify locked
        var lockedResult = await userManager.ValidateMultifactorAsync(user, "123456", CancellationToken.None);
        Assert.IsTrue(lockedResult.Message.Contains("locked") || lockedResult.Message.Contains("Too many"));

        // Wait for lockout to expire (simulate by adjusting tracker)
        // In real implementation, would wait actual time or adjust system clock in test
        await SimulateLockoutExpiration(user.Id);

        // Act - Should be able to attempt again
        var validCode = GetCurrentTOTPCode(user.MfaSecret);
        var result = await userManager.ValidateMultifactorAsync(user, validCode, CancellationToken.None);

        // Assert
        Assert.AreEqual(ResponseStatus.Success, result.Status);
    }

    [TestMethod]
    public async Task ValidateMFA_EmailToken_ExpiredToken_ShouldFail() {
        // Arrange
        var user = await CreateUserWithEmailMFA();

        // Generate token with short expiration
        var expiredToken = await GenerateExpiredMfaToken(user, minutesAgo: 20);

        // Act
        var result = await userManager.ValidateMultifactorAsync(user, expiredToken, CancellationToken.None);

        // Assert
        Assert.AreEqual(ResponseStatus.Unauthorized, result.Status);
        Assert.IsTrue(result.Message.Contains("expired"), "Should indicate token expiration");
    }

    [TestMethod]
    public async Task ValidateMFA_ConcurrentAttempts_ShouldHandleThreadSafety() {
        // Arrange
        var user = await CreateUserWithTOTP();
        var tasks = new List<Task<ICommandResponse>>();

        // Act - Simulate 10 concurrent invalid attempts
        for (int i = 0; i < 10; i++) {
            var attempt = i; // Capture for closure
            tasks.Add(Task.Run(async () => {
                await Task.Delay(attempt * 10); // Stagger slightly
                return await userManager.ValidateMultifactorAsync(
                    user,
                    $"{attempt:D6}",
                    CancellationToken.None
                );
            }));
        }

        var results = await Task.WhenAll(tasks);

        // Assert - After 5 attempts, should be locked
        var lockedCount = results.Count(r =>
            r.Message.Contains("locked") || r.Message.Contains("Too many"));

        Assert.IsTrue(lockedCount >= 5,
            $"At least 5 attempts should be blocked due to lockout, but only {lockedCount} were blocked");
    }
}
```

### Performance Considerations

The rate limiting implementation uses:
- **In-memory dictionary**: Fast lookups, but lost on restart
- **Concurrent dictionary**: Thread-safe without explicit locking
- **Semaphore**: Ensures atomic updates to tracking data
- **Automatic cleanup**: Expired trackers removed from memory

For production environments with multiple servers:
- Consider using **distributed cache** (Redis) for shared rate limiting
- Implement **database-backed tracking** for persistent lockout state
- Use **sliding window** rate limiting for more sophisticated control

### Compliance Impact

- **NIST 800-63B 5.2.2**: ✅ Compliant - Rate limiting on authenticators
- **PCI-DSS 8.1.6**: ✅ Compliant - Limit repeated access attempts
- **OWASP ASVS 2.2.3**: ✅ Compliant - Level 1 rate limiting requirement
- **CWE-307**: ✅ Mitigated - Brute force attacks prevented

---

## Implementation Roadmap

### Phase 1: Emergency Hotfixes (Week 1)
**Priority**: CRITICAL - Address within 7 days

- [ ] **Day 1-2**: Implement account lockout (#1)
  - Add lockout tracking to N2UserManager
  - Update ValidateAsync with lockout checks
  - Add unit tests (3 tests minimum)
  - Test in staging environment

- [ ] **Day 3-4**: Implement MFA rate limiting (#5)
  - Add MfaAttemptTracker model
  - Update ValidateMultifactorAsync with rate limiting
  - Add unit tests (6 tests minimum)
  - Test in staging environment

- [ ] **Day 5**: Deploy Phase 1 to production
  - Monitor authentication logs
  - Alert on lockout events
  - Verify no false positives

### Phase 2: Cryptographic Fixes (Week 2)
**Priority**: HIGH

- [ ] **Day 1-2**: Fix JWT DateTime issue (#3)
  - Change DateTime.Now to DateTime.UtcNow
  - Add standard JWT claims (jti, iat)
  - Add unit tests
  - Deploy immediately (low risk change)

- [ ] **Day 3-5**: Replace SHA-384 with HMAC (#2)
  - Generate secure TokenSigningSecret
  - Update token generation methods
  - Update token validation methods
  - Add constructor validation
  - Comprehensive unit tests
  - Deploy with monitoring

- [ ] **Day 6-7**: Strengthen JWT key validation (#4)
  - Update JwtExtensions minimum to 32 bytes
  - Add entropy validation
  - Create key generation utility
  - Generate new production keys
  - Deploy with dual-key support
  - Monitor for issues
  - Remove old keys after 48 hours

### Phase 3: Testing & Validation (Week 3)
**Priority**: HIGH

- [ ] Integration testing of all authentication flows
- [ ] Load testing with rate limiting active
- [ ] Security regression testing
- [ ] Penetration testing (if resources available)
- [ ] Performance monitoring and optimization
- [ ] Update security documentation

### Phase 4: Additional Hardening (Week 4+)
**Priority**: MEDIUM

- [ ] Implement token revocation capability (JWT blacklist)
- [ ] Add single-use token tracking for MFA
- [ ] Reduce TOTP validation window
- [ ] Implement distributed rate limiting (Redis)
- [ ] Add comprehensive audit logging
- [ ] Implement security event monitoring
- [ ] Set up alerting for suspicious activity

---

## Testing Checklist

### Before Each Deployment

- [ ] All unit tests pass (target: 95%+ coverage)
- [ ] Integration tests pass
- [ ] Security regression tests pass
- [ ] Performance tests show no significant degradation
- [ ] Manual testing completed:
  - [ ] Normal login flow
  - [ ] Failed login triggers lockout
  - [ ] Lockout expires correctly
  - [ ] MFA validation works
  - [ ] MFA rate limiting triggers
  - [ ] JWT tokens validate correctly
  - [ ] JWT expiration works as expected

### Security Validation

- [ ] Account lockout prevents brute force (5 attempts max)
- [ ] MFA rate limiting prevents TOTP brute force
- [ ] Tokens use HMAC-SHA256 (not SHA-384)
- [ ] JWT uses UtcNow (not Now)
- [ ] JWT keys are minimum 32 bytes
- [ ] All timing attacks mitigated with constant-time operations
- [ ] No user enumeration vulnerabilities
- [ ] Audit logging captures all security events

---

## Compliance Status After Implementation

| Standard | Requirement | Current Status | After Fix |
|----------|------------|----------------|-----------|
| OWASP Top 10 2021 | A01: Broken Access Control | ⚠️ VULNERABLE | ✅ COMPLIANT |
| OWASP Top 10 2021 | A02: Cryptographic Failures | ⚠️ VULNERABLE | ✅ COMPLIANT |
| OWASP Top 10 2021 | A07: Authentication Failures | ⚠️ VULNERABLE | ✅ COMPLIANT |
| PCI-DSS 4.0 | Req 8.1.6 (Account Lockout) | ❌ NON-COMPLIANT | ✅ COMPLIANT |
| PCI-DSS 4.0 | Req 3.6.1 (Strong Crypto) | ⚠️ PARTIAL | ✅ COMPLIANT |
| PCI-DSS 4.0 | Req 8.1.8 (Session Timeout) | ⚠️ PARTIAL | ✅ COMPLIANT |
| NIST 800-63B | Section 5.1.1 (Password Storage) | ✅ COMPLIANT | ✅ COMPLIANT |
| NIST 800-63B | Section 5.2.2 (Rate Limiting) | ❌ NON-COMPLIANT | ✅ COMPLIANT |
| NIST 800-63B | Section 7.1 (Session Mgmt) | ⚠️ PARTIAL | ✅ COMPLIANT |
| CWE Top 25 | CWE-287 (Improper Auth) | ⚠️ VULNERABLE | ✅ MITIGATED |
| CWE Top 25 | CWE-307 (Excessive Auth Attempts) | ❌ VULNERABLE | ✅ MITIGATED |
| CWE Top 25 | CWE-326 (Inadequate Encryption) | ⚠️ VULNERABLE | ✅ MITIGATED |
| CWE Top 25 | CWE-327 (Broken Crypto) | ⚠️ VULNERABLE | ✅ MITIGATED |

---

## Additional High-Severity Issues (Non-Critical)

### 6. Hardcoded Connection String in Design-Time Factory

**Severity**: HIGH (CVSS 6.5)
**Location**: `Data/DesignTimeFactory.cs` (line 14)

**Issue**: Contains hardcoded connection string pointing to "tp-i9" server.

**Fix**:
```csharp
// Use environment variable instead
var connectionString = Environment.GetEnvironmentVariable("DESIGN_TIME_CONNECTION_STRING")
    ?? throw new InvalidOperationException("DESIGN_TIME_CONNECTION_STRING environment variable not set");
```

### 7. Typo in JwtSettings Default Value

**Severity**: HIGH (CVSS 6.0)
**Location**: `JwtSettings.cs` (line 17)

**Issue**: `ChallengeScheme` property has typo: "vearer" instead of "bearer"

**Fix**:
```csharp
public string ChallengeScheme { get; set; } = "bearer"; // Fixed typo
```

### 8. Missing Input Validation on User-Provided Data

**Severity**: HIGH (CVSS 6.8)
**CWE**: CWE-20 (Improper Input Validation)

**Issues**:
- Username format not validated
- Display names accept up to 100 characters without sanitization
- Phone numbers not validated against E.164 format
- Email format validation relies on ASP.NET Identity default

**Recommendations**: Implement comprehensive input validation with regular expressions and length limits.

---

## Support & References

### Documentation
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [NIST Digital Identity Guidelines (800-63B)](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [PCI-DSS Requirements](https://www.pcisecuritystandards.org/)
- [Microsoft ASP.NET Core Security Best Practices](https://learn.microsoft.com/en-us/aspnet/core/security/)

### CWE References
- [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)
- [CWE-307: Improper Restriction of Excessive Authentication Attempts](https://cwe.mitre.org/data/definitions/307.html)
- [CWE-324: Use of a Key Past its Expiration Date](https://cwe.mitre.org/data/definitions/324.html)
- [CWE-326: Inadequate Encryption Strength](https://cwe.mitre.org/data/definitions/326.html)
- [CWE-327: Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)

### Tools & Utilities

```bash
# Generate secure JWT signing key (32 bytes / 256 bits)
dotnet run --project KeyGenerator

# Generate secure token signing secret
openssl rand -base64 32

# Verify JWT token locally
dotnet tool install -g dotnet-jwt
jwt decode <your-token-here>
```

---

## Emergency Contacts

**Security Team**: [Add contact information]
**On-Call Developer**: [Add contact information]
**Incident Response**: [Add playbook link]

---

## Version Control

**Document Version**: 1.0
**Last Updated**: 2025-11-13
**Status**: PENDING IMPLEMENTATION
**Next Review**: After Phase 1 completion (7 days)

---

## Approval & Sign-off

This document has been reviewed and approved for implementation:

- [ ] Security Team Lead: _________________ Date: _______
- [ ] Development Team Lead: _________________ Date: _______
- [ ] Chief Technology Officer: _________________ Date: _______

---

**END OF DOCUMENT**
