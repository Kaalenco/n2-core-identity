# N2.Core.Identity Security Audit Summary

**Date**: 2025-11-18
**Overall Security Posture**: MEDIUM RISK
**Findings**: 2 Critical, 4 High, 6 Medium, 3 Low

---

## Critical Issues (Immediate Action Required)

### 1. Password Hashing Configuration Verification Needed [DOCUMENTATION FIXED]
**File**: `src/N2.Core.Identity/Services/N2UserManager.cs:37-59`
**Risk**: Critical - Complete compromise of all user passwords if misconfigured

**Documentation Update** ✅: `CLAUDE.md` has been corrected to accurately state the system uses PBKDF2-HMAC-SHA256 via ASP.NET Core Identity's `PasswordHasher<ApplicationUser>`, not custom SHA384 hashing.

**Remaining Action**: Verify production configuration uses `PasswordHasher<ApplicationUser>` with proper iteration count (310,000 iterations per OWASP 2023):

```csharp
// Required production configuration
var options = new PasswordHasherOptions {
    CompatibilityMode = PasswordHasherCompatibilityMode.IdentityV3,
    IterationCount = 310000 // OWASP 2023 minimum
};
```

**Note**: Unit tests in `TestContext.cs:41-45` show correct configuration with 310,000 iterations. Ensure production dependency injection mirrors this configuration.

### 2. Email Confirmation Token Uses Insufficient Entropy
**File**: `src/N2.Core.Identity/Services/N2UserManager.cs:210-223`
**Risk**: High - Email confirmation bypass, account takeover

Token nonce uses only 30 characters from a 36-character set. Use cryptographically secure random bytes instead:

```csharp
// Replace current implementation
var nonceBytes = RandomNumberGenerator.GetBytes(32); // 256 bits
var nonce = Convert.ToBase64String(nonceBytes);
```

---

## High Priority Issues

### 3. MFA Secrets Stored in Plain Text
**File**: `src/N2.Core.Identity/Data/ApplicationUser.cs:30-31`
**Risk**: High - Complete MFA bypass if database compromised

MFA TOTP secrets are stored unencrypted in the database. Database breach would allow attackers to generate valid MFA codes indefinitely.

**Recommendation**: Encrypt MFA secrets using ASP.NET Core Data Protection or SQL Server column-level encryption.

### 4. JWT Token Expiration Too Long
**File**: `src/N2.Core.Identity/WebTokenGenerator.cs:53-59`
**Risk**: High - Extended unauthorized access window

Tokens can live up to 24 hours (1440 minutes). Compromised tokens remain valid for entire duration with no revocation mechanism.

**Recommendation**:
- Reduce access token lifetime to 15 minutes
- Implement refresh token pattern for longer sessions
- Add token revocation capability

### 5. Security Stamp Not Rotated on Password/MFA Changes
**File**: `src/N2.Core.Identity/Services/N2UserManager.cs:313, 392`
**Risk**: High - Persistent unauthorized access after security events

Security stamp is rotated on email/username changes but NOT on password changes or MFA modifications. Existing sessions remain valid after password reset.

**Recommendation**: Add `RotateSecurityStamp()` call on all critical operations (password change, MFA changes, lockout).

### 6. User Enumeration via Timing and Response Differences [PARTIALLY RESOLVED]
**Files**:
- `src/N2.Core.Identity/N2AuthenticationService.cs:21-83`
- `src/N2.Core.Identity/TimeoutTimer.cs`
- `src/N2.Core.Identity/ClaimExtensions.cs:7-28`
- `src/N2.Core.Identity.UnitTests/N2AuthenticatorTests.cs:39-71`

**Risk**: High - Statistical timing analysis can still reveal username existence

**Implemented Mitigations** ✅:
- `TimeoutTimer` enforces 200ms minimum response time on all code paths
- Generic error messages (all failures return `null`, no distinguishing responses)
- Constant-time token comparison via `ArraysAreEqual` method
- Unit test `Authentication_ValidVsInvalidUser_ShouldHaveConstantTiming` validates timing consistency

**Remaining Vulnerability** ❌:
Password verification (100-500ms) is **skipped** for non-existent users, creating measurable timing difference despite 200ms minimum. Statistical analysis with 100+ attempts can detect this pattern.

**Required Actions**:
1. Implement dummy user pattern to perform password hashing for non-existent users:
   ```csharp
   if (user == null) {
       // Perform dummy password verification to match timing
       var dummyUser = new ApplicationUser {
           UserName = userLogin.Username,
           PasswordHash = "$2a$12$DUMMY_HASH_FOR_TIMING"
       };
       await userManager.ValidateAsync(dummyUser, userLogin.Password, token);
       await timer.Wait();
       return null;
   }
   ```
2. Tighten unit test threshold from 20% to 5% with 1000+ iterations
3. Verify fix effectiveness in production-like environment

---

## Medium Priority Issues

### 7. Insufficient Account Lockout Duration
**File**: `src/N2.Core.Identity/Services/N2UserManager.cs:709-710`

15-minute lockout after 5 failed attempts is too short for modern brute-force attacks. Implement progressive delays (1 hour → 4 hours → 24 hours).

### 8. Weak QR Code Error Correction
**File**: `src/N2.Core.Identity/Services/N2UserManager.cs:588`

QR codes use level Q (25% recovery). Change to level H (30%) for better reliability.

### 9. Missing Input Validation on User Properties
**File**: `src/N2.Core.Identity/Data/ApplicationUser.cs:11-24`

`DisplayName`, `FirstName`, `LastName` lack validation for malicious content (XSS, injection). Add regex validation and HTML encoding.

### 10. Semaphore Causing Potential Deadlocks
**File**: `src/N2.Core.Identity/Services/N2UserManager.cs:33, 456`

`Semaphore.WaitOne()` (blocking) used in async methods. Replace with `SemaphoreSlim` and `WaitAsync()`.

### 11. Inconsistent MFA Secret Sizes
**File**: `src/N2.Core.Identity/Services/N2UserManager.cs:132, 337`

MFA secrets vary between 32 bytes (user creation) and 10 bytes (TOTP setup). Standardize to 32 bytes.

### 12. Database Connection String Exposure Risk
**File**: `src/N2.Core.Identity/Data/N2IdentityContextFactory.cs`

Connection strings may be exposed in logs or error messages. Never log connection strings; use Azure Key Vault or AWS Secrets Manager.

---

## Low Priority Issues

13. **Hardcoded Timing Delays** - Make authentication delays configurable
14. **Missing XML Documentation** - Add security warnings to public methods
15. **Phone Number Validation** - Validate E.164 format for SMS MFA

---

## Positive Security Practices Identified

✅ **Timing Attack Mitigation** - Multiple implementations:
  - `TimeoutTimer` class enforces minimum response times (200ms auth, 50ms validation)
  - Constant-time token comparison via `ArraysAreEqual` method (`ClaimExtensions.cs:7-28`)
  - Unit tests validate timing consistency (`N2AuthenticatorTests.cs`)
  - Used across authentication, MFA validation, and token verification

✅ **JWT Key Validation** - Comprehensive entropy and length checks (`JwtExtensions.cs:83-104`)
  - Minimum 256-bit key length enforcement
  - Low entropy detection and sequential pattern validation
  - Clear error messages with remediation guidance

✅ **MFA Rate Limiting** - Robust implementation preventing brute force (`RateLimitTracker.cs`)
  - Configurable attempt thresholds (default: 5 attempts)
  - Configurable lockout duration (default: 15 minutes)
  - Thread-safe implementation with automatic window expiration

✅ **Account Lockout** - 5 failed attempts with 15-minute lockout
  - Failed attempt counter reset on successful authentication
  - Comprehensive logging of lockout events

✅ **ASP.NET Core Identity** - Built on battle-tested framework with regular security updates
  - PBKDF2-HMAC-SHA256 with 310,000 iterations (OWASP 2023 compliant)
  - Security stamp support for session invalidation

---

## Recommended Remediation Roadmap

### Week 1 (Critical)
- [x] ~~Verify password hasher configuration~~ - Documentation corrected, production verification needed
- [ ] Implement MFA secret encryption
- [ ] Fix email confirmation token generation
- [ ] Add security stamp rotation on password/MFA changes

### Weeks 2-3 (High)
- [ ] Implement refresh token pattern (15-min access tokens)
- [ ] Complete user enumeration fix (implement dummy user pattern)
- [ ] Tighten timing test threshold from 20% to 5%
- [ ] Add progressive lockout delays
- [ ] Replace Semaphore with SemaphoreSlim

### Weeks 4-6 (Medium)
- [ ] Standardize MFA secret sizes to 32 bytes
- [ ] Add input validation for user properties
- [ ] Implement token generation rate limiting
- [ ] Secure connection string handling

---

## Compliance Impact

| Standard | Status | Required Actions |
|----------|--------|------------------|
| OWASP Top 10 2021 | ⚠️ Partial | Fix A02 (Cryptographic Failures), A07 (Auth Failures) |
| NIST SP 800-63B | ⚠️ Partial | Verify password storage, improve session management |
| PCI-DSS 4.0 | ⚠️ Partial | Encrypt MFA secrets, validate password hashing |
| GDPR Article 32 | ⚠️ Partial | Implement encryption at rest |
| SOC 2 | ⚠️ Partial | Address logical access and confidential info handling |

---

## Next Steps

1. **Immediate**: Review Critical findings with development team
2. **Week 1**: Address all Critical issues
3. **Week 2**: Security training on OWASP Top 10
4. **Week 4**: Implement automated security testing in CI/CD
5. **Post-remediation**: Conduct third-party penetration test

---

**For detailed analysis and code examples, see the full security audit report.**
