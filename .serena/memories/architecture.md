# Architecture Notes

## Core Components

### N2IdentityContext (`Data/N2IdentityContext.cs`)
- Extends `IdentityDbContext<ApplicationUser, ApplicationRole, Guid>`
- Implements `IIdentityContext`
- Includes change logging via concurrent queue (max 1000 entries)
- Health check functionality

### N2UserManager (`Services/N2UserManager.cs`)
- Implements `IUserManager<ApplicationUser>` (~824 lines)
- Factory-based context init with thread-safe lazy loading (semaphore)
- Key methods: CreateAsync, DeleteAsync, ValidateAsync, GenerateConfirmationTokenAsync, ConfirmEmailAsync, SetMultifactorAsync, ValidateMultifactorAsync, IncrementAccessFailedCountAsync, ResetAccessFailedCountAsync
- Rate limiting via RateLimiter/RateLimitTracker

### ApplicationUser (`Data/ApplicationUser.cs`)
- Extends `IdentityUser<Guid>`
- Extra: FirstName, LastName, MiddleName, DisplayName, ImagePath, MfaType, MfaConfirmed, MfaSecret

### N2AuthenticationService (`N2AuthenticationService.cs`)
- Implements `IAuthenticator`
- Validates credentials + lockout, returns `IUserContext` with roles

### WebTokenGenerator (`WebTokenGenerator.cs`)
- Generates JWT tokens (5-1440 min, debug: 14400 min)
- Claims: user ID, roles

## Key Patterns
- **Factory pattern**: `IIdentityContextFactory` creates DB contexts (multi-tenancy support)
- **Email confirmation tokens**: Base64(`{nonce}:{expirationTicks}`) + HMAC-SHA256 signature, 5-day expiry
- **MFA**: SMS, Email, TOTP (via Otp.NET + QRCoder)
- **Rate limiting**: Applied to authentication attempts (see RateLimiter.cs)

## Authentication Flow
1. Credentials → `N2AuthenticationService.AuthenticateAsync`
2. Validate username/password (constant-time)
3. Check lockout via `CanSignInAsync`
4. Retrieve roles from DB
5. Return `AspNetUserContext` with user + roles
6. JWT generated via `WebTokenGenerator`
