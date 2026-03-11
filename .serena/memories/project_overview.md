# N2.Core.Identity - Project Overview

## Purpose
A modular identity and role management library for .NET built on top of ASP.NET Core Identity.
Provides a strongly-typed N2IdentityContext (extending IdentityDbContext) and a feature-rich N2UserManager for advanced user, role, and authentication scenarios.
Published as NuGet package: `N2.Core.Identity` v1.4.6 by Kaalenco.

## Tech Stack
- **Targets**: net8.0 and net10.0 (multi-targeted)
- **Language**: C# 12, nullable enabled, implicit usings enabled
- **Identity**: Microsoft.AspNetCore.Identity.EntityFrameworkCore
- **ORM**: Entity Framework Core with SQL Server + MySQL (MySql.EntityFrameworkCore)
- **Auth**: Microsoft.AspNetCore.Authentication.JwtBearer, System.IdentityModel.Tokens.Jwt
- **MFA**: Otp.NET (TOTP), QRCoder (QR codes)
- **Testing**: MSTest
- **CI/CD**: GitHub Actions → NuGet publish on trunk

## Solution Structure
```
src/
  N2.Core.Identity/              # Main library
    Data/                        # ApplicationUser, N2IdentityContext, factories, logging
    Services/                    # N2UserManager, RateLimiter, RateLimitTracker
    Commands/                    # ApplicationUserResponse, MultifactorResponse
    Migrations/                  # EF Core migrations
    Scripts/                     # SQL migration scripts (M00, M01, M02)
    N2AuthenticationService.cs   # IAuthenticator implementation
    WebTokenGenerator.cs         # JWT generation
    AuthenticationConfig.cs      # Config section
    JwtSettings.cs               # JWT settings
    AspNetUserContext.cs         # IUserContext implementation
    ClaimExtensions.cs
    JwtExtensions.cs
    TimeoutTimer.cs
    UserContextFactory.cs
  N2.Core.Identity.UnitTests/    # MSTest unit tests
    TestContext.cs               # DI setup, 310k PBKDF2 iterations
    N2AuthenticatorTests.cs      # Timing attack protection tests
    UserManagerTests.cs
    JwtSecurityTests.cs
    JwtTimingTests.cs
    LockoutTests.cs
    MfaRateLimitingTests.cs
    TokenCryptographyTests.cs
```

## Key Dependencies
- N2.Core.Abstractions 1.5.0 — base abstractions (ICommand, IResponse, etc.)
- User Secrets ID: `N2-Core-0c368d89-5cb3-4451-9c68-b79e69920a09`
