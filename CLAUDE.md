# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

N2.Core.Identity is a modular identity and role management library for .NET built on top of ASP.NET Core Identity. It provides a strongly-typed N2IdentityContext (extending IdentityDbContext) and a feature-rich N2UserManager for advanced user, role, and authentication scenarios.

**Key Technologies:**
- Multi-targeted for .NET 8.0 and .NET 9.0
- ASP.NET Core Identity with Entity Framework Core
- SQL Server database provider
- JWT Bearer authentication
- MSTest for unit testing

## Build and Test Commands

**IMPORTANT**: Claude Code should NEVER run `dotnet build` or `dotnet test` commands automatically. Always ask the user to run these commands manually.

### Building the Project
```bash
# Restore dependencies
dotnet restore src

# Build (all targets)
dotnet build src

# Build without restore
dotnet build src --no-restore

# Build specific configuration
dotnet build src --configuration Release
```

### Running Tests
```bash
# Run all tests
dotnet test src

# Run tests without building
dotnet test src --no-build --verbosity normal

# Run a specific test by filter
dotnet test src --filter "FullyQualifiedName~N2.Core.Identity.UnitTests.N2UserManagerTests"

# Run a single test method
dotnet test src --filter "FullyQualifiedName=N2.Core.Identity.UnitTests.N2UserManagerTests.TestUserCreateAsync"
```

### Creating NuGet Package
```bash
# Build with package generation (configured in .csproj)
dotnet build src --configuration Release
```

## Architecture

### Core Components

**N2IdentityContext** (`Data/N2IdentityContext.cs`)
- Extends `IdentityDbContext<ApplicationUser, ApplicationRole, Guid>`
- Implements `IIdentityContext` interface
- Provides strongly-typed access to Users, Roles, and UserRoles
- Includes change logging via concurrent queue (max 1000 entries by default)
- Offers helper methods for common queries (FindByName, FindByEmail, CanSignIn, etc.)
- Health check functionality for database connectivity

**N2UserManager** (`Services/N2UserManager.cs`)
- Custom user manager implementing `IUserManager<ApplicationUser>`
- Handles user CRUD operations, email confirmation, role management
- Custom password hashing using SHA384 with username and security stamp
- Email confirmation tokens with 5-day expiration
- Multi-factor authentication support (SMS, Email, TOTP with QR code generation)
- Factory-based context initialization with thread-safe lazy loading

**ApplicationUser** (`Data/ApplicationUser.cs`)
- Extends `IdentityUser<Guid>`
- Custom properties: FirstName, LastName, MiddleName, DisplayName, ImagePath
- Multi-factor authentication properties: MfaType, MfaConfirmed, MfaSecret

**N2AuthenticationService** (`N2AuthenticationService.cs`)
- Implements `IAuthenticator` interface
- Validates user credentials and lockout status
- Returns `IUserContext` with user information and roles

**WebTokenGenerator** (`WebTokenGenerator.cs`)
- Generates JWT tokens with configurable timeout (5-1440 minutes)
- Debug mode allows extended timeout of 14400 minutes
- Includes user ID and roles as claims

### Database Context Factory Pattern

The library uses a factory pattern (`IIdentityContextFactory`) to create database contexts, allowing flexible connection string management and multi-tenancy support. The `N2UserManager` lazily initializes the context using a semaphore for thread safety.

### Authentication Flow

1. User credentials received via `IUserLogin`
2. `N2AuthenticationService.AuthenticateAsync` validates username/password
3. User lockout status checked via `CanSignInAsync`
4. Roles retrieved from database
5. `AspNetUserContext` returned with user details and roles
6. JWT token generated via `WebTokenGenerator` with user claims

### Email Confirmation

Custom token generation using:
- Base64-encoded data: `{normalizedEmail}:{expirationTicks}`
- SHA384 hash: `{normalizedEmail}:{expirationTicks}:{securityStamp}`
- Token format: `{base64Data}.{base64Hash}`
- 5-day expiration from generation time

## Coding Standards (from .github/copilot-instructions.md)

### Naming Conventions

- **Interfaces**: Defined in 'Abstractions' projects (not used in this repo's namespace)
- **DTOs/POCOs**: Postfix with 'Dto' for data transfer objects
- **Repositories**: Postfix with 'Repository'
- **Services**: Postfix with 'Service'
- **Clients**: Postfix with 'Client' for external service access
- **Extensions**: Static class with postfix 'Extensions'

### Code Style

- Use braces on same line as class/method declaration
- Fields: camelCase with no prefix
- Properties: PascalCase
- Always inject `ILogger<T>` in constructors
- Use XML documentation for public methods
- Inline comments for complex logic
- Prefer readability over cleverness
- Avoid external dependencies unless necessary

### Example Code Style
```csharp
public class MyClass {
    private int myField;
    public int MyProperty { get; set; }
    protected ILogger<MyClass> Logger { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="MyClass"/> class.
    /// </summary>
    public MyClass(int myField, ILogger<MyClass> logger) {
        this.myField = myField;
        Logger = logger;
    }
}
```

## Database Migrations

SQL migration scripts are included in `Scripts/` directory and copied to output:
- `M00-InitialMigration.sql`
- `M01.InitialMigration.sql`
- `M02.ExtendUserProperties.sql`

Entity Framework migrations are in `Migrations/` directory.

## Configuration

**AuthenticationConfig** (`AuthenticationConfig.cs`)
- Configuration section name for authentication settings
- Used for JWT configuration and MFA settings
- `TwoFactorTotpName` property for TOTP authenticator app name

**JwtSettings** (`JwtSettings.cs`)
- JWT token generation settings

**User Secrets**: The project uses User Secrets with ID `N2-Core-0c368d89-5cb3-4451-9c68-b79e69920a09`

## Testing

Tests use MSTest framework with dependency injection setup in `TestContext.cs`. Tests cover:
- User creation, deletion, and validation
- Email confirmation token generation and validation
- Role management (create, assign, remove)
- User lookup (by name, email, ID)
- Multi-factor authentication setup

Test users and data are configured via the `TestContext` service collection configuration.

## Dependencies

**Core:**
- N2.Core.Abstractions (1.4.4) - base abstractions for commands and responses
- Microsoft.AspNetCore.Identity.EntityFrameworkCore (version varies by target framework)
- Microsoft.EntityFrameworkCore.SqlServer

**Authentication:**
- Microsoft.AspNetCore.Authentication.JwtBearer
- Microsoft.IdentityModel.Tokens
- System.IdentityModel.Tokens.Jwt

**MFA:**
- QRCoder (1.7.0) - QR code generation for TOTP
- Otp.NET (1.4.0) - TOTP implementation

## CI/CD

GitHub Actions workflow (`.github/workflows/dotnet.yml`):
- Builds on push/PR to `trunk` branch
- Tests with both .NET 8.0 and 9.0
- Publishes NuGet package to nuget.org on success
- Uses secret `PACKAGE_N2` for NuGet API key
