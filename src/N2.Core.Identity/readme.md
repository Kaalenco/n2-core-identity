# N2.Core.Identity

## Description

**N2.Core.Identity** is a flexible identity and role management library for .NET applications, built on top of ASP.NET Core Identity. It provides a strongly-typed, extensible `N2IdentityDbContext` (extending `IdentityDbContext`) and a feature-rich `N2UserManager` for advanced user, role, and authentication scenarios. The library is designed for modern .NET (net8.0, net9.0) and supports custom user properties, role management, and token-based workflows.

## Features

- Extends `IdentityDbContext` for easy integration with ASP.NET Core Identity.
- Strongly-typed `ApplicationUser` and `ApplicationRole` with support for custom properties.
- Advanced user and role management via `N2UserManager`.
- Token generation and email confirmation workflows.
- Designed for .NET 8 and .NET 9.

## License

AFL-3.0

## Basic Setup

1. **Configure the DbContext in your application:**
[![NuGet](https://img.shields.io/nuget/v/N2.Core.Identity.svg)](https://www.nuget.org/packages/N2.Core.Identity/)
2. **Register the N2UserManager:**
3. **Configure Identity (optional, for ASP.NET Core):**
4. **Use N2UserManager in your application:**

``` C#
using N2.Core.Identity.Services; using N2.Core.Identity.Data;
public class AccountService { private readonly IUserManager<ApplicationUser> _userManager;
   public AccountService(IUserManager<ApplicationUser> userManager)
   {
       _userManager = userManager;
   }

   public async Task CreateUserAsync(string email, string password)
   {
       var user = new ApplicationUser { UserName = email, Email = email };
       await _userManager.CreateAsync(user, password, CancellationToken.None);
   }
}
```

## Best Practices

1. Secure Configuration

- Connection Strings: Store database connection strings securely (e.g., environment variables, Azure Key Vault, or user secrets in development).  
- Sensitive Data: Never log sensitive information such as passwords or tokens.

2. Dependency Injection
- Always register N2UserManager and related services (N2IdentityContext, ApplicationUser, ApplicationRole) using dependency injection. This ensures proper lifetime management and testability.

3. Error Handling
- Always check the result of N2UserManager methods. Most methods return an ICommandResponse or similar result object—verify Status.IsSuccess() before proceeding.
- Handle and log errors gracefully, but avoid exposing internal details to end users.

4. User Input Validation
- Validate all user input before passing it to N2UserManager methods. This includes usernames, emails, and passwords.
- Use strong password policies and validate emails for format and uniqueness.

5. Token Management
- Use the provided token generation and validation methods for email confirmation and password reset. Tokens should be time-limited and single-use where possible.
- Never expose raw tokens in logs or error messages.

6. Role Management
- Use AddToRoleAsync, RemoveFromRoleAsync, and RoleExistsAsync to manage user roles. Always check for role existence before assignment.
- Avoid hardcoding role names; use constants or configuration.

7. DbContext Lifetime
- Ensure that the N2IdentityContext (or your DbContext) is registered with a scoped lifetime (the default for EF Core in ASP.NET Core).
- Avoid sharing DbContext instances across threads.

8. Concurrency and Transactions
- Be aware of concurrency issues, especially when updating user or role data. Use transactions if multiple changes must be atomic.
- Handle potential DbUpdateConcurrencyException or similar exceptions.

9. Security Practices
- Always hash and salt passwords using the built-in mechanisms.
- Use HTTPS for all communications.
- Enable account lockout and email confirmation for new users.

10. Testing
- Write unit and integration tests for all user management workflows.
- Use test doubles or in-memory databases for testing, not production data.



