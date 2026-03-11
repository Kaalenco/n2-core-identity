# Code Style and Conventions

## Naming
- **Interfaces**: Defined in 'Abstractions' projects; prefix with `I`
- **DTOs/POCOs**: Postfix with `Dto`
- **Repositories**: Postfix with `Repository`
- **Services**: Postfix with `Service`
- **Clients**: Postfix with `Client`
- **Extensions**: Static class postfixed with `Extensions`
- **Fields**: camelCase, no prefix (e.g., `logger`, `factory`, `context`)
- **Properties**: PascalCase
- **Constants**: PascalCase

## Formatting
- Braces on same line as class/method declaration
- C# 12 features (primary constructors OK where idiomatic)
- Nullable enabled — annotate appropriately
- Implicit usings enabled

## Documentation
- XML doc comments (`/// <summary>`) for all public methods
- Inline comments for complex logic
- Prefer readability over cleverness

## Dependency Injection
- Always inject `ILogger<T>` in constructors
- Store as `protected ILogger<T> Logger { get; }`

## Example
```csharp
public class MyService {
    private int myField;
    public int MyProperty { get; set; }
    protected ILogger<MyService> Logger { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="MyService"/> class.
    /// </summary>
    public MyService(int myField, ILogger<MyService> logger) {
        this.myField = myField;
        Logger = logger;
    }
}
```

## Security Patterns
- Password hashing: PBKDF2-HMAC-SHA256 with 310,000 iterations (OWASP 2023)
- Token signing: HMAC-SHA256 with secret key from config (`TokenSigningSecret`)
- Nonces: cryptographically secure random bytes (min 256 bits)
- Constant-time comparison for tokens to prevent timing attacks
- Rate limiting on authentication attempts
