using System.ComponentModel.DataAnnotations;

using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace N2.Core.Identity.Data;

/// <summary>
/// Represents an application user, extending <see cref="IdentityUser{TKey}"/> with additional profile
/// and multi-factor authentication properties.
/// </summary>
public class ApplicationUser : IdentityUser<Guid>, IIdentityUser
{
    /// <summary>Gets or sets the user's first name. Maximum length: 100 characters.</summary>
    [MaxLength(100)]
    public string? FirstName { get; set; }

    /// <summary>Gets or sets the user's last name. Maximum length: 100 characters.</summary>
    [MaxLength(100)]
    public string? LastName { get; set; }

    /// <summary>Gets or sets the user's middle name. Maximum length: 10 characters.</summary>
    [MaxLength(10)]
    public string? MiddleName { get; set; }

    /// <summary>Gets or sets a friendly display name shown in the UI. Maximum length: 100 characters.</summary>
    [MaxLength(100)]
    public string? DisplayName { get; set; }

    /// <summary>Gets or sets the relative or absolute path to the user's profile image. Maximum length: 300 characters.</summary>
    [MaxLength(300)]
    public string? ImagePath { get; set; }

    /// <summary>Gets or sets the multi-factor authentication method configured for this user.</summary>
    public MultiFactorType MfaType { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the user has completed MFA enrollment and confirmed their
    /// second factor (e.g., verified the TOTP app or confirmed the SMS/email code).
    /// </summary>
    public bool MfaConfirmed { get; set; }

    /// <summary>
    /// Gets or sets the MFA shared secret used for TOTP code generation or HMAC-based token signing.
    /// Maximum length: 128 characters.
    /// </summary>
    [MaxLength(128)]
    public string? MfaSecret { get; set; }
}

/// <summary>
/// Represents an application registered under an <see cref="ApplicationTenant"/>.
/// Applications can be locked to prevent access without removing them from the system.
/// </summary>
public class Application {
    /// <summary>Gets or sets the unique identifier for the application.</summary>
    [Key()]
    public Guid Id { get; set; }

    /// <summary>Gets or sets the display name of the application. Maximum length: 100 characters.</summary>
    [MaxLength(100)]
    public string? Name { get; set; }

    [MaxLength(100)]
    public string? NormalizedName { get; set; }

    /// <summary>Gets or sets the foreign key referencing the owning <see cref="ApplicationTenant"/>.</summary>
    public virtual Guid ApplicationTenantId { get; set; }

    /// <summary>Gets or sets the navigation property to the owning tenant.</summary>
    public virtual ApplicationTenant ApplicationTenant { get; set; } = null!;

    /// <summary>Gets or sets a value indicating whether the application is locked and inaccessible to users.</summary>
    public bool IsLocked { get; set; }

    /// <summary>
    /// Gets or sets the MFA shared secret used for TOTP code generation or HMAC-based token signing.
    /// Maximum length: 128 characters.
    /// </summary>
    [MaxLength(128)]
    public string? MfaSecret { get; set; }
}

/// <summary>
/// The secret store can contain secrets like a personal access token (PAT) to represents a token
/// issued to an <see cref="ApplicationUser"/> for authentication purposes. PATs are typically used for
/// API access or other scenarios where a user needs to authenticate without using
/// their primary credentials. But is may store other secrets too, like application secrets. The identifier is stored in a hashed
/// form for security, and includes metadata such as name, expiration, and associated policies.
/// The secret is linked to a specific entity and can be managed (created, revoked, listed)
/// by the owner or administrators. For security, the actual token identifier is only shown at creation time and should not be
/// retrievable afterwards. The hashed token is used for authentication purposes. The hash is generated using a secure
/// algorithm (e.g., SHA-256) and uses the owners ID and MFA secret as part of the hashing process to ensure uniqueness
/// and security. The expiration property allows for time-limited tokens, and the policies property can store JSON or
/// other structured data defining the token's permissions and restrictions. The hash value is stored instead of the
/// plain token to prevent misuse if the database is compromised. When a token is presented for authentication,
/// it is hashed using the same algorithm and compared against the stored hash to verify its validity without ever
/// exposing the original token value. The original token value should contain information for the owner identification
/// and the algorithm used for hashing, so that the system can verify the token correctly.
/// </summary>
public class ApplicationSecret {
    /// <summary>Gets or sets the unique identifier for the personal access token.</summary>
    [Key()]
    public Guid Id { get; set; }
    /// <summary>Gets or sets the foreign key referencing the owner (user, application, or any other entity with a GUID as Id).</summary>
    public Guid ReferenceId { get; set; }
    /// <summary>Gets or sets the name to the owning entity.</summary>
    public string ReferenceType { get; set; } = null!;

    /// <summary>
    /// The name of the token, which can be used for display purposes to identify the token in a list of tokens. This is not the actual token value, but a user-friendly name that helps users and administrators recognize the purpose or context of the token. For example, a token might be named "API Access Token for MyApp" or "CI/CD Pipeline Token". The name should be descriptive enough to distinguish it from other tokens, especially if an owner has multiple tokens issued. Maximum length: 100 characters.
    /// </summary>
    [MaxLength(100)]
    public string? Name { get; set; }

    [MaxLength(100)]
    public string? NormalizedName { get; set; }

    /// <summary>
    /// Gets or sets the hashed representation of the token.
    /// </summary>
    [MaxLength(256)]
    public string HashedToken { get; set; } = null!;
    /// <summary>Gets or sets the expiration date and time of the token. Null if the token does not expire.</summary>
    public DateTime? Expiration { get; set; }
    [MaxLength(1000)]
    public string? Description { get; set; }
    /// <summary>
    /// Gets or sets the policies associated with this entity as a JSON string or other structured format.
    /// This can include permissions, scopes, or other metadata defining the token's capabilities and
    /// restrictions. Maximum length: 1000 characters.
    /// </summary>
    [MaxLength(1000)]
    public string? Policies { get; set; }

    /// <summary>
    /// Gets or sets the secret value as a byte array.
    /// </summary>
    /// <remarks>The length of the array must not exceed 4,000 bytes. This property is typically used to store
    /// sensitive information, such as cryptographic keys, tokens or information, in binary form.</remarks>
    [MaxLength(4000)]
    public byte[]? Secret { get; set; }
}

    /// <summary>
    /// Represents an application role, extending <see cref="IdentityRole{TKey}"/> with a <see cref="Guid"/> key.
    /// </summary>
    public class ApplicationRole : IdentityRole<Guid>, IIdentityRole
{
    /// <summary>Initializes a new instance of the <see cref="ApplicationRole"/> class.</summary>
    public ApplicationRole() : base()
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="ApplicationRole"/> class with the specified role name.
    /// </summary>
    /// <param name="roleName">The name of the role.</param>
    public ApplicationRole(string roleName) : base(roleName)
    {
    }
}

/// <summary>
/// Represents a tenant (organisation) in the multi-tenant identity system.
/// </summary>
public class ApplicationTenant
{
    /// <summary>Gets or sets the unique identifier for the tenant.</summary>
    [Key()]
    public Guid Id { get; set; }

    /// <summary>Gets or sets the display name of the tenant. Maximum length: 100 characters.</summary>
    [MaxLength(100)]
    public string? Name { get; set; }

    /// <summary>Gets or sets the upper-case normalized name used for case-insensitive lookups. Maximum length: 100 characters.</summary>
    [MaxLength(100)]
    public string? NormalizedName { get; set; }

    /// <summary>Gets or sets the mailing or physical address for the tenant. Maximum length: 1000 characters.</summary>
    [MaxLength(1000)]
    public string? Address { get; set; }

    /// <summary>Gets or sets the email address of the tenant administrator. Maximum length: 100 characters.</summary>
    [MaxLength(100)]
    public string? AdminEmail { get; set; }

    /// <summary>Gets or sets the upper-case normalized admin email used for case-insensitive lookups. Maximum length: 100 characters.</summary>
    [MaxLength(100)]
    public string? NormalizedEmail { get; set; }

    /// <summary>Gets or sets free-form contact information for the tenant (e.g. phone, support URL). Maximum length: 1000 characters.</summary>
    [MaxLength(1000)]
    public string? ContactInfo { get; set; }

    /// <summary>Gets or sets the relative or absolute path to the tenant's logo or image. Maximum length: 100 characters.</summary>
    [MaxLength(100)]
    public string? ImagePath { get; set; }

    /// <summary>Gets or sets a value indicating whether the tenant is locked and its users are prevented from signing in.</summary>
    public bool IsLocked { get; set; }

    /// <summary>Gets or sets a value indicating whether the tenant has been soft-deleted.</summary>
    public bool IsRemoved { get; set; }

    /// <summary>Gets or sets a value indicating whether the tenant is hidden from public-facing listings.</summary>
    public bool IsHidden { get; set; }

    /// <summary>Gets or sets the maximum number of users allowed for this tenant. Zero or negative values may indicate no limit.</summary>
    public int UserLimit { get; set; }

    /// <summary>
    /// Gets or sets the MFA shared secret used for TOTP code generation or HMAC-based token signing.
    /// Maximum length: 128 characters.
    /// </summary>
    [MaxLength(128)]
    public string? MfaSecret { get; set; }
}

/// <summary>
/// Join entity that associates an <see cref="ApplicationUser"/> with an <see cref="ApplicationTenant"/>,
/// representing a user's membership within a specific tenant.
/// </summary>
public class ApplicationUserTenant {
    /// <summary>Gets or sets the unique identifier for this user-tenant association.</summary>
    [Key()]
    public Guid Id { get; set; }

    /// <summary>Gets or sets the foreign key referencing the associated <see cref="ApplicationUser"/>.</summary>
    public virtual Guid ApplicationUserId { get; set; }

    /// <summary>Gets or sets the foreign key referencing the associated <see cref="ApplicationTenant"/>.</summary>
    public virtual Guid ApplicationTenantId { get; set; }

    /// <summary>Gets or sets the navigation property to the associated user.</summary>
    public virtual ApplicationUser ApplicationUser { get; set; } = null!;

    /// <summary>Gets or sets the navigation property to the associated tenant.</summary>
    public virtual ApplicationTenant ApplicationTenant { get; set; } = null!;
}

/// <summary>
/// Represents the many-to-many relationship between <see cref="ApplicationUser"/> and <see cref="ApplicationRole"/>,
/// extending <see cref="IdentityUserRole{TKey}"/> with a <see cref="Guid"/> key.
/// </summary>
public class ApplicationUserRole : IdentityUserRole<Guid>;

/// <summary>
/// Represents a claim associated with an <see cref="ApplicationUser"/>,
/// extending <see cref="IdentityUserClaim{TKey}"/> with a <see cref="Guid"/> key.
/// </summary>
public class ApplicationUserClaim : IdentityUserClaim<Guid>;