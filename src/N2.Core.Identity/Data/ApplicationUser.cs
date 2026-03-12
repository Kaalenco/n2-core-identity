using System.ComponentModel.DataAnnotations;

using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace N2.Core.Identity.Data;

// Add profile data for application users by adding properties to the ApplicationUser class
public class ApplicationUser : IdentityUser<Guid>, IIdentityUser
{
    // Add custom properties here
    [MaxLength(100)]
    public string? FirstName { get; set; }

    [MaxLength(100)]
    public string? LastName { get; set; }

    [MaxLength(10)]
    public string? MiddleName { get; set; }

    [MaxLength(100)]
    public string? DisplayName { get; set; }

    [MaxLength(300)]
    public string? ImagePath { get; set; }

    public MultiFactorType MfaType { get; set; }

    public bool MfaConfirmed { get; set; }

    [MaxLength(128)]
    public string? MfaSecret { get; set; }
}


public class ApplicationRole : IdentityRole<Guid>, IIdentityRole
{
    public ApplicationRole() : base()
    {
    }

    public ApplicationRole(string roleName) : base(roleName)
    {
    }
}

public class  ApplicationTenant 
{
    [Key()]
    public Guid Id { get; set; }
    [MaxLength(100)]
    public string? Name { get; set; }
    [MaxLength(100)]
    public string? NormalizedName { get; set; }
    
    [MaxLength(1000)]
    public string? Address { get; set; }
    [MaxLength(100)]
    public string? AdminEmail { get; set; }
    [MaxLength(100)]
    public string? NormalizedEmail { get; set; }
    [MaxLength(1000)]
    public string? ContactInfo { get; set; }
    [MaxLength(100)]
    public string? ImagePath { get; set; }
    public bool IsLocked { get; set; }
    public bool IsRemoved { get; set; }
    public bool IsHidden { get; set; }
    public int UserLimit { get; set; }
}

public class ApplicationUserTenant {
    [Key()]
    public Guid Id { get; set; }
    public virtual Guid ApplicationUserId { get; set; }
    public virtual Guid ApplicationTenantId { get; set; }
    public virtual ApplicationUser ApplicationUser { get; set; } = null!;
    public virtual ApplicationTenant ApplicationTenant { get; set; } = null!;
}

public class ApplicationUserRole : IdentityUserRole<Guid>;

public class ApplicationUserClaim : IdentityUserClaim<Guid>;