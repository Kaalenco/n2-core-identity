using Microsoft.AspNetCore.Identity;
using N2.Core.Identity;
using System.ComponentModel.DataAnnotations;

namespace N2.Identity.Data;
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
}

public class ApplicationRole : IdentityRole<Guid>, IIdentityRole
{
    public ApplicationRole() : base() { }
    public ApplicationRole(string roleName) : base(roleName) { }
}

public class ApplicationUserRole : IdentityUserRole<Guid>;

public class ApplicationUserClaim : IdentityUserClaim<Guid>;