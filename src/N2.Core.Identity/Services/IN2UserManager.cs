using N2.Core.Identity.Data;

namespace N2.Core.Identity.Services;

/// <summary>
/// Extends <see cref="IUserManager{TUser}"/> for <see cref="ApplicationUser"/> with
/// secret-ownership capabilities, mirroring the pattern used by
/// <see cref="IApplicationManager"/> and <see cref="ITenantManager"/>.
/// </summary>
public interface IN2UserManager : IUserManager<ApplicationUser>, IHaveSecrets {
}