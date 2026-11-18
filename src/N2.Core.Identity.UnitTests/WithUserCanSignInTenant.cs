using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;

using N2.Core.Identity.Data;

namespace N2.Core.Identity.UnitTests;

[TestClass]
public class WithUserCanSignInTenant {

    private static N2IdentityContext CreateContext() =>
        new(
            new DbContextOptionsBuilder<N2IdentityContext>()
                .UseInMemoryDatabase($"signin_tenant_{Guid.NewGuid():N}")
                .Options,
            NullLogger<N2IdentityContext>.Instance);

    private static async Task<(Guid UserId, Guid TenantId)> Seed(
        N2IdentityContext context,
        bool tenantLocked,
        bool isMember,
        DateTimeOffset? lockoutEnd) {
        var user = new ApplicationUser {
            Id = Guid.NewGuid(),
            UserName = "user",
            NormalizedUserName = "USER",
            EmailConfirmed = true,
            LockoutEnabled = true,
            LockoutEnd = lockoutEnd
        };
        var tenant = new ApplicationTenant { Id = Guid.NewGuid(), Name = "tenant", IsLocked = tenantLocked };
        context.Users.Add(user);
        context.Tenants.Add(tenant);
        if (isMember) {
            context.UserTenants.Add(new ApplicationUserTenant {
                Id = Guid.NewGuid(),
                ApplicationUserId = user.Id,
                ApplicationTenantId = tenant.Id
            });
        }
        await context.SaveChangesAsync(CancellationToken.None);
        return (user.Id, tenant.Id);
    }

    [TestMethod]
    public async Task MemberOfOpenTenant_ShouldReturnTrue() {
        using var context = CreateContext();
        var (userId, tenantId) = await Seed(context, tenantLocked: false, isMember: true, lockoutEnd: null);

        Assert.IsTrue(await context.UserCanSignInTenant(userId, tenantId, CancellationToken.None));
    }

    [TestMethod]
    public async Task MemberOfLockedTenant_ShouldReturnFalse() {
        using var context = CreateContext();
        var (userId, tenantId) = await Seed(context, tenantLocked: true, isMember: true, lockoutEnd: null);

        Assert.IsFalse(await context.UserCanSignInTenant(userId, tenantId, CancellationToken.None));
    }

    [TestMethod]
    public async Task NotAMember_ShouldReturnFalse() {
        using var context = CreateContext();
        var (userId, tenantId) = await Seed(context, tenantLocked: false, isMember: false, lockoutEnd: null);

        Assert.IsFalse(await context.UserCanSignInTenant(userId, tenantId, CancellationToken.None));
    }

    [TestMethod]
    public async Task UserLockedOut_ShouldReturnFalse() {
        using var context = CreateContext();
        var (userId, tenantId) = await Seed(context, tenantLocked: false, isMember: true, lockoutEnd: DateTimeOffset.UtcNow.AddHours(1));

        Assert.IsFalse(await context.UserCanSignInTenant(userId, tenantId, CancellationToken.None));
    }
}
