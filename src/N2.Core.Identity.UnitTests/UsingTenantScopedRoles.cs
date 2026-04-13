using Moq;

using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace N2.Core.Identity.UnitTests;

/// <summary>
/// Unit tests for tenant-scoped role resolution in <see cref="IdentityUserContext"/>,
/// <see cref="AspNetUserContext"/> and <see cref="WebTokenGenerator"/>.
/// </summary>
[TestClass]
public class UsingTenantScopedRoles : N2IdentityTestsBase
{
    private static readonly Guid TenantA = Guid.NewGuid();
    private static readonly Guid TenantB = Guid.NewGuid();

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private static IdentityUserContext BuildIdentityContext(
        IEnumerable<(Guid tenantId, string tenantName, string[] roles)> memberships)
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, Guid.NewGuid().ToString()),
            new(ClaimTypes.Name, "testuser"),
        };

        foreach (var (tenantId, tenantName, roles) in memberships)
        {
            claims.Add(new Claim(N2ClaimTypes.TenantMembership, $"{tenantId}:{tenantName}"));
            foreach (var role in roles)
                claims.Add(new Claim(N2ClaimTypes.TenantRole, $"{tenantId}:{role}"));
        }

        var identity = new ClaimsIdentity(claims, "Test");
        return new IdentityUserContext(new ClaimsPrincipal(identity));
    }

    private static AspNetUserContext BuildAspNetContext(
        IEnumerable<(Guid tenantId, string tenantName, string[] roles)> memberships)
    {
        var tenants = memberships
            .Select(m => (m.tenantId, m.tenantName, (IReadOnlyList<string>)m.roles.ToList()))
            .ToList();

        var user = new Mock<IIdentityUser>();
        user.SetupGet(u => u.Id).Returns(Guid.NewGuid());
        user.SetupGet(u => u.UserName).Returns("testuser");
        user.SetupGet(u => u.Email).Returns("test@example.com");

        return new AspNetUserContext(user.Object, tenants, [], null);
    }

    // -------------------------------------------------------------------------
    // Role checks without an active tenant
    // -------------------------------------------------------------------------

    [TestMethod]
    public void IdentityContext_NoTenantSet_IsInRole_ReturnsFalse()
    {
        var ctx = BuildIdentityContext([(TenantA, "Alpha", [SystemRoles.Admin])]);
        Assert.IsFalse(ctx.IsInRole(SystemRoles.Admin));
    }

    [TestMethod]
    public void IdentityContext_NoTenantSet_IsAdmin_ReturnsFalse()
    {
        var ctx = BuildIdentityContext([(TenantA, "Alpha", [SystemRoles.Admin])]);
        Assert.IsFalse(ctx.IsAdmin());
    }

    [TestMethod]
    public void IdentityContext_NoTenantSet_CurrentRoles_ReturnsEmpty()
    {
        var ctx = BuildIdentityContext([(TenantA, "Alpha", [SystemRoles.Admin, SystemRoles.Publisher])]);
        Assert.IsFalse(ctx.CurrentRoles().Any());
    }

    [TestMethod]
    public void AspNetContext_NoTenantSet_IsInRole_ReturnsFalse()
    {
        var ctx = BuildAspNetContext([(TenantA, "Alpha", [SystemRoles.Admin])]);
        Assert.IsFalse(ctx.IsInRole(SystemRoles.Admin));
    }

    // -------------------------------------------------------------------------
    // SetTenantContext
    // -------------------------------------------------------------------------

    [TestMethod]
    public void SetTenantContext_KnownId_ReturnsTrue()
    {
        var ctx = BuildIdentityContext([(TenantA, "Alpha", [SystemRoles.Admin])]);
        Assert.IsTrue(ctx.SetTenantContext(TenantA));
    }

    [TestMethod]
    public void SetTenantContext_UnknownId_ReturnsFalse()
    {
        var ctx = BuildIdentityContext([(TenantA, "Alpha", [SystemRoles.Admin])]);
        Assert.IsFalse(ctx.SetTenantContext(Guid.NewGuid()));
    }

    [TestMethod]
    public void SetTenantContext_ByName_ReturnsTrue()
    {
        var ctx = BuildIdentityContext([(TenantA, "Alpha", [SystemRoles.Admin])]);
        Assert.IsTrue(ctx.SetTenantContext("Alpha"));
    }

    [TestMethod]
    public void SetTenantContext_ByName_IsCaseInsensitive()
    {
        var ctx = BuildIdentityContext([(TenantA, "Alpha", [SystemRoles.Admin])]);
        Assert.IsTrue(ctx.SetTenantContext("ALPHA"));
    }

    [TestMethod]
    public void SetTenantContext_UnknownName_ReturnsFalse()
    {
        var ctx = BuildIdentityContext([(TenantA, "Alpha", [SystemRoles.Admin])]);
        Assert.IsFalse(ctx.SetTenantContext("Beta"));
    }

    [TestMethod]
    public void SetTenantContext_SetsCurrentTenantId()
    {
        var ctx = BuildIdentityContext([(TenantA, "Alpha", [])]);
        ctx.SetTenantContext(TenantA);
        Assert.AreEqual(TenantA, ctx.CurrentTenantId);
    }

    [TestMethod]
    public void SetTenantContext_SetsCurrentTenantName()
    {
        var ctx = BuildIdentityContext([(TenantA, "Alpha", [])]);
        ctx.SetTenantContext(TenantA);
        Assert.AreEqual("Alpha", ctx.CurrentTenantName);
    }

    // -------------------------------------------------------------------------
    // Role resolution after SetTenantContext
    // -------------------------------------------------------------------------

    [TestMethod]
    public void IdentityContext_AdminTenant_IsAdmin_ReturnsTrue()
    {
        var ctx = BuildIdentityContext([(TenantA, "Alpha", [SystemRoles.Admin])]);
        ctx.SetTenantContext(TenantA);
        Assert.IsTrue(ctx.IsAdmin());
    }

    [TestMethod]
    public void IdentityContext_NonAdminTenant_IsAdmin_ReturnsFalse()
    {
        var ctx = BuildIdentityContext([(TenantA, "Alpha", [SystemRoles.User])]);
        ctx.SetTenantContext(TenantA);
        Assert.IsFalse(ctx.IsAdmin());
    }

    [TestMethod]
    public void IdentityContext_PublisherRole_CanPublish_ReturnsTrue()
    {
        var ctx = BuildIdentityContext([(TenantA, "Alpha", [SystemRoles.Publisher])]);
        ctx.SetTenantContext(TenantA);
        Assert.IsTrue(ctx.CanPublish());
    }

    [TestMethod]
    public void IdentityContext_AdminRole_CanPublish_ReturnsTrue()
    {
        var ctx = BuildIdentityContext([(TenantA, "Alpha", [SystemRoles.Admin])]);
        ctx.SetTenantContext(TenantA);
        Assert.IsTrue(ctx.CanPublish());
    }

    [TestMethod]
    public void IdentityContext_UserRole_CanPublish_ReturnsFalse()
    {
        var ctx = BuildIdentityContext([(TenantA, "Alpha", [SystemRoles.User])]);
        ctx.SetTenantContext(TenantA);
        Assert.IsFalse(ctx.CanPublish());
    }

    [TestMethod]
    public void IdentityContext_DesignerRole_CanDesign_ReturnsTrue()
    {
        var ctx = BuildIdentityContext([(TenantA, "Alpha", [SystemRoles.Designer])]);
        ctx.SetTenantContext(TenantA);
        Assert.IsTrue(ctx.CanDesign());
    }

    [TestMethod]
    public void IdentityContext_AuthManagerRole_CanModifyRights_ReturnsTrue()
    {
        var ctx = BuildIdentityContext([(TenantA, "Alpha", [SystemRoles.AuthManager])]);
        ctx.SetTenantContext(TenantA);
        Assert.IsTrue(ctx.CanModifyRights());
    }

    [TestMethod]
    public void IdentityContext_IsInRole_IsCaseInsensitive()
    {
        var ctx = BuildIdentityContext([(TenantA, "Alpha", [SystemRoles.Admin])]);
        ctx.SetTenantContext(TenantA);
        Assert.IsTrue(ctx.IsInRole(SystemRoles.Admin.ToUpperInvariant()));
    }

    [TestMethod]
    public void IdentityContext_CurrentRoles_ReturnsActiveTenantRoles()
    {
        var ctx = BuildIdentityContext([(TenantA, "Alpha", [SystemRoles.Admin, SystemRoles.Publisher])]);
        ctx.SetTenantContext(TenantA);
        var roles = ctx.CurrentRoles().ToList();
        CollectionAssert.Contains(roles, SystemRoles.Admin);
        CollectionAssert.Contains(roles, SystemRoles.Publisher);
    }

    // -------------------------------------------------------------------------
    // Multi-tenant switching — different roles per tenant
    // -------------------------------------------------------------------------

    [TestMethod]
    public void MultiTenant_SwitchContext_RolesReflectActiveTenant()
    {
        var ctx = BuildIdentityContext([
            (TenantA, "Alpha", [SystemRoles.Admin]),
            (TenantB, "Beta",  [SystemRoles.User]),
        ]);

        ctx.SetTenantContext(TenantA);
        Assert.IsTrue(ctx.IsAdmin(), "Should be Admin in TenantA");
        Assert.IsFalse(ctx.IsInRole(SystemRoles.User), "Should not have User in TenantA");

        ctx.SetTenantContext(TenantB);
        Assert.IsFalse(ctx.IsAdmin(), "Should not be Admin in TenantB");
        Assert.IsTrue(ctx.IsInRole(SystemRoles.User), "Should have User in TenantB");
    }

    [TestMethod]
    public void MultiTenant_SwitchContext_CurrentTenantIdUpdates()
    {
        var ctx = BuildIdentityContext([
            (TenantA, "Alpha", []),
            (TenantB, "Beta",  []),
        ]);

        ctx.SetTenantContext(TenantA);
        Assert.AreEqual(TenantA, ctx.CurrentTenantId);

        ctx.SetTenantContext(TenantB);
        Assert.AreEqual(TenantB, ctx.CurrentTenantId);
    }

    [TestMethod]
    public void MultiTenant_AdminInOneTenant_NotAdminInOther()
    {
        var ctx = BuildAspNetContext([
            (TenantA, "Alpha", [SystemRoles.Admin]),
            (TenantB, "Beta",  [SystemRoles.User]),
        ]);

        ctx.SetTenantContext(TenantA);
        Assert.IsTrue(ctx.IsAdmin());

        ctx.SetTenantContext(TenantB);
        Assert.IsFalse(ctx.IsAdmin());
    }

    // -------------------------------------------------------------------------
    // IsInTenant
    // -------------------------------------------------------------------------

    [TestMethod]
    public void IsInTenant_KnownId_ReturnsTrue()
    {
        var ctx = BuildIdentityContext([(TenantA, "Alpha", [])]);
        Assert.IsTrue(ctx.IsInTenant(TenantA));
    }

    [TestMethod]
    public void IsInTenant_UnknownId_ReturnsFalse()
    {
        var ctx = BuildIdentityContext([(TenantA, "Alpha", [])]);
        Assert.IsFalse(ctx.IsInTenant(Guid.NewGuid()));
    }

    [TestMethod]
    public void IsInTenant_ByName_ReturnsTrue()
    {
        var ctx = BuildIdentityContext([(TenantA, "Alpha", [])]);
        Assert.IsTrue(ctx.IsInTenant("Alpha"));
    }

    [TestMethod]
    public void IsInTenant_ByName_IsCaseInsensitive()
    {
        var ctx = BuildIdentityContext([(TenantA, "Alpha", [])]);
        Assert.IsTrue(ctx.IsInTenant("alpha"));
    }

    // -------------------------------------------------------------------------
    // TenantMemberships enumeration
    // -------------------------------------------------------------------------

    [TestMethod]
    public void TenantMemberships_ReturnsAllTenants()
    {
        var ctx = BuildIdentityContext([
            (TenantA, "Alpha", [SystemRoles.Admin]),
            (TenantB, "Beta",  [SystemRoles.User]),
        ]);

        var memberships = ctx.TenantMemberships.ToList();
        Assert.AreEqual(2, memberships.Count);
        Assert.IsTrue(memberships.Any(m => m.TenantId == TenantA && m.Roles.Contains(SystemRoles.Admin)));
        Assert.IsTrue(memberships.Any(m => m.TenantId == TenantB && m.Roles.Contains(SystemRoles.User)));
    }

    [TestMethod]
    public void TenantMemberships_EmptyUser_ReturnsEmpty()
    {
        var ctx = BuildIdentityContext([]);
        Assert.IsFalse(ctx.TenantMemberships.Any());
    }

    // -------------------------------------------------------------------------
    // WebTokenGenerator — tenant claim emission
    // -------------------------------------------------------------------------

    [TestMethod]
    public void WebTokenGenerator_EmitsTenantMembershipClaims()
    {
        var userContext = new Mock<IUserContext>();
        userContext.SetupGet(m => m.PublicId).Returns(Guid.NewGuid());
        userContext.SetupGet(m => m.Name).Returns("testuser");
        userContext.SetupGet(m => m.Email).Returns("test@example.com");
        userContext.SetupGet(m => m.PhoneNumber).Returns(string.Empty);
        userContext.SetupGet(m => m.TenantMemberships).Returns([
            (TenantA, "Alpha", (IReadOnlyList<string>)[SystemRoles.Admin]),
        ]);

        var generator = new WebTokenGenerator(GetAuthenticationConfig().JwtSettings);
        var tokenString = generator.GenerateWebToken(userContext.Object, 5);

        var token = new JwtSecurityTokenHandler().ReadJwtToken(tokenString);
        var membershipClaims = token.Claims
            .Where(c => c.Type == N2ClaimTypes.TenantMembership)
            .ToList();

        Assert.AreEqual(1, membershipClaims.Count);
        Assert.AreEqual($"{TenantA}:Alpha", membershipClaims[0].Value);
    }

    [TestMethod]
    public void WebTokenGenerator_EmitsTenantRoleClaims()
    {
        var userContext = new Mock<IUserContext>();
        userContext.SetupGet(m => m.PublicId).Returns(Guid.NewGuid());
        userContext.SetupGet(m => m.Name).Returns("testuser");
        userContext.SetupGet(m => m.Email).Returns("test@example.com");
        userContext.SetupGet(m => m.PhoneNumber).Returns(string.Empty);
        userContext.SetupGet(m => m.TenantMemberships).Returns([
            (TenantA, "Alpha", (IReadOnlyList<string>)[SystemRoles.Admin, SystemRoles.Publisher]),
        ]);

        var generator = new WebTokenGenerator(GetAuthenticationConfig().JwtSettings);
        var tokenString = generator.GenerateWebToken(userContext.Object, 5);

        var token = new JwtSecurityTokenHandler().ReadJwtToken(tokenString);
        var roleClaims = token.Claims
            .Where(c => c.Type == N2ClaimTypes.TenantRole)
            .Select(c => c.Value)
            .ToList();

        CollectionAssert.Contains(roleClaims, $"{TenantA}:{SystemRoles.Admin}");
        CollectionAssert.Contains(roleClaims, $"{TenantA}:{SystemRoles.Publisher}");
    }

    [TestMethod]
    public void WebTokenGenerator_MultipleTenants_EmitsClaimsForEach()
    {
        var userContext = new Mock<IUserContext>();
        userContext.SetupGet(m => m.PublicId).Returns(Guid.NewGuid());
        userContext.SetupGet(m => m.Name).Returns("testuser");
        userContext.SetupGet(m => m.Email).Returns("test@example.com");
        userContext.SetupGet(m => m.PhoneNumber).Returns(string.Empty);
        userContext.SetupGet(m => m.TenantMemberships).Returns([
            (TenantA, "Alpha", (IReadOnlyList<string>)[SystemRoles.Admin]),
            (TenantB, "Beta",  (IReadOnlyList<string>)[SystemRoles.User]),
        ]);

        var generator = new WebTokenGenerator(GetAuthenticationConfig().JwtSettings);
        var tokenString = generator.GenerateWebToken(userContext.Object, 5);

        var token = new JwtSecurityTokenHandler().ReadJwtToken(tokenString);
        var membershipClaims = token.Claims.Where(c => c.Type == N2ClaimTypes.TenantMembership).ToList();
        var roleClaims = token.Claims.Where(c => c.Type == N2ClaimTypes.TenantRole).ToList();

        Assert.AreEqual(2, membershipClaims.Count, "Should emit one membership claim per tenant");
        Assert.AreEqual(2, roleClaims.Count, "Should emit one role claim per tenant-role pair");
    }

    [TestMethod]
    public void WebTokenGenerator_RoundTrip_ClaimsRestoredInIdentityContext()
    {
        var tenantId = TenantA;

        // Generate a token with tenant claims
        var userContext = new Mock<IUserContext>();
        userContext.SetupGet(m => m.PublicId).Returns(Guid.NewGuid());
        userContext.SetupGet(m => m.Name).Returns("testuser");
        userContext.SetupGet(m => m.Email).Returns("test@example.com");
        userContext.SetupGet(m => m.PhoneNumber).Returns(string.Empty);
        userContext.SetupGet(m => m.TenantMemberships).Returns([
            (tenantId, "Alpha", (IReadOnlyList<string>)[SystemRoles.Admin]),
        ]);

        var generator = new WebTokenGenerator(GetAuthenticationConfig().JwtSettings);
        var tokenString = generator.GenerateWebToken(userContext.Object, 5);

        // Parse token claims back into an IdentityUserContext
        var rawToken = new JwtSecurityTokenHandler().ReadJwtToken(tokenString);
        var claims = rawToken.Claims.ToList();
        var identity = new ClaimsIdentity(claims, "Test");
        var restored = new IdentityUserContext(new ClaimsPrincipal(identity));

        // Verify tenant membership and roles survive the round-trip
        Assert.IsTrue(restored.IsInTenant(tenantId));
        restored.SetTenantContext(tenantId);
        Assert.IsTrue(restored.IsAdmin());
        Assert.AreEqual("Alpha", restored.CurrentTenantName);
    }
}
