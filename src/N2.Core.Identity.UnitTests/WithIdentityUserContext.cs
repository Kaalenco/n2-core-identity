using System.Security.Claims;

namespace N2.Core.Identity.UnitTests;

[TestClass]
public sealed class WithIdentityUserContext
{
    private static readonly Guid TestUserId = new("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
    private static readonly Guid TenantId = new("11111111-2222-3333-4444-555555555555");

    private static ClaimsPrincipal BuildPrincipal(params Claim[] claims)
    {
        var identity = new ClaimsIdentity(claims, "test");
        return new ClaimsPrincipal(identity);
    }

    // -------------------------------------------------------------------------
    // Constructor — claims extraction
    // -------------------------------------------------------------------------

    [TestMethod]
    public void Constructor_ExtractsPublicIdFromNameIdentifier()
    {
        ClaimsPrincipal principal = BuildPrincipal(
            new Claim(ClaimTypes.NameIdentifier, TestUserId.ToString()));
        IdentityUserContext ctx = new(principal);
        Assert.AreEqual(TestUserId, ctx.PublicId);
    }

    [TestMethod]
    public void Constructor_NoNameIdentifier_UsesAnonymousId()
    {
        ClaimsPrincipal principal = BuildPrincipal();
        IdentityUserContext ctx = new(principal);
        Assert.AreEqual(Guid.Parse(IdentityUserContext.AnonymousUserId), ctx.PublicId);
    }

    [TestMethod]
    public void Constructor_ExtractsEmailFromEmailClaim()
    {
        ClaimsPrincipal principal = BuildPrincipal(
            new Claim(ClaimTypes.NameIdentifier, Guid.NewGuid().ToString()),
            new Claim(ClaimTypes.Email, "user@domain.com"));
        IdentityUserContext ctx = new(principal);
        Assert.AreEqual("user@domain.com", ctx.Email);
    }

    // -------------------------------------------------------------------------
    // Tenant index — from N2 claims
    // -------------------------------------------------------------------------

    [TestMethod]
    public void Constructor_WithTenantMembershipClaim_PopulatesTenantIndex()
    {
        ClaimsPrincipal principal = BuildPrincipal(
            new Claim(ClaimTypes.NameIdentifier, Guid.NewGuid().ToString()),
            new Claim(N2ClaimTypes.TenantMembership, $"{TenantId}:Acme"));
        IdentityUserContext ctx = new(principal);
        Assert.IsTrue(ctx.IsInTenant(TenantId));
    }

    [TestMethod]
    public void Constructor_WithTenantRoleClaim_PopulatesRolesForTenant()
    {
        ClaimsPrincipal principal = BuildPrincipal(
            new Claim(ClaimTypes.NameIdentifier, Guid.NewGuid().ToString()),
            new Claim(N2ClaimTypes.TenantMembership, $"{TenantId}:Acme"),
            new Claim(N2ClaimTypes.TenantRole, $"{TenantId}:Admin"));
        IdentityUserContext ctx = new(principal);
        ctx.SetTenantContext(TenantId);
        Assert.IsTrue(ctx.IsInRole("Admin"));
    }

    // -------------------------------------------------------------------------
    // SetTenantContext
    // -------------------------------------------------------------------------

    [TestMethod]
    public void SetTenantContext_KnownGuid_ReturnsTrueAndUpdatesContext()
    {
        ClaimsPrincipal principal = BuildPrincipal(
            new Claim(ClaimTypes.NameIdentifier, Guid.NewGuid().ToString()),
            new Claim(N2ClaimTypes.TenantMembership, $"{TenantId}:Acme"));
        IdentityUserContext ctx = new(principal);
        bool result = ctx.SetTenantContext(TenantId);
        Assert.IsTrue(result);
        Assert.AreEqual(TenantId, ctx.CurrentTenantId);
    }

    [TestMethod]
    public void SetTenantContext_NameCaseInsensitive_ReturnsTrue()
    {
        ClaimsPrincipal principal = BuildPrincipal(
            new Claim(ClaimTypes.NameIdentifier, Guid.NewGuid().ToString()),
            new Claim(N2ClaimTypes.TenantMembership, $"{TenantId}:Acme"));
        IdentityUserContext ctx = new(principal);
        bool result = ctx.SetTenantContext("acme");
        Assert.IsTrue(result);
    }

    [TestMethod]
    public void SetTenantContext_UnknownTenant_ReturnsFalse()
    {
        ClaimsPrincipal principal = BuildPrincipal(
            new Claim(ClaimTypes.NameIdentifier, Guid.NewGuid().ToString()));
        IdentityUserContext ctx = new(principal);
        bool result = ctx.SetTenantContext(Guid.NewGuid());
        Assert.IsFalse(result);
    }

    // -------------------------------------------------------------------------
    // CurrentTenantName
    // -------------------------------------------------------------------------

    [TestMethod]
    public void CurrentTenantName_AfterSetTenantContext_ReturnsName()
    {
        ClaimsPrincipal principal = BuildPrincipal(
            new Claim(ClaimTypes.NameIdentifier, Guid.NewGuid().ToString()),
            new Claim(N2ClaimTypes.TenantMembership, $"{TenantId}:Acme"));
        IdentityUserContext ctx = new(principal);
        ctx.SetTenantContext(TenantId);
        Assert.AreEqual("Acme", ctx.CurrentTenantName);
    }

    // -------------------------------------------------------------------------
    // IsInRole
    // -------------------------------------------------------------------------

    [TestMethod]
    public void IsInRole_WithoutTenantContext_ReturnsFalse()
    {
        ClaimsPrincipal principal = BuildPrincipal(
            new Claim(ClaimTypes.NameIdentifier, Guid.NewGuid().ToString()),
            new Claim(N2ClaimTypes.TenantMembership, $"{TenantId}:Acme"),
            new Claim(N2ClaimTypes.TenantRole, $"{TenantId}:Admin"));
        IdentityUserContext ctx = new(principal);
        Assert.IsFalse(ctx.IsInRole("Admin"));
    }

    // -------------------------------------------------------------------------
    // Alert
    // -------------------------------------------------------------------------

    [TestMethod]
    public void Alert_AddsToAlertsList()
    {
        ClaimsPrincipal principal = BuildPrincipal(
            new Claim(ClaimTypes.NameIdentifier, Guid.NewGuid().ToString()));
        IdentityUserContext ctx = new(principal);
        ctx.Alert("test", Priority.Normal);
        Assert.AreEqual(1, ctx.Alerts.Count());
    }

    [TestMethod]
    public void Alert_DispatchesToAlertAction()
    {
        ClaimsPrincipal principal = BuildPrincipal(
            new Claim(ClaimTypes.NameIdentifier, Guid.NewGuid().ToString()));
        IdentityUserContext ctx = new(principal);
        UserAlert? received = null;
        ctx.AlertAction = a => received = a;
        ctx.Alert("hello", Priority.High);
        Assert.IsNotNull(received);
    }

    // -------------------------------------------------------------------------
    // Static members
    // -------------------------------------------------------------------------

    [TestMethod]
    public void SystemRolesSet_ContainsAdminRole()
    {
        Assert.IsTrue(IdentityUserContext.SystemRolesSet.Contains(SystemRoles.Admin));
    }

    [TestMethod]
    public void AnonymousUserId_EqualsEmptyGuid()
    {
        Assert.AreEqual(Guid.Empty, Guid.Parse(IdentityUserContext.AnonymousUserId));
    }
}
