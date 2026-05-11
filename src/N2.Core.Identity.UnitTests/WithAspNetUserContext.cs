using N2.Core.Identity.Data;

namespace N2.Core.Identity.UnitTests;

[TestClass]
public sealed class WithAspNetUserContext
{
    private static readonly Guid TenantAlphaId = new("11111111-0000-0000-0000-000000000000");
    private static readonly Guid TenantBetaId = new("22222222-0000-0000-0000-000000000000");

    private static IList<(Guid, string, IReadOnlyList<string>)> TwoTenants() =>
        new List<(Guid, string, IReadOnlyList<string>)>
        {
            (TenantAlphaId, "Alpha", new string[] { "Admin", "User" }),
            (TenantBetaId, "Beta", new string[] { "User" })
        };

    private static AspNetUserContext BuildWithUser(Action<UserAlert>? alertAction = null) =>
        new(
            new ApplicationUser { Id = Guid.NewGuid(), UserName = "alice", Email = "alice@test.com" },
            TwoTenants(),
            [],
            alertAction);

    private static AspNetUserContext BuildAnonymous() => new(null!, [], [], null);

    // -------------------------------------------------------------------------
    // Constructor — authenticated user
    // -------------------------------------------------------------------------

    [TestMethod]
    public void Constructor_WithUser_IsAuthenticated()
    {
        AspNetUserContext ctx = BuildWithUser();
        Assert.IsTrue(ctx.IsAuthenticated);
    }

    [TestMethod]
    public void Constructor_WithUser_CopiesUserFields()
    {
        Guid id = Guid.NewGuid();
        ApplicationUser user = new() { Id = id, UserName = "bob", Email = "bob@test.com" };
        AspNetUserContext ctx = new(user, [], [], null);
        Assert.AreEqual(id, ctx.PublicId);
        Assert.AreEqual("bob", ctx.UserName);
        Assert.AreEqual("bob@test.com", ctx.Email);
    }

    // -------------------------------------------------------------------------
    // Constructor — anonymous
    // -------------------------------------------------------------------------

    [TestMethod]
    public void Constructor_NullUser_IsNotAuthenticated()
    {
        AspNetUserContext ctx = BuildAnonymous();
        Assert.IsFalse(ctx.IsAuthenticated);
    }

    [TestMethod]
    public void Constructor_NullUser_UserNameIsAnonymous()
    {
        AspNetUserContext ctx = BuildAnonymous();
        Assert.AreEqual("anonymous", ctx.UserName);
    }

    // -------------------------------------------------------------------------
    // SetTenantContext — by Guid
    // -------------------------------------------------------------------------

    [TestMethod]
    public void SetTenantContext_KnownGuid_ReturnsTrue()
    {
        AspNetUserContext ctx = BuildWithUser();
        bool result = ctx.SetTenantContext(TenantAlphaId);
        Assert.IsTrue(result);
    }

    [TestMethod]
    public void SetTenantContext_UnknownGuid_ReturnsFalse()
    {
        AspNetUserContext ctx = BuildWithUser();
        bool result = ctx.SetTenantContext(Guid.NewGuid());
        Assert.IsFalse(result);
    }

    [TestMethod]
    public void SetTenantContext_KnownGuid_UpdatesCurrentTenantId()
    {
        AspNetUserContext ctx = BuildWithUser();
        ctx.SetTenantContext(TenantAlphaId);
        Assert.AreEqual(TenantAlphaId, ctx.CurrentTenantId);
    }

    // -------------------------------------------------------------------------
    // SetTenantContext — by name
    // -------------------------------------------------------------------------

    [TestMethod]
    public void SetTenantContext_NameCaseInsensitive_ReturnsTrue()
    {
        AspNetUserContext ctx = BuildWithUser();
        bool result = ctx.SetTenantContext("alpha");
        Assert.IsTrue(result);
    }

    [TestMethod]
    public void SetTenantContext_UnknownName_ReturnsFalse()
    {
        AspNetUserContext ctx = BuildWithUser();
        bool result = ctx.SetTenantContext("NoSuchTenant");
        Assert.IsFalse(result);
    }

    // -------------------------------------------------------------------------
    // CurrentTenantName
    // -------------------------------------------------------------------------

    [TestMethod]
    public void CurrentTenantName_AfterSetTenantContext_ReturnsName()
    {
        AspNetUserContext ctx = BuildWithUser();
        ctx.SetTenantContext(TenantAlphaId);
        Assert.AreEqual("Alpha", ctx.CurrentTenantName);
    }

    [TestMethod]
    public void CurrentTenantName_WithoutContext_ReturnsEmpty()
    {
        AspNetUserContext ctx = BuildWithUser();
        Assert.AreEqual(string.Empty, ctx.CurrentTenantName);
    }

    // -------------------------------------------------------------------------
    // IsInTenant
    // -------------------------------------------------------------------------

    [TestMethod]
    public void IsInTenant_KnownGuid_ReturnsTrue()
    {
        AspNetUserContext ctx = BuildWithUser();
        Assert.IsTrue(ctx.IsInTenant(TenantAlphaId));
    }

    [TestMethod]
    public void IsInTenant_KnownName_ReturnsTrue()
    {
        AspNetUserContext ctx = BuildWithUser();
        Assert.IsTrue(ctx.IsInTenant("Beta"));
    }

    [TestMethod]
    public void IsInTenant_UnknownGuid_ReturnsFalse()
    {
        AspNetUserContext ctx = BuildWithUser();
        Assert.IsFalse(ctx.IsInTenant(Guid.NewGuid()));
    }

    // -------------------------------------------------------------------------
    // IsInRole
    // -------------------------------------------------------------------------

    [TestMethod]
    public void IsInRole_WithTenantContext_KnownRole_ReturnsTrue()
    {
        AspNetUserContext ctx = BuildWithUser();
        ctx.SetTenantContext(TenantAlphaId);
        Assert.IsTrue(ctx.IsInRole("Admin"));
    }

    [TestMethod]
    public void IsInRole_WithoutTenantContext_ReturnsFalse()
    {
        AspNetUserContext ctx = BuildWithUser();
        Assert.IsFalse(ctx.IsInRole("Admin"));
    }

    [TestMethod]
    public void IsInRole_TenantDoesNotHaveRole_ReturnsFalse()
    {
        AspNetUserContext ctx = BuildWithUser();
        ctx.SetTenantContext(TenantBetaId);
        Assert.IsFalse(ctx.IsInRole("Admin"));
    }

    // -------------------------------------------------------------------------
    // CurrentRoles
    // -------------------------------------------------------------------------

    [TestMethod]
    public void CurrentRoles_WithTenantContext_ReturnsRoles()
    {
        AspNetUserContext ctx = BuildWithUser();
        ctx.SetTenantContext(TenantAlphaId);
        CollectionAssert.AreEquivalent(new[] { "Admin", "User" }, ctx.CurrentRoles().ToList());
    }

    [TestMethod]
    public void CurrentRoles_WithoutTenantContext_ReturnsEmpty()
    {
        AspNetUserContext ctx = BuildWithUser();
        Assert.IsFalse(ctx.CurrentRoles().Any());
    }

    // -------------------------------------------------------------------------
    // Alert
    // -------------------------------------------------------------------------

    [TestMethod]
    public void Alert_AddsToAlertsList()
    {
        AspNetUserContext ctx = BuildWithUser();
        ctx.Alert("test message", Priority.High);
        Assert.AreEqual(1, ctx.Alerts.Count());
    }

    [TestMethod]
    public void Alert_DispatchesToAlertAction()
    {
        UserAlert? received = null;
        AspNetUserContext ctx = BuildWithUser(alertAction: a => received = a);
        ctx.Alert("hello", Priority.Low);
        Assert.IsNotNull(received);
    }

    // -------------------------------------------------------------------------
    // TenantMemberships
    // -------------------------------------------------------------------------

    [TestMethod]
    public void TenantMemberships_ReturnsAllTenants()
    {
        AspNetUserContext ctx = BuildWithUser();
        Assert.AreEqual(2, ctx.TenantMemberships.Count());
    }
}
