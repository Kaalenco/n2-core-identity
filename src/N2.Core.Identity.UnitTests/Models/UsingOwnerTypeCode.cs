using N2.Core.Identity.Models;

namespace N2.Core.Identity.UnitTests.Models;

[TestClass]
public sealed class UsingOwnerTypeCode
{
    // -------------------------------------------------------------------------
    // Compute
    // -------------------------------------------------------------------------

    [TestMethod]
    public void Compute_ReturnsEightCharacterString()
    {
        string code = OwnerTypeCode.Compute("TestType");
        Assert.AreEqual(8, code.Length);
    }

    [TestMethod]
    public void Compute_IsDeterministic()
    {
        string first = OwnerTypeCode.Compute("ApplicationUser");
        string second = OwnerTypeCode.Compute("ApplicationUser");
        Assert.AreEqual(first, second);
    }

    [TestMethod]
    public void Compute_DifferentInputs_YieldDifferentCodes()
    {
        string userCode = OwnerTypeCode.Compute("ApplicationUser");
        string tenantCode = OwnerTypeCode.Compute("ApplicationTenant");
        Assert.AreNotEqual(userCode, tenantCode);
    }

    // -------------------------------------------------------------------------
    // Pre-computed constants
    // -------------------------------------------------------------------------

    [TestMethod]
    public void User_MatchesComputedValue()
    {
        Assert.AreEqual(OwnerTypeCode.Compute("ApplicationUser"), OwnerTypeCode.User);
    }

    [TestMethod]
    public void Application_MatchesComputedValue()
    {
        Assert.AreEqual(OwnerTypeCode.Compute("ApplicationDefinition"), OwnerTypeCode.Application);
    }

    [TestMethod]
    public void Tenant_MatchesComputedValue()
    {
        Assert.AreEqual(OwnerTypeCode.Compute("ApplicationTenant"), OwnerTypeCode.Tenant);
    }

    [TestMethod]
    public void AllPrecomputedConstants_HaveEightCharacters()
    {
        Assert.AreEqual(8, OwnerTypeCode.User.Length);
        Assert.AreEqual(8, OwnerTypeCode.Application.Length);
        Assert.AreEqual(8, OwnerTypeCode.Tenant.Length);
    }
}
