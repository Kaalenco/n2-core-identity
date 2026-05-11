using N2.Core.Commands;
using N2.Core.Identity.Commands;
using N2.Core.Identity.Data;

namespace N2.Core.Identity.UnitTests.Commands;

[TestClass]
public sealed class WithApplicationUserResponse
{
    // -------------------------------------------------------------------------
    // Default constructor
    // -------------------------------------------------------------------------

    [TestMethod]
    public void DefaultCtor_StatusIsForbidden()
    {
        ApplicationUserResponse response = new();
        Assert.AreEqual(ResponseStatus.Forbidden, response.Status);
    }

    // -------------------------------------------------------------------------
    // (ApplicationUser?) constructor
    // -------------------------------------------------------------------------

    [TestMethod]
    public void ValueCtor_NullValue_StatusIsNotFound()
    {
        ApplicationUserResponse response = new(value: null);
        Assert.AreEqual(ResponseStatus.NotFound, response.Status);
        Assert.IsNull(response.Value);
    }

    [TestMethod]
    public void ValueCtor_NonNullValue_StatusIsSuccess()
    {
        ApplicationUser user = new() { UserName = "testuser" };
        ApplicationUserResponse response = new(user);
        Assert.AreEqual(ResponseStatus.Success, response.Status);
        Assert.AreEqual(user, response.Value);
    }

    // -------------------------------------------------------------------------
    // (ApplicationUser, ResponseStatus) constructor
    // -------------------------------------------------------------------------

    [TestMethod]
    public void ExplicitStatusCtor_SetsStatusAndValue()
    {
        ApplicationUser user = new() { UserName = "testuser" };
        ApplicationUserResponse response = new(user, ResponseStatus.Accepted);
        Assert.AreEqual(ResponseStatus.Accepted, response.Status);
        Assert.AreEqual(user, response.Value);
    }
}
