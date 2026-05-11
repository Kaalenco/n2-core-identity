using N2.Core.Identity;

namespace N2.Core.Identity.UnitTests;

[TestClass]
public sealed class ForAuthenticationExceptionUnitTests
{
    // -------------------------------------------------------------------------
    // Default constructor
    // -------------------------------------------------------------------------

    [TestMethod]
    public void DefaultCtor_MessageIsNonEmpty()
    {
        AuthenticationException ex = new();
        Assert.IsFalse(string.IsNullOrEmpty(ex.Message));
    }

    [TestMethod]
    public void DefaultCtor_IsAssignableToException()
    {
        AuthenticationException ex = new();
        Assert.IsInstanceOfType<Exception>(ex);
    }

    // -------------------------------------------------------------------------
    // String constructor
    // -------------------------------------------------------------------------

    [TestMethod]
    public void StringCtor_PreservesMessage()
    {
        AuthenticationException ex = new("authentication failed");
        Assert.AreEqual("authentication failed", ex.Message);
    }

    // -------------------------------------------------------------------------
    // String + inner constructor
    // -------------------------------------------------------------------------

    [TestMethod]
    public void StringInnerCtor_ChainsCorrectly()
    {
        InvalidOperationException inner = new("inner reason");
        AuthenticationException ex = new("outer message", inner);
        Assert.AreEqual("outer message", ex.Message);
        Assert.AreEqual(inner, ex.InnerException);
    }
}
