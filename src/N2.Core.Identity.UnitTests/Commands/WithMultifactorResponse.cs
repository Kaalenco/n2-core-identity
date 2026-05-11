using N2.Core.Commands;
using N2.Core.Identity.Commands;
using N2.Core.Identity.Data;

namespace N2.Core.Identity.UnitTests.Commands;

[TestClass]
public sealed class WithMultifactorResponse
{
    // -------------------------------------------------------------------------
    // Default constructor
    // -------------------------------------------------------------------------

    [TestMethod]
    public void DefaultCtor_StatusIsForbidden()
    {
        MultifactorResponse response = new();
        Assert.AreEqual(ResponseStatus.Forbidden, response.Status);
    }

    // -------------------------------------------------------------------------
    // (ResponseStatus, MultiFactorProperties) constructor
    // -------------------------------------------------------------------------

    [TestMethod]
    public void PropertiesCtor_SetsStatusAndValue()
    {
        MultiFactorProperties props = new() { MultiFactorType = MultiFactorType.Totp };
        MultifactorResponse response = new(ResponseStatus.Success, props);
        Assert.AreEqual(ResponseStatus.Success, response.Status);
        Assert.AreEqual(props, response.Value);
    }

    // -------------------------------------------------------------------------
    // (ResponseStatus, string) constructor
    // -------------------------------------------------------------------------

    [TestMethod]
    public void MessageCtor_SetsStatusAndMessage()
    {
        MultifactorResponse response = new(ResponseStatus.Unauthorized, "Invalid code");
        Assert.AreEqual(ResponseStatus.Unauthorized, response.Status);
        Assert.AreEqual("Invalid code", response.Message);
    }

    // -------------------------------------------------------------------------
    // Failed()
    // -------------------------------------------------------------------------

    [TestMethod]
    public void Failed_StatusIsBadRequest()
    {
        MultifactorResponse response = MultifactorResponse.Failed("bad input");
        Assert.AreEqual(ResponseStatus.BadRequest, response.Status);
    }

    [TestMethod]
    public void Failed_PreservesMessage()
    {
        MultifactorResponse response = MultifactorResponse.Failed("bad input");
        Assert.AreEqual("bad input", response.Message);
    }

    // -------------------------------------------------------------------------
    // Ok()
    // -------------------------------------------------------------------------

    [TestMethod]
    public void Ok_StatusIsSuccess()
    {
        MultifactorResponse response = MultifactorResponse.Ok();
        Assert.AreEqual(ResponseStatus.Success, response.Status);
    }
}
