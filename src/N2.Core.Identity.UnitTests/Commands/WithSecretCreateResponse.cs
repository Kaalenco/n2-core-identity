using N2.Core.Commands;
using N2.Core.Identity.Commands;
using N2.Core.Identity.Models;

namespace N2.Core.Identity.UnitTests.Commands;

[TestClass]
public sealed class WithSecretCreateResponse
{
    // -------------------------------------------------------------------------
    // Default constructor
    // -------------------------------------------------------------------------

    [TestMethod]
    public void DefaultCtor_StatusIsServerError()
    {
        SecretCreateResponse response = new();
        Assert.AreEqual(ResponseStatus.ServerError, response.Status);
    }

    // -------------------------------------------------------------------------
    // (SecretCreateResultDto) constructor
    // -------------------------------------------------------------------------

    [TestMethod]
    public void ValueCtor_StatusIsSuccess()
    {
        SecretCreateResultDto dto = new() { Id = Guid.NewGuid(), PlainToken = "tok" };
        SecretCreateResponse response = new(dto);
        Assert.AreEqual(ResponseStatus.Success, response.Status);
        Assert.AreEqual(dto, response.Value);
    }

    // -------------------------------------------------------------------------
    // (ResponseStatus, string) constructor
    // -------------------------------------------------------------------------

    [TestMethod]
    public void ExplicitStatusCtor_SetsStatusAndMessage()
    {
        SecretCreateResponse response = new(ResponseStatus.BadRequest, "invalid request");
        Assert.AreEqual(ResponseStatus.BadRequest, response.Status);
        Assert.AreEqual("invalid request", response.Message);
    }
}
