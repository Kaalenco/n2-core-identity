using N2.Core.Commands;
using N2.Core.Identity.Commands;
using N2.Core.Identity.Models;

namespace N2.Core.Identity.UnitTests.Commands;

[TestClass]
public sealed class WithSecretResponse
{
    // -------------------------------------------------------------------------
    // Default constructor
    // -------------------------------------------------------------------------

    [TestMethod]
    public void DefaultCtor_StatusIsForbidden()
    {
        SecretResponse response = new();
        Assert.AreEqual(ResponseStatus.Forbidden, response.Status);
    }

    // -------------------------------------------------------------------------
    // (ApplicationSecretDto?) constructor
    // -------------------------------------------------------------------------

    [TestMethod]
    public void ValueCtor_NullValue_StatusIsNotFound()
    {
        SecretResponse response = new(value: null);
        Assert.AreEqual(ResponseStatus.NotFound, response.Status);
        Assert.IsNull(response.Value);
    }

    [TestMethod]
    public void ValueCtor_NonNullValue_StatusIsSuccess()
    {
        ApplicationSecretDto dto = new() { Id = Guid.NewGuid(), Name = "my-secret" };
        SecretResponse response = new(dto);
        Assert.AreEqual(ResponseStatus.Success, response.Status);
        Assert.AreEqual(dto, response.Value);
    }

    // -------------------------------------------------------------------------
    // (ApplicationSecretDto, ResponseStatus) constructor
    // -------------------------------------------------------------------------

    [TestMethod]
    public void ExplicitStatusCtor_SetsStatusAndValue()
    {
        ApplicationSecretDto dto = new() { Id = Guid.NewGuid() };
        SecretResponse response = new(dto, ResponseStatus.Accepted);
        Assert.AreEqual(ResponseStatus.Accepted, response.Status);
        Assert.AreEqual(dto, response.Value);
    }
}
