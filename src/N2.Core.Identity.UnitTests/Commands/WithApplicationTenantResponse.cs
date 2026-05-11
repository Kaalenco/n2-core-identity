using N2.Core.Commands;
using N2.Core.Identity.Commands;
using N2.Core.Identity.Data;

namespace N2.Core.Identity.UnitTests.Commands;

[TestClass]
public sealed class WithApplicationTenantResponse
{
    // -------------------------------------------------------------------------
    // Default constructor
    // -------------------------------------------------------------------------

    [TestMethod]
    public void DefaultCtor_StatusIsForbidden()
    {
        ApplicationTenantResponse response = new();
        Assert.AreEqual(ResponseStatus.Forbidden, response.Status);
    }

    // -------------------------------------------------------------------------
    // (ApplicationTenant?) constructor
    // -------------------------------------------------------------------------

    [TestMethod]
    public void ValueCtor_NullValue_StatusIsNotFound()
    {
        ApplicationTenantResponse response = new(value: null);
        Assert.AreEqual(ResponseStatus.NotFound, response.Status);
        Assert.IsNull(response.Value);
    }

    [TestMethod]
    public void ValueCtor_NonNullValue_StatusIsSuccess()
    {
        ApplicationTenant tenant = new() { Id = Guid.NewGuid(), Name = "Acme" };
        ApplicationTenantResponse response = new(tenant);
        Assert.AreEqual(ResponseStatus.Success, response.Status);
        Assert.AreEqual(tenant, response.Value);
    }

    // -------------------------------------------------------------------------
    // (ApplicationTenant, ResponseStatus) constructor
    // -------------------------------------------------------------------------

    [TestMethod]
    public void ExplicitStatusCtor_SetsStatusAndValue()
    {
        ApplicationTenant tenant = new() { Id = Guid.NewGuid() };
        ApplicationTenantResponse response = new(tenant, ResponseStatus.Accepted);
        Assert.AreEqual(ResponseStatus.Accepted, response.Status);
        Assert.AreEqual(tenant, response.Value);
    }
}
