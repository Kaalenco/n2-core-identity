using N2.Core.Commands;
using N2.Core.Identity.Data;
using N2.Core.Identity.Models;

using System.Runtime.CompilerServices;

namespace N2.Core.Identity.Commands;

public class ApplicationUserResponse : CommandResponse<ApplicationUser>
{
    public ApplicationUserResponse()
    {
        Status = ResponseStatus.Forbidden;
    }

    public ApplicationUserResponse(ApplicationUser? value)
    {
        Value = value;
        Status = value != null
            ? ResponseStatus.Success
            : ResponseStatus.NotFound;

    }

    public ApplicationUserResponse(ApplicationUser value, ResponseStatus responseStatus)
    {
        Status = responseStatus;
        Value = value;
    }
}

public class ApplicationTenantResponse : CommandResponse<ApplicationTenant> {
    public ApplicationTenantResponse() {
        Status = ResponseStatus.Forbidden;
    }

    public ApplicationTenantResponse(ApplicationTenant? value) {
        Value = value;
        Status = value != null
            ? ResponseStatus.Success
            : ResponseStatus.NotFound;

    }

    public ApplicationTenantResponse(ApplicationTenant value, ResponseStatus responseStatus) {
        Status = responseStatus;
        Value = value;
    }
}