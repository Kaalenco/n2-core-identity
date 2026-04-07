using N2.Core.Commands;
using N2.Core.Identity.Data;

namespace N2.Core.Identity.Commands;

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