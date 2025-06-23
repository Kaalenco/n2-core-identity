using N2.Core.Commands;
using N2.Core.Identity.Data;

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
            ? ResponseStatus.Accepted
            : ResponseStatus.NotFound;

    }

    public ApplicationUserResponse(ApplicationUser value, ResponseStatus responseStatus)
    {
        Status = responseStatus;
        Value = value;
    }
}
