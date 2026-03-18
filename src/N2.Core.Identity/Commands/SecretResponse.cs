using N2.Core.Commands;
using N2.Core.Identity.Models;

namespace N2.Core.Identity.Commands;

public class SecretResponse : CommandResponse<ApplicationSecretDto>
{
    public SecretResponse()
    {
        Status = ResponseStatus.Forbidden;
    }
    public SecretResponse(ApplicationSecretDto? value)
    {
        Value = value;
        Status = value != null
            ? ResponseStatus.Success
            : ResponseStatus.NotFound;
    }
    public SecretResponse(ApplicationSecretDto value, ResponseStatus responseStatus)
    {
        Status = responseStatus;
        Value = value;
    }
}
