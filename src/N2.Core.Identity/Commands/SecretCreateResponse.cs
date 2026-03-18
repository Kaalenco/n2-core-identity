using N2.Core.Commands;
using N2.Core.Identity.Models;

namespace N2.Core.Identity.Commands;

public class SecretCreateResponse : CommandResponse<SecretCreateResultDto> {
    public SecretCreateResponse() { Status = ResponseStatus.ServerError; }
    public SecretCreateResponse(SecretCreateResultDto value) {
        Value = value;
        Status = ResponseStatus.Success;
    }
    public SecretCreateResponse(ResponseStatus status, string message) {
        Status = status;
        Message = message;
    }
}
