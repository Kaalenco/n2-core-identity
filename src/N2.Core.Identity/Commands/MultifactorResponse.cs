using N2.Core.Commands;

namespace N2.Core.Identity.Commands;

public class MultifactorResponse : CommandResponse<MultiFactorProperties> {
    public MultifactorResponse() {
        Status = ResponseStatus.Forbidden;
    }

    public MultifactorResponse(ResponseStatus status, MultiFactorProperties value) {
        Status = status;
        Value = value;
    }

    public MultifactorResponse(ResponseStatus status, string message) {
        Status = status;
        Message = message;
    }

    public static MultifactorResponse Failed(string message) {
        MultifactorResponse result = new() {
            Message = message,
            Status = ResponseStatus.BadRequest
        };
        return result;
    }

    public static MultifactorResponse Ok() {
        return new() {
            Status = ResponseStatus.Success
        };
    }
}