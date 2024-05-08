namespace N2.Core.Identity;

public class AuthenticationException : Exception
{
    public AuthenticationException(string message) : base(message)
    {
    }

    public AuthenticationException()
    {
    }

    public AuthenticationException(string message, Exception innerException) : base(message, innerException)
    {
    }
}