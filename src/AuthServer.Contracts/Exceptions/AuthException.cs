namespace AuthServer.Contracts.Exceptions;

public class AuthException : Exception
{
    public AuthException(string message)
        : base(message)
    {
    }

    public AuthException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}