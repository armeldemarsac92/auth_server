namespace AuthServer.Contracts.Exceptions;

public class DuplicateException : Exception
{
    public DuplicateException()
        : base("Duplicate entry found. Please check the data and try again. ")
    {
    }

    public DuplicateException(string message)
        : base(message)
    {
    }

    public DuplicateException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}