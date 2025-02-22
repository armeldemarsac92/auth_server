namespace AuthServer.Contracts.Exceptions;

public enum DatabaseObjectType
{
    Table,
    Column,
    Function,
    Parameter,
    Cursor,
    Database,
    Schema,
    Alias
}

public enum DatabaseConnectionError
{
    General,
    TooManyConnections,
    ConnectionDoesNotExist,
    ConnectionFailure,
    UnableToEstablish,
    Rejected,
    Communication
}

public class DatabaseUniqueViolationException : DatabaseException
{
    public string ConstraintName { get; }

    public DatabaseUniqueViolationException(string message, string constraintName, Exception innerException) 
        : base(message, innerException)
    {
        ConstraintName = constraintName;
    }
}

public class DatabaseForeignKeyViolationException : DatabaseException
{
    public string ConstraintName { get; }

    public DatabaseForeignKeyViolationException(string message, string constraintName, Exception innerException) 
        : base(message, innerException)
    {
        ConstraintName = constraintName;
    }
}

public class DatabaseNotNullViolationException : DatabaseException
{
    public string ColumnName { get; }

    public DatabaseNotNullViolationException(string message, string columnName, Exception innerException) 
        : base(message, innerException)
    {
        ColumnName = columnName;
    }
}

public class DatabaseCheckViolationException : DatabaseException
{
    public string ConstraintName { get; }

    public DatabaseCheckViolationException(string message, string constraintName, Exception innerException) 
        : base(message, innerException)
    {
        ConstraintName = constraintName;
    }
}

public class DatabaseExclusionViolationException : DatabaseException
{
    public string ConstraintName { get; }

    public DatabaseExclusionViolationException(string message, string constraintName, Exception innerException) 
        : base(message, innerException)
    {
        ConstraintName = constraintName;
    }
}

public class DatabaseObjectNotFoundException : DatabaseException
{
    public DatabaseObjectType ObjectType { get; }

    public DatabaseObjectNotFoundException(string message, DatabaseObjectType objectType, Exception innerException) 
        : base(message, innerException)
    {
        ObjectType = objectType;
    }
}

public class DatabaseDuplicateObjectException : DatabaseException
{
    public DatabaseObjectType ObjectType { get; }

    public DatabaseDuplicateObjectException(string message, DatabaseObjectType objectType, Exception innerException) 
        : base(message, innerException)
    {
        ObjectType = objectType;
    }
}

public class DatabaseSyntaxException : DatabaseException
{
    public DatabaseSyntaxException(string message, Exception innerException) 
        : base(message, innerException)
    {
    }
}

public class DatabasePermissionException : DatabaseException
{
    public DatabasePermissionException(string message, Exception innerException) 
        : base(message, innerException)
    {
    }
}

public class DatabaseConnectionException : DatabaseException
{
    public DatabaseConnectionError ErrorType { get; }

    public DatabaseConnectionException(string message, DatabaseConnectionError errorType, Exception innerException) 
        : base(message, innerException)
    {
        ErrorType = errorType;
    }
}

public class DatabaseConfigurationException : DatabaseException
{
    public DatabaseConfigurationException(string message, Exception innerException) 
        : base(message, innerException)
    {
    }
}

public class DatabaseDataException : DatabaseException
{
    public DatabaseDataException(string message, Exception innerException) 
        : base(message, innerException)
    {
    }
}

public class DatabaseTimeoutException : DatabaseException
{
    public DatabaseTimeoutException(string message, Exception innerException) 
        : base(message, innerException)
    {
    }
}