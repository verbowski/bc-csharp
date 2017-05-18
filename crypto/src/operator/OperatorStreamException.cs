using System;

namespace Org.BouncyCastle.Operator
{ 

//import java.io.IOException;

public class OperatorStreamException : Exception
{
    private Exception cause;

public OperatorStreamException(string msg, Exception cause):base(msg)
{
   // super(msg);

    this.cause = cause;
}

public Exception getCause()
{
    return cause;
}
}
}