using System;

namespace Org.BouncyCastle.Cert
{

/**
 * General checked Exception thrown in the cert package and its sub-packages.
 */
public class CertException : Exception
{
    private Exception cause;

public CertException(string msg, Exception cause):base(msg)
{
//    super(msg);

    this.cause = cause;
}

public CertException(String msg):base(msg)
{
//    super(msg);
}

public Exception getCause()
{
    return cause;
}
}
}