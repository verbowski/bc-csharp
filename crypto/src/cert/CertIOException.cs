using System;
using System.IO;

namespace Org.BouncyCastle.Cert
{
//import java.io.IOException;

/**
 * General IOException thrown in the cert package and its sub-packages.
 */
public class CertIOException : IOException
{
    private Exception cause;

public CertIOException(string msg, Exception cause):base(msg)
{
//    super(msg);

    this.cause = cause;
}

public CertIOException(string msg):base(msg)
{
//    super(msg);
}

public Exception getCause()
{
    return cause;
}
}
}