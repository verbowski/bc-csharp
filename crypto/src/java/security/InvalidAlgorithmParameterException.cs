using System;
using System.Collections.Generic;
using System.Text;

namespace java.security
{
    public class InvalidAlgorithmParameterException : GeneralSecurityException
    {
    public InvalidAlgorithmParameterException()
    {
    }

    public InvalidAlgorithmParameterException(String msg):base(msg)
    {
//        super(msg);
    }
}
}
