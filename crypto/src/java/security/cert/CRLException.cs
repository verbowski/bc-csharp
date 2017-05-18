using System;

namespace java.security.cert
{
    public class CRLException : GeneralSecurityException
    {
        public CRLException()
        {
        }

        public CRLException(String msg) : base(msg)
        {
            //        super(msg);
        }
    }
}