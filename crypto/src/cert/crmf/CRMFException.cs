// https://github.com/bcgit/bc-java/blob/master/pkix/src/main/java/org/bouncycastle/cert/crmf/CRMFException.java
using System;

namespace Org.BouncyCastle.Cert.Crmf
{
    public class CRMFException : Exception
    {
        private Exception cause;

        public CRMFException(String msg, Exception cause) : base(msg)
        {
            //    super(msg);

            this.cause = cause;
        }

        public Exception getCause()
        {
            return cause;
        }
    }
}