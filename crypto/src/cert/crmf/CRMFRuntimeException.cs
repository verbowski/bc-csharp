// https://github.com/bcgit/bc-java/blob/master/pkix/src/main/java/org/bouncycastle/cert/crmf/CRMFRuntimeException.java
using System;

namespace Org.BouncyCastle.Cert.Crmf
{
    public class CRMFRuntimeException : SystemException
    {
        private Exception cause;

        public CRMFRuntimeException(string msg, Exception cause) : base(msg)
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