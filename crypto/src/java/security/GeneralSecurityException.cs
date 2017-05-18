using System;

namespace java.security
{
    public class GeneralSecurityException : Exception
    {
        public GeneralSecurityException()
        {
        }

        public GeneralSecurityException(string msg) : base(msg)
        {
        }
    }
}