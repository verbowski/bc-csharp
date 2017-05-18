using System;
using System.Collections.Generic;
using System.Text;

namespace java.security
{
    public class NoSuchProviderException : GeneralSecurityException
    {
        public NoSuchProviderException()
        {
        }
        public NoSuchProviderException(string msg) : base(msg)
        {
            //        super(msg);
        }
    }
}
