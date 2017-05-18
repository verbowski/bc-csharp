using System;
using System.Collections.Generic;
using System.Text;

namespace java.security
{
    public class NoSuchAlgorithmException : GeneralSecurityException
    {
        public NoSuchAlgorithmException()
        {
        }

        public NoSuchAlgorithmException(string msg) : base(msg)
        {
            //        super(msg);
        }
    }
}
