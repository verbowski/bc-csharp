using System;
using System.Collections.Generic;
using System.Text;

namespace java.security
{
    public class RuntimeException : Exception
    {
        static readonly long serialVersionUID = -7034897190745766939L;
        public RuntimeException() : base() { }
        public RuntimeException(string msg) : base(msg) { }
        public RuntimeException(string msg, Exception cause) : base(msg, cause) { }
        public RuntimeException(Exception cause) : base() { }
        protected RuntimeException(string message, Exception cause,
                           bool enableSuppression,
                           bool writableStackTrace):base(message,cause)
        {
//            base(message, cause, enableSuppression, writableStackTrace);
        }
    }
}
