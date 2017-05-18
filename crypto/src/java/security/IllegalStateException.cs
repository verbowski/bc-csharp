using System;
using System.Collections.Generic;
using System.Text;

namespace java.security
{
    public class IllegalStateException: RuntimeException
    {
        static readonly long serialVersionUID = -1848914673093119416L;
        public IllegalStateException() : base() { }
        public IllegalStateException(string msg) : base(msg) { }
        public IllegalStateException(string msg, Exception cause) : base(msg,cause) { }
        public IllegalStateException(Exception cause) : base(cause) { }
    }
}
