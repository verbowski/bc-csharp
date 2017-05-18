using System;
using System.Collections.Generic;
using System.Text;

namespace java.security
{
    public class System
    {
        static SecurityManager _sm = new SecurityManager();
        internal static SecurityManager getSecurityManager()
        {
            return _sm;
        }
    }
}