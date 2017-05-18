using System;

namespace java.security
{
    internal class RuntimePermission : Permission
    {
        public RuntimePermission(string msg) : base(msg) { }

        public override bool equals(object obj)
        {
            throw new NotImplementedException();
        }

        public override string getActions()
        {
            throw new NotImplementedException();
        }

        public override int hashCode()
        {
            throw new NotImplementedException();
        }

        public override bool implies(Permission permission)
        {
            throw new NotImplementedException();
        }
    }
}