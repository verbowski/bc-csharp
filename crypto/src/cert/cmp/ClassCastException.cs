using System;
using System.Runtime.Serialization;

namespace Org.BouncyCastle.Cert.Cmp
{
    [Serializable]
    internal class ClassCastException : Exception
    {
        public ClassCastException()
        {
        }

        public ClassCastException(string message) : base(message)
        {
        }

        public ClassCastException(string message, Exception innerException) : base(message, innerException)
        {
        }

        protected ClassCastException(SerializationInfo info, StreamingContext context) : base(info, context)
        {
        }
    }
}