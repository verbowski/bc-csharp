using System;
using System.Runtime.Serialization;

namespace javax.crypto
{
    [Serializable]
    internal class CloneNotSupportedException : Exception
    {
        public CloneNotSupportedException()
        {
        }

        public CloneNotSupportedException(string message) : base(message)
        {
        }

        public CloneNotSupportedException(string message, Exception innerException) : base(message, innerException)
        {
        }

        protected CloneNotSupportedException(SerializationInfo info, StreamingContext context) : base(info, context)
        {
        }
    }
}