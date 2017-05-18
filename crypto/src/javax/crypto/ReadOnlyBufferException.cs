using System;
using System.Runtime.Serialization;

namespace javax.crypto
{
    [Serializable]
    internal class ReadOnlyBufferException : Exception
    {
        public ReadOnlyBufferException()
        {
        }

        public ReadOnlyBufferException(string message) : base(message)
        {
        }

        public ReadOnlyBufferException(string message, Exception innerException) : base(message, innerException)
        {
        }

        protected ReadOnlyBufferException(SerializationInfo info, StreamingContext context) : base(info, context)
        {
        }
    }
}