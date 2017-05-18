using System;
using System.Runtime.Serialization;

namespace Org.BouncyCastle.Cert.Crmf
{
    [Serializable]
    internal class OperatorCreationException : Exception
    {
        public OperatorCreationException()
        {
        }

        public OperatorCreationException(string message) : base(message)
        {
        }

        public OperatorCreationException(string message, Exception innerException) : base(message, innerException)
        {
        }

        protected OperatorCreationException(SerializationInfo info, StreamingContext context) : base(info, context)
        {
        }
    }
}