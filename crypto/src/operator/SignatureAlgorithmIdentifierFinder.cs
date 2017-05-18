using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Operator
{
    public interface SignatureAlgorithmIdentifierFinder
    {
        /**
         * Find the signature algorithm identifier that matches with
         * the passed in signature algorithm name.
         *
         * @param sigAlgName the name of the signature algorithm of interest.
         * @return an algorithm identifier for the corresponding signature.
         */
        AlgorithmIdentifier find(string sigAlgName);
    }
}