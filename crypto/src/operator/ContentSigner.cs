using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Operator
{
    /// <summary>
    /// https://github.com/bcgit/bc-java/blob/master/pkix/src/main/java/org/bouncycastle/operator/ContentSigner.java
    /// </summary>
    public interface ContentSigner
    {
        AlgorithmIdentifier getAlgorithmIdentifier();

        /**
         * Returns a stream that will accept data for the purpose of calculating
         * a signature. Use org.bouncycastle.util.io.TeeOutputStream if you want to accumulate
         * the data on the fly as well.
         *
         * @return an OutputStream
         */
        System.IO.Stream getOutputStream(); //java.io.OutputStream

        /**
         * Returns a signature based on the current data written to the stream, since the
         * start or the last call to getSignature().
         *
         * @return bytes representing the signature.
         */
        byte[] getSignature();
    }
}