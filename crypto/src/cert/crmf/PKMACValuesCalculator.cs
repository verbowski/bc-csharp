using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Cert.Crmf
{
    public interface PKMACValuesCalculator
    {
        void setup(AlgorithmIdentifier digestAlg, AlgorithmIdentifier macAlg);

        byte[] calculateDigest(byte[] data);

        byte[] calculateMac(byte[] pwd, byte[] data);
    }
}