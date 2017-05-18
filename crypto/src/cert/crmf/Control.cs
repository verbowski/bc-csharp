//https://github.com/bcgit/bc-java/blob/master/pkix/src/main/java/org/bouncycastle/cert/crmf/Control.java
using Org.BouncyCastle.Asn1;

namespace Org.BouncyCastle.Cert.Crmf
{

//    import org.bouncycastle.asn1.ASN1Encodable;
//    import org.bouncycastle.asn1.ASN1ObjectIdentifier;

    /**
     * Generic interface for a CertificateRequestMessage control value.
     */
    public interface Control
    {
        /**
         * Return the type of this control.
         *
         * @return an ASN1ObjectIdentifier representing the type.
         */
        DerObjectIdentifier getType();
        Asn1Encodable getValue();
    }
}