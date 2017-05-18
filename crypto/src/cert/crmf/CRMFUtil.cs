// https://github.com/bcgit/bc-java/blob/master/pkix/src/main/java/org/bouncycastle/cert/crmf/CRMFUtil.java

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using System.IO;

namespace Org.BouncyCastle.Cert.Crmf
{ 
    /*
    import java.io.IOException;
    import java.io.OutputStream;

    import org.bouncycastle.asn1.ASN1Encodable;
    import org.bouncycastle.asn1.ASN1ObjectIdentifier;
    import org.bouncycastle.asn1.DEROutputStream;
    import org.bouncycastle.asn1.x509.ExtensionsGenerator;
    import org.bouncycastle.cert.CertIOException;
    */
    class CRMFUtil
    {
        public static void derEncodeToStream(Asn1Encodable obj, Stream stream)
        {
            DerOutputStream dOut = new DerOutputStream(stream);

            try
            {
                dOut.WriteObject(obj);

                dOut.Close();
            }
            catch (IOException e)
            {
                throw new CRMFRuntimeException("unable to DER encode object: " + e.Message, e);
            }
        }

        public static void addExtension(X509ExtensionsGenerator extGenerator, DerObjectIdentifier oid, bool isCritical, Asn1Encodable value)
        {
        try
        {
                extGenerator.AddExtension(oid, isCritical, value);
            }
        catch (IOException e)
        {
                throw new CertIOException("cannot encode extension: " + e.Message, e);
            }
        }
    }
}