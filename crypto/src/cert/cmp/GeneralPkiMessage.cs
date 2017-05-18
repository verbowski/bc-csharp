using java.security;
using Org.BouncyCastle.Asn1.Cmp;

namespace Org.BouncyCastle.Cert.Cmp
{ 
    /*
import java.io.IOException;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.cert.CertIOException;
*/
/**
 * General wrapper for a generic PKIMessage
 */
public class GeneralPKIMessage
{
    private readonly PkiMessage pkiMessage;

    private static PkiMessage parseBytes(byte[] encoding)
    {
        try
        {
            return PkiMessage.GetInstance(ASN1Primitive.fromByteArray(encoding));
        }
        catch (ClassCastException e)
        {
            throw new CertIOException("malformed data: " + e.Message, e);
        }
        catch (IllegalArgumentException e)
        {
            throw new CertIOException("malformed data: " + e.Message, e);
        }
    }

    /**
     * Create a PKIMessage from the passed in bytes.
     *
     * @param encoding BER/DER encoding of the PKIMessage
     * @throws IOException in the event of corrupted data, or an incorrect structure.
     */
    public GeneralPKIMessage(byte[] encoding): this(parseBytes(encoding))
    {
        
    }

    /**
     * Wrap a PKIMessage ASN.1 structure.
     *
     * @param pkiMessage base PKI message.
     */
    public GeneralPKIMessage(PkiMessage pkiMessage)
    {
        this.pkiMessage = pkiMessage;
    }

    public PkiHeader getHeader()
    {
        return pkiMessage.Header;
    }

    public PkiBody getBody()
    {
        return pkiMessage.Body;
    }

    /**
     * Return true if this message has protection bits on it. A return value of true
     * indicates the message can be used to construct a ProtectedPKIMessage.
     *
     * @return true if message has protection, false otherwise.
     */
    public bool hasProtection()
    {
        return pkiMessage.Header.ProtectionAlg != null;
    }

    public PkiMessage toASN1Structure()
    {
        return pkiMessage;
    }
}
}