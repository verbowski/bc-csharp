using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Crmf;

namespace Org.BouncyCastle.Cert.Crmf
{ 
    /*
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.crmf.CRMFObjectIdentifiers;
*/
/**
 * Carrier for a registration token control.
 */
public class RegTokenControl : Control
{
    private static readonly DerObjectIdentifier type = CrmfObjectIdentifiers.id_regCtrl_regToken;

    private readonly DerUtf8String token;

    /**
     * Basic constructor - build from a UTF-8 string representing the token.
     *
     * @param token UTF-8 string representing the token.
     */
    public RegTokenControl(DerUtf8String token)
{
    this.token = token;
}

/**
 * Basic constructor - build from a string representing the token.
 *
 * @param token string representing the token.
 */
public RegTokenControl(string token)
{
    this.token = new DerUtf8String(token);
}

/**
 * Return the type of this control.
 *
 * @return CRMFObjectIdentifiers.id_regCtrl_regToken
 */
public DerObjectIdentifier getType()
{
    return type;
}

/**
 * Return the token associated with this control (a UTF8String).
 *
 * @return a UTF8String.
 */
public Asn1Encodable getValue()
{
    return token;
}
}
}