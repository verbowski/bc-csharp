// https://github.com/bcgit/bc-java/blob/master/pkix/src/main/java/org/bouncycastle/cert/crmf/PKMACValueGenerator.java
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Crmf;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cert.Crmf;
using Org.BouncyCastle.Operator;
using System.IO;

namespace Org.BouncyCastle.Cert.Crmf
{ 
    /*
import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.crmf.PKMACValue;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.operator.MacCalculator;
*/
public class PKMACValueGenerator
{
    private Org.BouncyCastle.Cert.Crmf.PKMACBuilder builder;

    public PKMACValueGenerator(PKMACBuilder builder)
    {
        this.builder = builder;
    }

    public PKMacValue generate(char[] password, SubjectPublicKeyInfo keyInfo)
    {
        MacCalculator calculator = builder.build(password);

        Stream macOut = calculator.getOutputStream();

        try
        {
            macOut.Write(keyInfo.GetEncoded(Asn1Encodable.Der));

            macOut.Close();
        }
        catch (IOException e)
        {
            throw new CRMFException("exception encoding mac input: " + e.Message, e);
        }

        return new PKMacValue(calculator.getAlgorithmIdentifier(), new DerBitString(calculator.getMac()));
    }
}
}