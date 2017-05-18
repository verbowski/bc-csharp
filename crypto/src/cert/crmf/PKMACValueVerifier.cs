using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.Asn1.Crmf;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Operator;
using Org.BouncyCastle.Utilities;
using System.IO;

namespace Org.BouncyCastle.Cert.Crmf
{
    /*
import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.cmp.PBMParameter;
import org.bouncycastle.asn1.crmf.PKMACValue;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.operator.MacCalculator;
import org.bouncycastle.util.Arrays;
*/
    class PKMACValueVerifier
    {
        private readonly PKMACBuilder builder;

    public PKMACValueVerifier(PKMACBuilder builder)
        {
            this.builder = builder;
        }

        public bool isValid(PKMacValue value, char[] password, SubjectPublicKeyInfo keyInfo)
        {
            builder.setParameters(PbmParameter.GetInstance(value.AlgID.Parameters));
            MacCalculator calculator = builder.build(password);

            Stream macOut = calculator.getOutputStream();

        try
        {
                macOut.Write(keyInfo.GetEncoded(Org.BouncyCastle.Asn1.Asn1Encodable.Der));

                macOut.Close();
            }
        catch (IOException e)
        {
                throw new CRMFException("exception encoding mac input: " + e.Message, e);
            }

        return Arrays.AreEqual(calculator.getMac(), value.MacValue.GetBytes());
        }
    }
}