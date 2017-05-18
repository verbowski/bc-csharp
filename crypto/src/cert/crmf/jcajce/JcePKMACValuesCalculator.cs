using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.JcaJce.Util;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Cert.Crmf.JcaJce
{ 
/*
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.Provider;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.crmf.CRMFException;
import org.bouncycastle.cert.crmf.PKMACValuesCalculator;
import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.util.NamedJcaJceHelper;
import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
*/
public class JcePKMACValuesCalculator: PKMACValuesCalculator
{
        // java.security.MessageDigest;
        private MessageDigest digest;
        //javax.crypto.Mac;
        private Mac mac;
private CRMFHelper helper;

public JcePKMACValuesCalculator()
{
    this.helper = new CRMFHelper(new DefaultJcaJceHelper());
}
        // java.security.Provider;
        public JcePKMACValuesCalculator setProvider(Provider provider)
{
    this.helper = new CRMFHelper(new ProviderJcaJceHelper(provider));

    return this;
}

public JcePKMACValuesCalculator setProvider(string providerName)
{
    this.helper = new CRMFHelper(new NamedJcaJceHelper(providerName));

    return this;
}

public void setup(AlgorithmIdentifier digAlg, AlgorithmIdentifier macAlg)
{
    digest = helper.createDigest(digAlg.Algorithm);
    mac = helper.createMac(macAlg.Algorithm);
}

public byte[] calculateDigest(byte[] data)
{
    return digest.digest(data);
}

public byte[] calculateMac(byte[] pwd, byte[] data)
{
        try
        {
                // javax.crypto.spec.SecretKeySpec;
                mac.init(new SecretKeySpec(pwd, mac.getAlgorithm()));

        return mac.doFinal(data);
    }
        catch (GeneralSecurityException e)
        {
        throw new CRMFException("failure in setup: " + e.Message, e);
    }
}
}
}