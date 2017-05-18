using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cert.Crmf;
using Org.BouncyCastle.JcaJce.Util;
using Org.BouncyCastle.Security;
using System;
using System.IO;

namespace Org.BouncyCastle.Cert.Crmf.JcaJce
{
    /*
import java.io.IOException;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.RC2ParameterSpec;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Null;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.iana.IANAObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.crmf.CRMFException;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.jcajce.util.AlgorithmParametersUtils;
import org.bouncycastle.jcajce.util.JcaJceHelper;
*/
    class CRMFHelper
    {
        protected static readonly Map BASE_CIPHER_NAMES = new HashMap();
        protected static readonly Map CIPHER_ALG_NAMES = new HashMap();
        protected static readonly Map DIGEST_ALG_NAMES = new HashMap();
        protected static readonly Map KEY_ALG_NAMES = new HashMap();
        protected static readonly Map MAC_ALG_NAMES = new HashMap();

        static
    {
        BASE_CIPHER_NAMES.put(PKCSObjectIdentifiers.des_EDE3_CBC,  "DESEDE");
        BASE_CIPHER_NAMES.put(NISTObjectIdentifiers.id_aes128_CBC,  "AES");
        BASE_CIPHER_NAMES.put(NISTObjectIdentifiers.id_aes192_CBC,  "AES");
        BASE_CIPHER_NAMES.put(NISTObjectIdentifiers.id_aes256_CBC,  "AES");
        
        CIPHER_ALG_NAMES.put(CMSAlgorithm.DES_EDE3_CBC,  "DESEDE/CBC/PKCS5Padding");
        CIPHER_ALG_NAMES.put(CMSAlgorithm.AES128_CBC,  "AES/CBC/PKCS5Padding");
        CIPHER_ALG_NAMES.put(CMSAlgorithm.AES192_CBC,  "AES/CBC/PKCS5Padding");
        CIPHER_ALG_NAMES.put(CMSAlgorithm.AES256_CBC,  "AES/CBC/PKCS5Padding");
        CIPHER_ALG_NAMES.put(new ASN1ObjectIdentifier(PKCSObjectIdentifiers.rsaEncryption.getId()), "RSA/ECB/PKCS1Padding");
        
        DIGEST_ALG_NAMES.put(OIWObjectIdentifiers.idSHA1, "SHA1");
        DIGEST_ALG_NAMES.put(NISTObjectIdentifiers.id_sha224, "SHA224");
        DIGEST_ALG_NAMES.put(NISTObjectIdentifiers.id_sha256, "SHA256");
        DIGEST_ALG_NAMES.put(NISTObjectIdentifiers.id_sha384, "SHA384");
        DIGEST_ALG_NAMES.put(NISTObjectIdentifiers.id_sha512, "SHA512");

        MAC_ALG_NAMES.put(IANAObjectIdentifiers.hmacSHA1, "HMACSHA1");
        MAC_ALG_NAMES.put(PKCSObjectIdentifiers.id_hmacWithSHA1, "HMACSHA1");
        MAC_ALG_NAMES.put(PKCSObjectIdentifiers.id_hmacWithSHA224, "HMACSHA224");
        MAC_ALG_NAMES.put(PKCSObjectIdentifiers.id_hmacWithSHA256, "HMACSHA256");
        MAC_ALG_NAMES.put(PKCSObjectIdentifiers.id_hmacWithSHA384, "HMACSHA384");
        MAC_ALG_NAMES.put(PKCSObjectIdentifiers.id_hmacWithSHA512, "HMACSHA512");

        KEY_ALG_NAMES.put(PKCSObjectIdentifiers.rsaEncryption, "RSA");
        KEY_ALG_NAMES.put(X9ObjectIdentifiers.id_dsa, "DSA");
    }

    private JcaJceHelper helper;

    CRMFHelper(JcaJceHelper helper)
    {
        this.helper = helper;
    }

    PublicKey toPublicKey(SubjectPublicKeyInfo subjectPublicKeyInfo)
    {
        try
        {
            // java/security/spec/X509EncodedKeySpec.java 
            X509EncodedKeySpec xspec = new X509EncodedKeySpec(subjectPublicKeyInfo.GetEncoded());
            AlgorithmIdentifier keyAlg = subjectPublicKeyInfo.AlgorithmID;

            return createKeyFactory(keyAlg.Algorithm).generatePublic(xspec);
        }
        catch (Exception e)
        {
            throw new CRMFException("invalid key: " + e.Message, e);
        }
    }

    Cipher createCipher(DerObjectIdentifier algorithm)
    {
        try
        {
            string cipherName = (string)CIPHER_ALG_NAMES.get(algorithm);

            if (cipherName != null)
            {
                try
                {
                    // this is reversed as the Sun policy files now allow unlimited strength RSA
                    return helper.createCipher(cipherName);
                }
                catch (NoSuchAlgorithmException e)
                {
                    // Ignore
                }
            }
            return helper.createCipher(algorithm.Id);
        }
        catch (GeneralSecurityException e)
        {
            throw new CRMFException("cannot create cipher: " + e.getMessage(), e);
        }
    }

    public KeyGenerator createKeyGenerator(DerObjectIdentifier algorithm)
    {
        try
        {
            string cipherName = (string)BASE_CIPHER_NAMES.get(algorithm);

            if (cipherName != null)
            {
                try
                {
                    // this is reversed as the Sun policy files now allow unlimited strength RSA
                    return helper.createKeyGenerator(cipherName);
                }
                catch (NoSuchAlgorithmException e)
                {
                    // Ignore
                }
            }
            return helper.createKeyGenerator(algorithm.Id);
        }
        catch (GeneralSecurityException e)
        {
            throw new CRMFException("cannot create key generator: " + e.Message, e);
        }
    }



    Cipher createContentCipher(Key sKey, AlgorithmIdentifier encryptionAlgID)
    {
        return (Cipher)execute(new JCECallback()
        {
            public object doInJCE()
    {
        Cipher cipher = createCipher(encryptionAlgID.getAlgorithm());
        ASN1Primitive sParams = (ASN1Primitive)encryptionAlgID.getParameters();
        DerObjectIdentifier encAlg = encryptionAlgID.getAlgorithm();

        if (sParams != null && !(sParams instanceof ASN1Null))
                {
            try
            {
                AlgorithmParameters Params = createAlgorithmParameters(encryptionAlgID.getAlgorithm());

                try
                {
                    AlgorithmParametersUtils.loadParameters(Params, sParams);
                }
                catch (IOException e)
                {
                    throw new CRMFException("error decoding algorithm parameters.", e);
                }

                cipher.init(Cipher.DECRYPT_MODE, sKey, Params);
            }
            catch (NoSuchAlgorithmException e)
            {
                if (encAlg.equals(CMSAlgorithm.DES_EDE3_CBC)
                    || encAlg.equals(CMSAlgorithm.IDEA_CBC)
                    || encAlg.equals(CMSAlgorithm.AES128_CBC)
                    || encAlg.equals(CMSAlgorithm.AES192_CBC)
                    || encAlg.equals(CMSAlgorithm.AES256_CBC))
                {
                    cipher.init(Cipher.DECRYPT_MODE, sKey, new IvParameterSpec(
                        ASN1OctetString.getInstance(sParams).getOctets()));
                }
                else
                {
                    throw e;
                }
            }
        }
                else
                {
            if (encAlg.Equals(CMSAlgorithm.DES_EDE3_CBC)
                || encAlg.Equals(CMSAlgorithm.IDEA_CBC)
                || encAlg.Equals(CMSAlgorithm.CAST5_CBC))
            {
                cipher.init(Cipher.DECRYPT_MODE, sKey, new IvParameterSpec(new byte[8]));
            }
            else
            {
                cipher.init(Cipher.DECRYPT_MODE, sKey);
            }
        }

        return cipher;
    }
});
    }
    
    AlgorithmParameters createAlgorithmParameters(ASN1ObjectIdentifier algorithm)
{
    string algorithmName = (string)BASE_CIPHER_NAMES.get(algorithm);

    if (algorithmName != null)
    {
        try
        {
            // this is reversed as the Sun policy files now allow unlimited strength RSA
            return helper.createAlgorithmParameters(algorithmName);
        }
        catch (NoSuchAlgorithmException e)
        {
            // Ignore
        }
    }
    return helper.createAlgorithmParameters(algorithm.getId());
}

KeyFactory createKeyFactory(DerObjectIdentifier algorithm)
{
    try
    {
        String algName = (String)KEY_ALG_NAMES.get(algorithm);

        if (algName != null)
        {
            try
            {
                // this is reversed as the Sun policy files now allow unlimited strength RSA
                return helper.createKeyFactory(algName);
            }
            catch (NoSuchAlgorithmException e)
            {
                // Ignore
            }
        }
        return helper.createKeyFactory(algorithm.Id);
    }
    catch (GeneralSecurityException e)
    {
        throw new CRMFException("cannot create cipher: " + e.getMessage(), e);
    }
}

MessageDigest createDigest(DerObjectIdentifier algorithm)
{
    try
    {
        String digestName = (String)DIGEST_ALG_NAMES.get(algorithm);

        if (digestName != null)
        {
            try
            {
                // this is reversed as the Sun policy files now allow unlimited strength RSA
                return helper.createDigest(digestName);
            }
            catch (NoSuchAlgorithmException e)
            {
                // Ignore
            }
        }
        return helper.createDigest(algorithm.Id);
    }
    catch (GeneralSecurityException e)
    {
        throw new CRMFException("cannot create cipher: " + e.getMessage(), e);
    }
}

Mac createMac(DerObjectIdentifier algorithm)
{
    try
    {
        String macName = (String)MAC_ALG_NAMES.get(algorithm);

        if (macName != null)
        {
            try
            {
                // this is reversed as the Sun policy files now allow unlimited strength RSA
                return helper.createMac(macName);
            }
            catch (NoSuchAlgorithmException e)
            {
                // Ignore
            }
        }
        return helper.createMac(algorithm.Id);
    }
    catch (GeneralSecurityException e)
    {
        throw new CRMFException("cannot create mac: " + e.getMessage(), e);
    }
}

AlgorithmParameterGenerator createAlgorithmParameterGenerator(DerObjectIdentifier algorithm)
{
    String algorithmName = (String)BASE_CIPHER_NAMES.get(algorithm);

    if (algorithmName != null)
    {
        try
        {
            // this is reversed as the Sun policy files now allow unlimited strength RSA
            return helper.createAlgorithmParameterGenerator(algorithmName);
        }
        catch (NoSuchAlgorithmException e)
        {
            // Ignore
        }
    }
    return helper.createAlgorithmParameterGenerator(algorithm.Id);
}

AlgorithmParameters generateParameters(ASN1ObjectIdentifier encryptionOID, SecretKey encKey, SecureRandom rand)
{
    try
    {
        AlgorithmParameterGenerator pGen = createAlgorithmParameterGenerator(encryptionOID);

        if (encryptionOID.equals(CMSAlgorithm.RC2_CBC))
        {
            byte[] iv = new byte[8];

            rand.nextBytes(iv);

            try
            {
                pGen.init(new RC2ParameterSpec(encKey.getEncoded().length * 8, iv), rand);
            }
            catch (InvalidAlgorithmParameterException e)
            {
                throw new CRMFException("parameters generation error: " + e, e);
            }
        }

        return pGen.generateParameters();
    }
    catch (NoSuchAlgorithmException e)
    {
        return null;
    }
    catch (GeneralSecurityException e)
    {
        throw new CRMFException("exception creating algorithm parameter generator: " + e, e);
    }
}

AlgorithmIdentifier getAlgorithmIdentifier(ASN1ObjectIdentifier encryptionOID, AlgorithmParameters Params)
{
    Asn1Encodable asn1Params;
    if (Params != null)
    {
        try
        {
            asn1Params = AlgorithmParametersUtils.extractParameters(Params);
        }
        catch (IOException e)
        {
            throw new CRMFException("cannot encode parameters: " + e.Message, e);
        }
    }
    else
    {
        asn1Params = DerNull.Instance;
    }

    return new AlgorithmIdentifier(
        encryptionOID,
        asn1Params);
}


static object execute(JCECallback callback)
{
    try
    {
        return callback.doInJCE();
    }
    catch (NoSuchAlgorithmException e)
    {
        throw new CRMFException("can't find algorithm.", e);
    }
    catch (InvalidKeyException e)
    {
        throw new CRMFException("key invalid in message.", e);
    }
    catch (NoSuchProviderException e)
    {
        throw new CRMFException("can't find provider.", e);
    }
    catch (NoSuchPaddingException e)
    {
        throw new CRMFException("required padding not supported.", e);
    }
    catch (InvalidAlgorithmParameterException e)
    {
        throw new CRMFException("algorithm parameters invalid.", e);
    }
    catch (InvalidParameterSpecException e)
    {
        throw new CRMFException("MAC algorithm parameter spec invalid.", e);
    }
}

static interface JCECallback
{
    object doInJCE();
}
}
}