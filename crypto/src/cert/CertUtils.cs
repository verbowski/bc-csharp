using java.security;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Operator;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Collections;
using System;
using System.Collections;
using System.IO;

namespace Org.BouncyCastle.Cert
{
    /*
    import java.io.IOException;
    import java.io.OutputStream;
    import java.text.ParseException;
    import java.util.ArrayList;
    import java.util.Arrays;
    import java.util.Collections;
    import java.util.Date;
    import java.util.HashSet;
    import java.util.List;
    import java.util.Set;

    import org.bouncycastle.asn1.ASN1Encodable;
    import org.bouncycastle.asn1.Asn1EncodableVector;
    import org.bouncycastle.asn1.ASN1GeneralizedTime;
    import org.bouncycastle.asn1.ASN1ObjectIdentifier;
    import org.bouncycastle.asn1.DERBitString;
    import org.bouncycastle.asn1.DERNull;
    import org.bouncycastle.asn1.DEROutputStream;
    import org.bouncycastle.asn1.DerSequence;
    import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
    import org.bouncycastle.asn1.x509.AttributeCertificate;
    import org.bouncycastle.asn1.x509.AttributeCertificateInfo;
    import org.bouncycastle.asn1.x509.Certificate;
    import org.bouncycastle.asn1.x509.CertificateList;
    import org.bouncycastle.asn1.x509.Extensions;
    import org.bouncycastle.asn1.x509.ExtensionsGenerator;
    import org.bouncycastle.asn1.x509.TBSCertList;
    import org.bouncycastle.asn1.x509.TBSCertificate;
    import org.bouncycastle.operator.ContentSigner;
    */
    class CertUtils
    {
        private static Set EMPTY_SET = Collections.unmodifiableSet(new HashSet());
        private static List EMPTY_LIST = Collections.unmodifiableList(new ArrayList());

        static X509CertificateHolder generateFullCert(ContentSigner signer, Org.BouncyCastle.Asn1.X509.TbsCertificateStructure /*TBSCertificate*/ tbsCert)
        {
            try
            {
                return new X509CertificateHolder(generateStructure(tbsCert, signer.getAlgorithmIdentifier(), generateSig(signer, tbsCert)));
            }
            catch (IOException e)
            {
                throw new IllegalStateException("cannot produce certificate signature");
            }
        }

        static X509AttributeCertificateHolder generateFullAttrCert(ContentSigner signer, AttributeCertificateInfo attrInfo)
        {
            try
            {
                return new X509AttributeCertificateHolder(generateAttrStructure(attrInfo, signer.getAlgorithmIdentifier(), generateSig(signer, attrInfo)));
            }
            catch (IOException e)
            {
                throw new IllegalStateException("cannot produce attribute certificate signature");
            }
        }

        static X509CRLHolder generateFullCRL(ContentSigner signer, TBSCertList tbsCertList)
        {
            try
            {
                return new X509CRLHolder(generateCRLStructure(tbsCertList, signer.getAlgorithmIdentifier(), generateSig(signer, tbsCertList)));
            }
            catch (IOException e)
            {
                throw new IllegalStateException("cannot produce certificate signature");
            }
        }

        private static byte[] generateSig(ContentSigner signer, Asn1Encodable tbsObj)
        {
            Stream sOut = signer.getOutputStream();
            DerOutputStream dOut = new DerOutputStream(sOut);

            dOut.WriteObject(tbsObj);

            sOut.Close();

            return signer.getSignature();
        }

        private static Certificate generateStructure(Org.BouncyCastle.Asn1.X509.TbsCertificateStructure /*TBSCertificate*/ tbsCert, AlgorithmIdentifier sigAlgId, byte[] signature)
        {
            Asn1EncodableVector v = new Asn1EncodableVector();

            v.Add(tbsCert);
            v.Add(sigAlgId);
            v.Add(new DerBitString(signature));

            return Certificate.getInstance(new DerSequence(v));
        }

        private static AttributeCertificate generateAttrStructure(AttributeCertificateInfo attrInfo, AlgorithmIdentifier sigAlgId, byte[] signature)
        {
            Asn1EncodableVector v = new Asn1EncodableVector();

            v.Add(attrInfo);
            v.Add(sigAlgId);
            v.Add(new DerBitString(signature));

            return AttributeCertificate.GetInstance(new DerSequence(v));
        }

        private static CertificateList generateCRLStructure(Org.BouncyCastle.Asn1.X509.TbsCertificateList /*TBSCertList*/ tbsCertList, AlgorithmIdentifier sigAlgId, byte[] signature)
        {
            Asn1EncodableVector v = new Asn1EncodableVector();

            v.Add(tbsCertList);
            v.Add(sigAlgId);
            v.Add(new DerBitString(signature));

            return CertificateList.GetInstance(new DerSequence(v));
        }

        static Set getCriticalExtensionOIDs(X509Extensions extensions)
        {
            if (extensions == null)
            {
                return EMPTY_SET;
            }

            return Collections.unmodifiableSet(new HashSet(Arrays.asList(extensions.GetCriticalExtensionOids())));
        }

        static Set getNonCriticalExtensionOIDs(X509Extensions extensions)
        {
            if (extensions == null)
            {
                return EMPTY_SET;
            }

            // TODO: should probably produce a set that imposes correct ordering
            return Collections.unmodifiableSet(new HashSet(Arrays.asList(extensions.GetNonCriticalExtensionOids())));
        }

        static List getExtensionOIDs(X509Extensions extensions)
        {
            if (extensions == null)
            {
                return EMPTY_LIST;
            }

            return Collections.unmodifiableList(Arrays.asList(extensions.GetExtensionOids()));
        }

        static void addExtension(X509ExtensionsGenerator extGenerator, DerObjectIdentifier oid, bool isCritical, Asn1Encodable value)
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

        static DerBitString booleanToBitString(bool[] id)
        {
            byte[] bytes = new byte[(id.Length + 7) / 8];

            for (int i = 0; i != id.Length; i++)
            {
                bytes[i / 8] |= (id[i]) ? (1 << ((7 - (i % 8)))) : 0;
            }

            int pad = id.Length % 8;

            if (pad == 0)
            {
                return new DerBitString(bytes);
            }
            else
            {
                return new DerBitString(bytes, 8 - pad);
            }
        }

        static bool[] bitStringToBoolean(DerBitString bitString)
        {
            if (bitString != null)
            {
                byte[] bytes = bitString.GetBytes();
                bool[] boolId = new bool[bytes.Length * 8 - bitString.getPadBits()];

                for (int i = 0; i != boolId.Length; i++)
                {
                    boolId[i] = (bytes[i / 8] & (0x80 >>> (i % 8))) != 0;
                }

                return boolId;
            }

            return null;
        }

        static DateTime recoverDate(ASN1GeneralizedTime time)
        {
            try
            {
                return time.getDate();
            }
            catch (ParseException e)
            {
                throw new IllegalStateException("unable to recover date: " + e.Message);
            }
        }

        static bool isAlgIdEqual(AlgorithmIdentifier id1, AlgorithmIdentifier id2)
        {
            if (!id1.Algorithm.Equals(id2.Algorithm))
            {
                return false;
            }

            if (id1.Parameters == null)
            {
                if (id2.Parameters != null && !id2.Parameters.Equals(DerNull.Instance))
                {
                    return false;
                }

                return true;
            }

            if (id2.Parameters == null)
            {
                if (id1.Parameters != null && !id1.Parameters.Equals(DerNull.Instance))
                {
                    return false;
                }

                return true;
            }

            return id1.Parameters.Equals(id2.Parameters);
        }
    }
}