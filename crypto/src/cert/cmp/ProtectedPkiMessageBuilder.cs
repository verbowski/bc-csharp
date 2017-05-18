using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Operator;
using System.IO;

namespace Org.BouncyCastle.Cert.Cmp
{ 
    /*
import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.InfoTypeAndValue;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIFreeText;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIHeaderBuilder;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.MacCalculator;
*/
/**
 * Builder for creating a protected PKI message.
 */
public class ProtectedPKIMessageBuilder
{
    private PkiHeaderBuilder hdrBuilder;
    private PkiBody body;
    private List generalInfos = new ArrayList();
    private List extraCerts = new ArrayList();

    /**
     * Commence a message with the header version CMP_2000.
     *
     * @param sender message sender.
     * @param recipient intended recipient.
     */
    public ProtectedPKIMessageBuilder(GeneralName sender, GeneralName recipient): this(PkiHeader.CMP_2000, sender, recipient)
    {
        
    }

    /**
     * Commence a message with a specific header type.
     *
     * @param pvno  the version CMP_1999 or CMP_2000.
     * @param sender message sender.
     * @param recipient intended recipient.
     */
    public ProtectedPKIMessageBuilder(int pvno, GeneralName sender, GeneralName recipient)
    {
        hdrBuilder = new PkiHeaderBuilder(pvno, sender, recipient);
    }

    /**
     * Set the identifier for the transaction the new message will belong to.
     *
     * @param tid  the transaction ID.
     * @return the current builder instance.
     */
    public ProtectedPKIMessageBuilder setTransactionID(byte[] tid)
    {
        hdrBuilder.SetTransactionID(tid);

        return this;
    }

    /**
     * Include a human-readable message in the new message.
     *
     * @param freeText the contents of the human readable message,
     * @return the current builder instance.
     */
    public ProtectedPKIMessageBuilder setFreeText(PkiFreeText freeText)
    {
        hdrBuilder.SetFreeText(freeText);

        return this;
    }

    /**
     * Add a generalInfo data record to the header of the new message.
     *
     * @param genInfo the generalInfo data to be added.
     * @return the current builder instance.
     */
    public ProtectedPKIMessageBuilder addGeneralInfo(InfoTypeAndValue genInfo)
    {
        generalInfos.add(genInfo);

        return this;
    }

    /**
     * Set the creation time for the new message.
     *
     * @param time the message creation time.
     * @return the current builder instance.
     */
    public ProtectedPKIMessageBuilder setMessageTime(Date time)
    {
        hdrBuilder.SetMessageTime(new ASN1GeneralizedTime(time));

        return this;
    }

    /**
     * Set the recipient key identifier for the key to be used to verify the new message.
     *
     * @param kid a key identifier.
     * @return the current builder instance.
     */
    public ProtectedPKIMessageBuilder setRecipKID(byte[] kid)
    {
        hdrBuilder.SetRecipKID(kid);

        return this;
    }

    /**
     * Set the recipient nonce field on the new message.
     *
     * @param nonce a NONCE, typically copied from the sender nonce of the previous message.
     * @return the current builder instance.
     */
    public ProtectedPKIMessageBuilder setRecipNonce(byte[] nonce)
    {
        hdrBuilder.SetRecipNonce(nonce);

        return this;
    }

    /**
     * Set the sender key identifier for the key used to protect the new message.
     *
     * @param kid a key identifier.
     * @return the current builder instance.
     */
    public ProtectedPKIMessageBuilder setSenderKID(byte[] kid)
    {
        hdrBuilder.SetSenderKID(kid);

        return this;
    }

    /**
     * Set the sender nonce field on the new message.
     *
     * @param nonce a NONCE, typically 128 bits of random data.
     * @return the current builder instance.
     */
    public ProtectedPKIMessageBuilder setSenderNonce(byte[] nonce)
    {
        hdrBuilder.SetSenderNonce(nonce);

        return this;
    }

    /**
     * Set the body for the new message
     *
     * @param body the message body.
     * @return the current builder instance.
     */
    public ProtectedPKIMessageBuilder setBody(PkiBody body)
    {
        this.body = body;

        return this;
    }

    /**
     * Add an "extra certificate" to the message.
     *
     * @param extraCert the extra certificate to add.
     * @return the current builder instance.
     */
    public ProtectedPKIMessageBuilder addCMPCertificate(X509CertificateHolder extraCert)
    {
        extraCerts.add(extraCert);

        return this;
    }

    /**
     * Build a protected PKI message which has MAC based integrity protection.
     *
     * @param macCalculator MAC calculator.
     * @return the resulting protected PKI message.
     * @throws CMPException if the protection MAC cannot be calculated.
     */
    public ProtectedPKIMessage build(MacCalculator macCalculator)
    {
        finaliseHeader(macCalculator.getAlgorithmIdentifier());
            PkiHeader header = hdrBuilder.Build();

        try
        {
            DerBitString protection = new DerBitString(calculateMac(macCalculator, header, body));

            return finaliseMessage(header, protection);
        }
        catch (IOException e)
        {
            throw new CMPException("unable to encode MAC input: " + e.Message, e);
        }
    }

    /**
     * Build a protected PKI message which has MAC based integrity protection.
     *
     * @param signer the ContentSigner to be used to calculate the signature.
     * @return the resulting protected PKI message.
     * @throws CMPException if the protection signature cannot be calculated.
     */
    public ProtectedPKIMessage build(ContentSigner signer)
    {
        finaliseHeader(signer.getAlgorithmIdentifier());
            PkiHeader header = hdrBuilder.Build();
        
        try
        {
                DerBitString protection = new DerBitString(calculateSignature(signer, header, body));

            return finaliseMessage(header, protection);
        }
        catch (IOException e)
        {
            throw new CMPException("unable to encode signature input: " + e.Message, e);
        }
    }

    private void finaliseHeader(AlgorithmIdentifier algorithmIdentifier)
    {
        hdrBuilder.SetProtectionAlg(algorithmIdentifier);

        if (!generalInfos.isEmpty())
        {
            InfoTypeAndValue[] genInfos = new InfoTypeAndValue[generalInfos.size()];

            hdrBuilder.SetGeneralInfo((InfoTypeAndValue[])generalInfos.toArray(genInfos));
        }
    }

    private ProtectedPKIMessage finaliseMessage(PkiHeader header, DerBitString protection)
    {
        if (!extraCerts.isEmpty())
        {
                CmpCertificate[] cmpCerts = new CmpCertificate[extraCerts.size()];

            for (int i = 0; i != cmpCerts.Length; i++)
            {
                cmpCerts[i] = new CmpCertificate(((X509CertificateHolder)extraCerts.get(i)).toASN1Structure());
            }

            return new ProtectedPKIMessage(new PkiMessage(header, body, protection, cmpCerts));
        }
        else
        {
            return new ProtectedPKIMessage(new PkiMessage(header, body, protection));
        }
    }

    private byte[] calculateSignature(ContentSigner signer, PkiHeader header, PkiBody body)
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

    v.add(header);
        v.add(body);

        Stream sOut = signer.getOutputStream();

    sOut.Write(new DerSequence(v).getEncoded(ASN1Encoding.DER));

        sOut.Close();

        return signer.getSignature();
    }

private byte[] calculateMac(MacCalculator macCalculator, PkiHeader header, PkiBody body)
{
            Asn1EncodableVector v = new Asn1EncodableVector();

v.Add(header);
        v.Add(body);

        Stream sOut = macCalculator.getOutputStream();

sOut.Write(new DerSequence(v).GetEncoded(ASN1Encoding.DER));

        sOut.Close();

        return macCalculator.getMac();
    }
}
}