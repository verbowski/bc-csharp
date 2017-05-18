// https://github.com/bcgit/bc-java/blob/master/pkix/src/main/java/org/bouncycastle/cert/crmf/CertificateRequestMessage.java

/*
import java.io.IOException;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.crmf.AttributeTypeAndValue;
import org.bouncycastle.asn1.crmf.CRMFObjectIdentifiers;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.crmf.Controls;
import org.bouncycastle.asn1.crmf.PKIArchiveOptions;
import org.bouncycastle.asn1.crmf.PKMACValue;
import org.bouncycastle.asn1.crmf.POPOSigningKey;
import org.bouncycastle.asn1.crmf.ProofOfPossession;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Encodable;
*/
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Crmf;
using Org.BouncyCastle.Operator;
using System;

namespace Org.BouncyCastle.Cert.Crmf
{
    /**
     * Carrier for a CRMF CertReqMsg.
     */
    public class CertificateRequestMessage : Org.BouncyCastle.Util.Encodable
    {
        public static readonly int popRaVerified = ProofOfPossession.TYPE_RA_VERIFIED;
        public static readonly int popSigningKey = ProofOfPossession.TYPE_SIGNING_KEY;
        public static readonly int popKeyEncipherment = ProofOfPossession.TYPE_KEY_ENCIPHERMENT;
        public static readonly int popKeyAgreement = ProofOfPossession.TYPE_KEY_AGREEMENT;

        private readonly CertReqMsg certReqMsg;
        private readonly Controls controls;

        private static CertReqMsg parseBytes(byte[] encoding)
        {
            try
            {
                return CertReqMsg.GetInstance(ASN1Primitive.fromByteArray(encoding));
            }
            catch (System.InvalidCastException e)
            {
                throw new CertIOException("malformed data: " + e.Message, e);
            }
            catch (System.InvalidOperationException e)
            {
                throw new CertIOException("malformed data: " + e.Message, e);
            }
        }

        /**
         * Create a CertificateRequestMessage from the passed in bytes.
         *
         * @param certReqMsg BER/DER encoding of the CertReqMsg structure.
         * @throws IOException in the event of corrupted data, or an incorrect structure.
         */
        public CertificateRequestMessage(byte[] certReqMsg) : this(parseBytes(certReqMsg))
        {

        }

        public CertificateRequestMessage(CertReqMsg certReqMsg)
        {
            this.certReqMsg = certReqMsg;
            this.controls = certReqMsg.CertReq.Controls;
        }

        /**
         * Return the underlying ASN.1 object defining this CertificateRequestMessage object.
         *
         * @return a CertReqMsg.
         */
        public CertReqMsg toASN1Structure()
        {
            return certReqMsg;
        }

        /**
         * Return the certificate template contained in this message.
         *
         * @return  a CertTemplate structure.
         */
        public CertTemplate getCertTemplate()
        {
            return this.certReqMsg.CertReq.CertTemplate;
        }

        /**
         * Return whether or not this request has control values associated with it.
         *
         * @return true if there are control values present, false otherwise.
         */
        public bool hasControls()
        {
            return controls != null;
        }

        /**
         * Return whether or not this request has a specific type of control value.
         *
         * @param type the type OID for the control value we are checking for.
         * @return true if a control value of type is present, false otherwise.
         */
        public bool hasControl(DerObjectIdentifier type)
        {
            return findControl(type) != null;
        }

        /**
         * Return a control value of the specified type.
         *
         * @param type the type OID for the control value we are checking for.
         * @return the control value if present, null otherwise.
         */
        public Control getControl(DerObjectIdentifier type)
        {
            AttributeTypeAndValue found = findControl(type);

            if (found != null)
            {
                if (found.Type.Equals(CrmfObjectIdentifiers.id_regCtrl_pkiArchiveOptions))
                {
                    return new PKIArchiveControl(PkiArchiveOptions.GetInstance(found.Value));
                }
                if (found.Type.Equals(CrmfObjectIdentifiers.id_regCtrl_regToken))
                {
                    return new RegTokenControl(DerUtf8String.GetInstance(found.Value));
                }
                if (found.Type.Equals(CrmfObjectIdentifiers.id_regCtrl_authenticator))
                {
                    return new AuthenticatorControl(DerUtf8String.GetInstance(found.Value));
                }
            }

            return null;
        }

        private AttributeTypeAndValue findControl(DerObjectIdentifier type)
        {
            if (controls == null)
            {
                return null;
            }

            AttributeTypeAndValue[] tAndVs = controls.ToAttributeTypeAndValueArray();
            AttributeTypeAndValue found = null;

            for (int i = 0; i != tAndVs.Length; i++)
            {
                if (tAndVs[i].GetType().Equals(type))
                {
                    found = tAndVs[i];
                    break;
                }
            }

            return found;
        }

        /**
         * Return whether or not this request message has a proof-of-possession field in it.
         *
         * @return true if proof-of-possession is present, false otherwise.
         */
        public bool hasProofOfPossession()
        {
            return this.certReqMsg.Popo != null;
        }

        /**
         * Return the type of the proof-of-possession this request message provides.
         *
         * @return one of: popRaVerified, popSigningKey, popKeyEncipherment, popKeyAgreement
         */
        public int getProofOfPossessionType()
        {
            return this.certReqMsg.Popo.Type;
        }

        /**
         * Return whether or not the proof-of-possession (POP) is of the type popSigningKey and
         * it has a public key MAC associated with it.
         *
         * @return true if POP is popSigningKey and a PKMAC is present, false otherwise.
         */
        public bool hasSigningKeyProofOfPossessionWithPKMAC()
        {
            ProofOfPossession pop = certReqMsg.Popo;

            if (pop.Type == popSigningKey)
            {
                PopoSigningKey popoSign = PopoSigningKey.GetInstance(pop.Object);

                return popoSign.PoposkInput.PublicKeyMac != null;
            }

            return false;
        }

        /**
         * Return whether or not a signing key proof-of-possession (POP) is valid.
         *
         * @param verifierProvider a provider that can produce content verifiers for the signature contained in this POP.
         * @return true if the POP is valid, false otherwise.
         * @throws CRMFException if there is a problem in verification or content verifier creation.
         * @throws IllegalStateException if POP not appropriate.
         */
        public bool isValidSigningKeyPOP(ContentVerifierProvider verifierProvider)
        {
            ProofOfPossession pop = certReqMsg.Popo;

            if (pop.Type == popSigningKey)
            {
                PopoSigningKey popoSign = PopoSigningKey.GetInstance(pop.Object);

                if (popoSign.PoposkInput != null && popoSign.PoposkInput.PublicKeyMac != null)
                {
                    throw new System.InvalidProgramException("verification requires password check");
                }

                return verifySignature(verifierProvider, popoSign);
            }
            else
            {
                throw new InvalidProgramException("not Signing Key type of proof of possession");
            }
        }

        /**
         * Return whether or not a signing key proof-of-possession (POP), with an associated PKMAC, is valid.
         *
         * @param verifierProvider a provider that can produce content verifiers for the signature contained in this POP.
         * @param macBuilder a suitable PKMACBuilder to create the MAC verifier.
         * @param password the password used to key the MAC calculation.
         * @return true if the POP is valid, false otherwise.
         * @throws CRMFException if there is a problem in verification or content verifier creation.
         * @throws IllegalStateException if POP not appropriate.
         */
        public bool isValidSigningKeyPOP(ContentVerifierProvider verifierProvider, PKMACBuilder macBuilder, char[] password)
        {
            ProofOfPossession pop = certReqMsg.Popo;

            if (pop.Type == popSigningKey)
            {
                PopoSigningKey popoSign = PopoSigningKey.GetInstance(pop.Object);

                if (popoSign.PoposkInput == null || popoSign.PoposkInput.Sender != null)
                {
                    throw new System.InvalidProgramException("no PKMAC present in proof of possession");
                }

                PKMacValue pkMAC = popoSign.PoposkInput.PublicKeyMac;
                PKMACValueVerifier macVerifier = new PKMACValueVerifier(macBuilder);

                if (macVerifier.isValid(pkMAC, password, this.getCertTemplate().PublicKey))
                {
                    return verifySignature(verifierProvider, popoSign);
                }

                return false;
            }
            else
            {
                throw new InvalidProgramException("not Signing Key type of proof of possession");
            }
        }

        private bool verifySignature(ContentVerifierProvider verifierProvider, PopoSigningKey popoSign)
        {
            ContentVerifier verifier;

            try
            {
                verifier = verifierProvider.get(popoSign.AlgorithmIdentifier);
            }
            catch (OperatorCreationException e)
            {
                throw new CRMFException("unable to create verifier: " + e.getMessage(), e);
            }

            if (popoSign.PoposkInput != null)
            {
                CRMFUtil.derEncodeToStream(popoSign.PoposkInput, verifier.getOutputStream());
            }
            else
            {
                CRMFUtil.derEncodeToStream(certReqMsg.CertReq, verifier.getOutputStream());
            }

            return verifier.verify(popoSign.Signature.GetOctets());
        }

        /**
         * Return the ASN.1 encoding of the certReqMsg we wrap.
         *
         * @return a byte array containing the binary encoding of the certReqMsg.
         * @throws IOException if there is an exception creating the encoding.
         */
        public byte[] getEncoded()
        {
            return certReqMsg.GetEncoded();
        }
    }
}