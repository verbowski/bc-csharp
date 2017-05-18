
/*
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Null;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.crmf.AttributeTypeAndValue;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.crmf.CertRequest;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
import org.bouncycastle.asn1.crmf.OptionalValidity;
import org.bouncycastle.asn1.crmf.POPOPrivKey;
import org.bouncycastle.asn1.crmf.ProofOfPossession;
import org.bouncycastle.asn1.crmf.SubsequentMessage;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.operator.ContentSigner;
*/
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Crmf;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cert.Crmf;
using Org.BouncyCastle.Math;
using System;
using System.Collections;
using System.Collections.Generic;

namespace Org.BouncyCastle.Cert.Crmf
{
    public static class MyExtensions
    {
    }
    public class CertificateRequestMessageBuilder
    {
        private BigInteger certReqId;

        private Org.BouncyCastle.Asn1.X509.X509ExtensionsGenerator extGenerator;
        private CertTemplateBuilder templateBuilder;
        private ArrayList controls;
        private Org.BouncyCastle.Operator.ContentSigner popSigner;
        private PKMACBuilder pkmacBuilder;
        private char[] password;
        private GeneralName sender;
        private PopoPrivKey popoPrivKey;
        private Asn1Null popRaVerified;

        public CertificateRequestMessageBuilder(BigInteger certReqId)
        {
            this.certReqId = certReqId;

            this.extGenerator = new X509ExtensionsGenerator();
            this.templateBuilder = new CertTemplateBuilder();
            this.controls = new ArrayList();
        }

        public CertificateRequestMessageBuilder setPublicKey(SubjectPublicKeyInfo publicKey)
        {
            if (publicKey != null)
            {
                templateBuilder.SetPublicKey(publicKey);
            }

            return this;
        }

        public CertificateRequestMessageBuilder setIssuer(X509Name issuer)
        {
            if (issuer != null)
            {
                templateBuilder.SetIssuer(issuer);
            }

            return this;
        }

        public CertificateRequestMessageBuilder setSubject(X509Name subject)
        {
            if (subject != null)
            {
                templateBuilder.SetSubject(subject);
            }

            return this;
        }

        public CertificateRequestMessageBuilder setSerialNumber(BigInteger serialNumber)
        {
            if (serialNumber != null)
            {
                // DerInteger == ASN1Integer?
                templateBuilder.SetSerialNumber(new DerInteger(serialNumber));
            }

            return this;
        }
        /**
         * Request a validity period for the certificate. Either, but not both, of the date parameters may be null.
         *
         * @param notBeforeDate not before date for certificate requested.
         * @param notAfterDate not after date for the certificate requested.
         *
         * @return the current builder.
         */
        public CertificateRequestMessageBuilder setValidity(DateTime notBeforeDate, DateTime notAfterDate)
        {
            // https://github.com/bcgit/bc-csharp
            // https://github.com/bcgit/bc-csharp/blob/master/crypto/src/asn1/crmf/OptionalValidity.cs
            DerSequence der = new DerSequence(createTime(notBeforeDate), createTime(notAfterDate));
            OptionalValidity v = OptionalValidity.GetInstance(der);
            
            templateBuilder.SetValidity(v);

            return this;
        }
        private Time createTime(DateTime date)
        {
            if (date != null)
            {
                return new Time(date);
            }

            return null;
        }

        public CertificateRequestMessageBuilder AddExtension(
            DerObjectIdentifier oid,
            bool critical,
    Asn1Encodable value)
        {
            CRMFUtil.addExtension(extGenerator, oid, critical, value);

            return this;
        }

        public CertificateRequestMessageBuilder addExtension(
            DerObjectIdentifier oid,
            bool critical,
            byte[] value)
        {
            extGenerator.AddExtension(oid, critical, value);

            return this;
        }

        public CertificateRequestMessageBuilder addControl(Control control)
        {
            controls.Add(control);

            return this;
        }

        public CertificateRequestMessageBuilder setProofOfPossessionSigningKeySigner(Org.BouncyCastle.Operator.ContentSigner popSigner)
        {
            if (popoPrivKey != null || popRaVerified != null)
            {
                throw new InvalidOperationException("only one proof of possession allowed");
            }

            this.popSigner = popSigner;

            return this;
        }

        public CertificateRequestMessageBuilder setProofOfPossessionSubsequentMessage(SubsequentMessage msg)
        {
            if (popSigner != null || popRaVerified != null)
            {
                throw new InvalidOperationException("only one proof of possession allowed");
            }

            this.popoPrivKey = new PopoPrivKey(msg);

            return this;
        }

        public CertificateRequestMessageBuilder setProofOfPossessionRaVerified()
        {
            if (popSigner != null || popoPrivKey != null)
            {
                throw new InvalidOperationException("only one proof of possession allowed");
            }

            this.popRaVerified = DerNull.Instance;

            return this;
        }

        public CertificateRequestMessageBuilder setAuthInfoPKMAC(PKMACBuilder pkmacBuilder, char[] password)
        {
            this.pkmacBuilder = pkmacBuilder;
            this.password = password;

            return this;
        }

        public CertificateRequestMessageBuilder setAuthInfoSender(X509Name sender)
        {
            return setAuthInfoSender(new GeneralName(sender));
        }

        public CertificateRequestMessageBuilder setAuthInfoSender(GeneralName sender)
        {
            this.sender = sender;

            return this;
        }

        public CertificateRequestMessage build()
        {
            Asn1EncodableVector v = new Asn1EncodableVector();

            v.Add(new ASN1Integer(certReqId));

            if (!extGenerator.IsEmpty)
            {
                templateBuilder.SetExtensions(extGenerator.Generate());
            }

            v.Add(templateBuilder.Build());

            if (!(controls.Count==0))
            {
                Asn1EncodableVector controlV = new Asn1EncodableVector();

                foreach (Control control in controls)
                {
                    controlV.Add(new AttributeTypeAndValue(control.getType(), control.getValue()));
                }

                v.Add(new DerSequence(controlV));
            }

            CertRequest request = CertRequest.GetInstance(new DerSequence(v));

            v = new Asn1EncodableVector();

            v.Add(request);

            if (popSigner != null)
            {
                CertTemplate template = request.CertTemplate;

                if (template.Subject == null || template.PublicKey == null)
                {
                    SubjectPublicKeyInfo pubKeyInfo = request.CertTemplate.PublicKey;
                    ProofOfPossessionSigningKeyBuilder builder = new ProofOfPossessionSigningKeyBuilder(pubKeyInfo);

                    if (sender != null)
                    {
                        builder.setSender(sender);
                    }
                    else
                    {
                        PKMACValueGenerator pkmacGenerator = new PKMACValueGenerator(pkmacBuilder);

                        builder.setPublicKeyMac(pkmacGenerator, password);
                    }

                    v.Add(new ProofOfPossession(builder.build(popSigner)));
                }
                else
                {
                    ProofOfPossessionSigningKeyBuilder builder = new ProofOfPossessionSigningKeyBuilder(request);

                    v.Add(new ProofOfPossession(builder.build(popSigner)));
                }
            }
            else if (popoPrivKey != null)
            {
                v.Add(new ProofOfPossession(ProofOfPossession.TYPE_KEY_ENCIPHERMENT, popoPrivKey));
            }
            else if (popRaVerified != null)
            {
                v.Add(new ProofOfPossession());
            }

            return new CertificateRequestMessage(CertReqMsg.GetInstance(new DerSequence(v)));
        }
    }
}