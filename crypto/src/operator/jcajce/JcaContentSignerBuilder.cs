
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.JcaJce.Util;
using Org.BouncyCastle.OpenPgp.Operator.JcaJce;
using Org.BouncyCastle.Operator;
using Org.BouncyCastle.Security;
using System.IO;

namespace Org.BouncyCastle.Operator.JcaJce
{
//    package org.bouncycastle.operator.jcajce;
/*
    import java.io.IOException;
    import java.io.OutputStream;
    import java.security.GeneralSecurityException;
    import java.security.PrivateKey;
    import java.security.Provider;
    import java.security.SecureRandom;
    import java.security.Signature;
    import java.security.SignatureException;

    import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
    import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
    import org.bouncycastle.jcajce.util.NamedJcaJceHelper;
    import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
    import org.bouncycastle.operator.ContentSigner;
    import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
    import org.bouncycastle.operator.OperatorCreationException;
    import org.bouncycastle.operator.OperatorStreamException;
    import org.bouncycastle.operator.RuntimeOperatorException;
    */
    public class JcaContentSignerBuilder
    {
        private OperatorHelper helper = new OperatorHelper(new DefaultJcaJceHelper());
        private SecureRandom random;
        private string signatureAlgorithm;
        private AlgorithmIdentifier sigAlgId;

        public JcaContentSignerBuilder(string signatureAlgorithm)
        {
            this.signatureAlgorithm = signatureAlgorithm;
            this.sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find(signatureAlgorithm);
        }
        public JcaContentSignerBuilder setProvider(Provider provider)
        {
            this.helper = new OperatorHelper(new ProviderJcaJceHelper(provider));

            return this;
        }

        public JcaContentSignerBuilder setProvider(string providerName)
        {
            this.helper = new OperatorHelper(new NamedJcaJceHelper(providerName));

            return this;
        }

        public JcaContentSignerBuilder setSecureRandom(SecureRandom random)
        {
            this.random = random;

            return this;
        }

        public ContentSigner build(PrivateKey privateKey)
        {
        try
        {
                // java.security.Signature;
                Signature sig = helper.createSignature(sigAlgId);
                AlgorithmIdentifier signatureAlgId = sigAlgId;

                if (random != null)
                {
                    sig.initSign(privateKey, random);
                }
                else
                {
                    sig.initSign(privateKey);
                }

                return new ContentSigner()
                {
                private SignatureOutputStream stream = new SignatureOutputStream(sig);

        public AlgorithmIdentifier getAlgorithmIdentifier()
        {
            return signatureAlgId;
        }

        public Stream getOutputStream()
        {
            return stream;
        }

        public byte[] getSignature()
        {
            try
            {
                return stream.getSignature();
            }
            catch (SignatureException e)
            {
                throw new RuntimeOperatorException("exception obtaining signature: " + e.Message, e);
            }
        }
    };
}
        catch (GeneralSecurityException e)
        {
            throw new OperatorCreationException("cannot create signer: " + e.Message, e);
        }
    }

    private class SignatureOutputStream:Stream
{
        private Signature sig;

        SignatureOutputStream(Signature sig)
{
    this.sig = sig;
}

public void write(byte[] bytes, int off, int len)
{
            try
            {
        sig.update(bytes, off, len);
    }
            catch (SignatureException e)
            {
        throw new OperatorStreamException("exception in content signer: " + e.Message, e);
    }
}

public void write(byte[] bytes)
{
            try
            {
        sig.update(bytes);
    }
            catch (SignatureException e)
            {
        throw new OperatorStreamException("exception in content signer: " + e.Message, e);
    }
}

public void write(int b)
{
            try
            {
        sig.update((byte)b);
    }
            catch (SignatureException e)
            {
        throw new OperatorStreamException("exception in content signer: " + e.Message, e);
    }
}

byte[] getSignature()
{
            return sig.sign();
}
    }
}
}