/*
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.security.SecureRandom;

import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.cmp.CMPObjectIdentifiers;
import org.bouncycastle.asn1.cmp.PBMParameter;
import org.bouncycastle.asn1.iana.IANAObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.GenericKey;
import org.bouncycastle.operator.MacCalculator;
import org.bouncycastle.operator.RuntimeOperatorException;
import org.bouncycastle.util.Strings;
*/
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.Asn1.Iana;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Operator;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using System;
using System.IO;

namespace Org.BouncyCastle.Cert.Crmf
{
    public class PKMACBuilder
    {
        private AlgorithmIdentifier owf;
        private int iterationCount;
        private AlgorithmIdentifier mac;
        private int saltLength = 20;
        private SecureRandom random;
        private PKMACValuesCalculator calculator;
        private PbmParameter parameters;
        private int maxIterations;

        public PKMACBuilder(PKMACValuesCalculator calculator) : this(
            new AlgorithmIdentifier(OiwObjectIdentifiers.IdSha1), 1000,
            new AlgorithmIdentifier(IanaObjectIdentifiers.HmacSha1, DerNull.Instance), calculator)
        {
        }

        /**
         * Create a PKMAC builder enforcing a ceiling on the maximum iteration count.
         *
         * @param calculator     supporting calculator
         * @param maxIterations  max allowable value for iteration count.
         */
        public PKMACBuilder(PKMACValuesCalculator calculator, int maxIterations)
        {
            this.maxIterations = maxIterations;
            this.calculator = calculator;
        }

        private PKMACBuilder(AlgorithmIdentifier hashAlgorithm, int iterationCount, AlgorithmIdentifier macAlgorithm, PKMACValuesCalculator calculator)
        {
            this.owf = hashAlgorithm;
            this.iterationCount = iterationCount;
            this.mac = macAlgorithm;
            this.calculator = calculator;
        }

        /**
         * Set the salt length in octets.
         *
         * @param saltLength length in octets of the salt to be generated.
         * @return the generator
         */
        public PKMACBuilder setSaltLength(int saltLength)
        {
            if (saltLength < 8)
            {
                throw new ArgumentOutOfRangeException("salt length must be at least 8 bytes");
            }

            this.saltLength = saltLength;

            return this;
        }

        public PKMACBuilder setIterationCount(int iterationCount)
        {
            if (iterationCount < 100)
            {
                throw new ArgumentOutOfRangeException("iteration count must be at least 100");
            }
            checkIterationCountCeiling(iterationCount);

            this.iterationCount = iterationCount;

            return this;
        }

        public PKMACBuilder setSecureRandom(SecureRandom random)
        {
            this.random = random;

            return this;
        }

        public PKMACBuilder setParameters(PbmParameter parameters)
        {
            checkIterationCountCeiling(parameters.IterationCount.Value.IntValue);

            this.parameters = parameters;

            return this;
        }

        public MacCalculator build(char[] password)
        {
            if (parameters != null)
            {
                return genCalculator(parameters, password);
            }
            else
            {
                byte[] salt = new byte[saltLength];

                if (random == null)
                {
                    this.random = new SecureRandom();
                }

                random.NextBytes(salt);

                return genCalculator(new PbmParameter(salt, owf, iterationCount, mac), password);
            }
        }

        private void checkIterationCountCeiling(int iterationCount)
        {
            if (maxIterations > 0 && iterationCount > maxIterations)
            {
                throw new ArgumentOutOfRangeException("iteration count exceeds limit (" + iterationCount + " > " + maxIterations + ")");
            }
        }

        private MacCalculator genCalculator(PbmParameter Params, char[] password)
        {
            // From RFC 4211
            //
            //   1.  Generate a random salt value S
            //
            //   2.  Append the salt to the pw.  K = pw || salt.
            //
            //   3.  Hash the value of K.  K = HASH(K)
            //
            //   4.  Iter = Iter - 1.  If Iter is greater than zero.  Goto step 3.
            //
            //   5.  Compute an HMAC as documented in [HMAC].
            //
            //       MAC = HASH( K XOR opad, HASH( K XOR ipad, data) )
            //
            //       Where opad and ipad are defined in [HMAC].
            byte[] pw = Strings.ToUtf8ByteArray(password);
            byte[] salt = Params.Salt.GetOctets();
            byte[] K = new byte[pw.Length + salt.Length];

            System.arraycopy(pw, 0, K, 0, pw.Length);
            System.arraycopy(salt, 0, K, pw.Length, salt.Length);

            calculator.setup(Params.Owf, Params.Mac);

            int iter = Params.IterationCount.Value.IntValue;
            do
            {
                K = calculator.calculateDigest(K);
            }
            while (--iter > 0);

            byte[] key = K;

            return new MacCalculator() // anonymous class??
                    {
                        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

                                public AlgorithmIdentifier getAlgorithmIdentifier()
                            {
                                return new AlgorithmIdentifier(CmpObjectIdentifiers.passwordBasedMac, Params);
                            }

                            public GenericKey getKey()
                            {
                                return new GenericKey(getAlgorithmIdentifier(), key);
                            }

                            public Stream getOutputStream()
                            {
                                return bOut;
                            }

                            public byte[] getMac()
                            {
                                try
                                {
                                    return calculator.calculateMac(key, bOut.toByteArray());
                                }
                                catch (CRMFException e)
                                {
                                    throw new Exception("exception calculating mac: " + e.Message, e);
                                }
                            }
                        };
}
}
}