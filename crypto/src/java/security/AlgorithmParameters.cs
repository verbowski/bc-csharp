using java.security;
using java.security.spec;
using System;

namespace java.security
{
    /*
    package java.security;

    import java.io.IOException;
    import java.security.spec.AlgorithmParameterSpec;
    import java.security.spec.InvalidParameterSpecException;
    */
    public class AlgorithmParameters : object
    {
        private AlgorithmParametersSpi spi;
        private Provider provider;
        private string algorithm;

        protected AlgorithmParameters(
            AlgorithmParametersSpi paramSpi,
            Provider provider,
            string algorithm)
        {
            this.spi = paramSpi;
            this.provider = provider;
            this.algorithm = algorithm;
        }
        public string getAlgorithm()
        {
            return algorithm;
        }
        public byte[] getEncoded() //throws IOException
        {
            return spi.engineGetEncoded();
        }
        public byte[] getEncoded(string format)// throws IOException
        {
            return spi.engineGetEncoded(format);
        }
        public static AlgorithmParameters getInstance(string algorithm)
        //      throws NoSuchAlgorithmException
        {
            try
            {
                SecurityUtil.Implementation imp = SecurityUtil.getImplementation("AlgorithmParameters", algorithm, null);

                if (imp != null)
                {
                    return new AlgorithmParameters((AlgorithmParametersSpi)imp.getEngine(), imp.getProvider(), algorithm);
                }

                throw new NoSuchAlgorithmException("can't find algorithm " + algorithm);
            }
            catch (NoSuchProviderException e)
            {
                throw new NoSuchAlgorithmException(algorithm + " not found");
            }
        }
        public static AlgorithmParameters getInstance(String algorithm, String provider)
        //       throws NoSuchAlgorithmException, NoSuchProviderException
        {
            SecurityUtil.Implementation imp = SecurityUtil.getImplementation("AlgorithmParameters", algorithm, provider);

            if (imp != null)
            {
                return new AlgorithmParameters((AlgorithmParametersSpi)imp.getEngine(), imp.getProvider(), algorithm);
            }

            throw new NoSuchAlgorithmException("can't find algorithm " + algorithm);
        }
        public AlgorithmParameterSpec getParameterSpec(Class paramSpec)
        //   throws InvalidParameterSpecException
        {
            return spi.engineGetParameterSpec(paramSpec);
        }
        public Provider getProvider()
        {
            return provider;
        }
        public void init(AlgorithmParameterSpec paramSpec)
        //    throws InvalidParameterSpecException
        {
            spi.engineInit(paramSpec);
        }
        public void init(byte[] Params)// throws IOException
        {
            spi.engineInit(Params);
        }
        public void init(byte[] Params, String format)// throws IOException
        {
            spi.engineInit(Params, format);
        }
        public string toString()
        {
            return spi.engineToString();
        }
    }
}