using java.security.spec;
using System;
using System.Collections.Generic;
using System.Text;

namespace java.security
{
    /*
    package java.security;

    import java.io.IOException;
    import java.security.spec.AlgorithmParameterSpec;
    import java.security.spec.InvalidParameterSpecException;
    */
    public abstract class AlgorithmParametersSpi : Object
    {
    public AlgorithmParametersSpi()
    {
    }

        protected abstract byte[] engineGetEncoded()
    ;//        throws IOException;
    protected abstract byte[] engineGetEncoded(String format)
   ;//     throws IOException;
        protected abstract AlgorithmParameterSpec engineGetParameterSpec(Class paramSpec)
  ;//      throws InvalidParameterSpecException;
        protected abstract void engineInit(AlgorithmParameterSpec paramSpec)
   ;//     throws InvalidParameterSpecException;
        protected abstract void engineInit(byte[] Params)
   ;//     throws IOException;
        protected abstract void engineInit(byte[] Params, String format)
   ;//     throws IOException;
        protected abstract String engineToString();
}
}
