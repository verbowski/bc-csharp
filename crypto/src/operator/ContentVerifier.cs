﻿using Org.BouncyCastle.Asn1.X509;
using System.IO;

namespace Org.BouncyCastle.Operator
{

//import java.io.OutputStream;

//import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

public interface ContentVerifier
{
    /**
     * Return the algorithm identifier describing the signature
     * algorithm and parameters this expander supports.
     *
     * @return algorithm oid and parameters.
     */
    AlgorithmIdentifier getAlgorithmIdentifier();

    /**
     * Returns a stream that will accept data for the purpose of calculating
     * a signature for later verification. Use org.bouncycastle.util.io.TeeOutputStream if you want to accumulate
     * the data on the fly as well.
     *
     * @return an OutputStream
     */
    Stream getOutputStream();

    /**
     * @param expected expected value of the signature on the data.
     * @return true if the signature verifies, false otherwise
     */
    bool verify(byte[] expected);
}