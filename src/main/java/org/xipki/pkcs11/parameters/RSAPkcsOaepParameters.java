// Copyright (c) 2002 Graz University of Technology. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// 3. The end-user documentation included with the redistribution, if any, must
//    include the following acknowledgment:
//
//    "This product includes software developed by IAIK of Graz University of
//     Technology."
//
//    Alternately, this acknowledgment may appear in the software itself, if and
//    wherever such third-party acknowledgments normally appear.
//
// 4. The names "Graz University of Technology" and "IAIK of Graz University of
//    Technology" must not be used to endorse or promote products derived from
//    this software without prior written permission.
//
// 5. Products derived from this software may not be called "IAIK PKCS Wrapper",
//    nor may "IAIK" appear in their name, without prior written permission of
//    Graz University of Technology.
//
// THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESSED OR IMPLIED
// WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE LICENSOR BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
// OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
// OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
// ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

package org.xipki.pkcs11.parameters;

import iaik.pkcs.pkcs11.wrapper.CK_RSA_PKCS_OAEP_PARAMS;
import org.xipki.pkcs11.Functions;

import static org.xipki.pkcs11.PKCS11Constants.CKZ_SALT_SPECIFIED;

/**
 * This class encapsulates parameters for the Mechanism.RSA_PKCS_OAEP.
 *
 * @author Karl Scheibelhofer
 * @author Lijun Liao (xipki)
 */
public class RSAPkcsOaepParameters extends RSAPkcsParameters {

  /**
   * The source of the encoding parameter.
   */
  private long source;

  /**
   * The data used as the input for the encoding parameter source.
   */
  private byte[] sourceData;

  /**
   * Create a new RSAPkcsOaepParameters object with the given attributes.
   *
   * @param hashAlgorithm
   *          The message digest algorithm used to calculate the digest of the
   *          encoding parameter.
   * @param maskGenerationFunction
   *          The mask to apply to the encoded block. One of the constants
   *          defined in the MessageGenerationFunctionType interface.
   * @param source
   *          The source of the encoding parameter. One of the constants
   *          defined in the SourceType interface.
   * @param sourceData
   *          The data used as the input for the encoding parameter source.
   */
  public RSAPkcsOaepParameters(long hashAlgorithm, long maskGenerationFunction, long source, byte[] sourceData) {
    super(hashAlgorithm, maskGenerationFunction);
    this.source = Functions.requireAmong("source", source, 0, CKZ_SALT_SPECIFIED);
    this.sourceData = sourceData;
  }

  /**
   * Get this parameters object as an object of the CK_RSA_PKCS_OAEP_PARAMS
   * class.
   *
   * @return This object as a CK_RSA_PKCS_OAEP_PARAMS object.
   */
  public CK_RSA_PKCS_OAEP_PARAMS getPKCS11ParamsObject() {
    CK_RSA_PKCS_OAEP_PARAMS params = new CK_RSA_PKCS_OAEP_PARAMS();

    params.hashAlg = hashAlg;
    params.mgf = mgf;
    params.source = source;
    params.pSourceData = sourceData;

    return params;
  }

  /**
   * Get the source of the encoding parameter.
   *
   * @return The source of the encoding parameter.
   */
  public long getSource() {
    return source;
  }

  /**
   * Get the data used as the input for the encoding parameter source.
   *
   * @return The data used as the input for the encoding parameter source.
   */
  public byte[] getSourceData() {
    return sourceData;
  }

  /**
   * Returns the string representation of this object. Do not parse data from
   * this string, it is for debugging only.
   *
   * @return A string representation of this object.
   */
  public String toString() {
    return super.toString() + "\n  Source: " + Functions.ckzCodeToName(source)
        + "\n  Source Data (hex): " + Functions.toHex(sourceData);
  }

}
