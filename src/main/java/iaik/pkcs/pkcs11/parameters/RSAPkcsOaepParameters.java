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

package iaik.pkcs.pkcs11.parameters;

import iaik.pkcs.pkcs11.Util;
import sun.security.pkcs11.wrapper.CK_RSA_PKCS_OAEP_PARAMS;

import java.util.Arrays;

import static iaik.pkcs.pkcs11.wrapper.PKCS11Constants.CKZ_DATA_SPECIFIED;
import static iaik.pkcs.pkcs11.wrapper.PKCS11Constants.CKZ_SALT_SPECIFIED;

/**
 * This class encapsulates parameters for the Mechanism.RSA_PKCS_OAEP.
 *
 * @author Karl Scheibelhofer
 * @version 1.0
 */
public class RSAPkcsOaepParameters extends RSAPkcsParameters {

  /**
   * The source of the encoding parameter.
   */
  protected long source;

  /**
   * The data used as the input for the encoding parameter source.
   */
  protected byte[] sourceData;

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
    if ((source != 0) && (source != CKZ_SALT_SPECIFIED)) {
      throw new IllegalArgumentException("Illegal value for argument 'source': " + Long.toHexString(source));
    }
    this.source = source;
    this.sourceData = sourceData;
  }

  /**
   * Get this parameters object as an object of the CK_RSA_PKCS_OAEP_PARAMS
   * class.
   *
   * @return This object as a CK_RSA_PKCS_OAEP_PARAMS object.
   */
  @Override
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
   * Set the source of the encoding parameter. One of the constants defined in
   * the SourceType interface.
   *
   * @param source
   *          The source of the encoding parameter.
   */
  public void setSource(long source) {
    if ((source != 0) && (source != CKZ_SALT_SPECIFIED)) {
      throw new IllegalArgumentException("Illegal value for argument 'source': " + Long.toHexString(source));
    }
    this.source = source;
  }

  /**
   * Set the data used as the input for the encoding parameter source.
   *
   * @param sourceData
   *          The data used as the input for the encoding parameter source.
   */
  public void setSourceData(byte[] sourceData) {
    this.sourceData = sourceData;
  }

  /**
   * Returns the string representation of this object. Do not parse data from
   * this string, it is for debugging only.
   *
   * @return A string representation of this object.
   */
  @Override
  public String toString() {
    String sourceStr;
    if (source == 0) {
      sourceStr = "Empty";
    } else if (source == CKZ_DATA_SPECIFIED) {
      sourceStr = "Data Specified";
    } else {
      sourceStr = "<unknown>";
    }

    String upperStr = super.toString();
    return upperStr + "\n  Source: " + sourceStr + "\n  Source Data (hex): " + Util.toHex(sourceData);
  }

  /**
   * Compares all member variables of this object with the other object.
   * Returns only true, if all are equal in both objects.
   *
   * @param otherObject
   *          The other object to compare to.
   * @return True, if other is an instance of this class and all member
   *         variables of both objects are equal. False, otherwise.
   */
  @Override
  public boolean equals(Object otherObject) {
    if (this == otherObject) return true;
    else if (!(otherObject instanceof RSAPkcsOaepParameters)) return false;

    RSAPkcsOaepParameters other = (RSAPkcsOaepParameters) otherObject;
    return super.equals(other) && (source == other.source) && Arrays.equals(sourceData, other.sourceData);
  }

  /**
   * The overriding of this method should ensure that the objects of this
   * class work correctly in a hashtable.
   *
   * @return The hash code of this object.
   */
  @Override
  public int hashCode() {
    return super.hashCode() ^ ((int) source) ^ Arrays.hashCode(sourceData);
  }

}
