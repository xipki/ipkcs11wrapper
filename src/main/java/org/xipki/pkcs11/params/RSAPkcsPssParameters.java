// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.
//
// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.params;

import iaik.pkcs.pkcs11.wrapper.CK_RSA_PKCS_PSS_PARAMS;

/**
 * This class encapsulates parameters for the Mechanism.RSA_PKCS_PSS.
 *
 * @author Karl Scheibelhofer (SIC)
 * @author Lijun Liao (xipki)
 */
public class RSAPkcsPssParameters extends RSAPkcsParameters {

  /**
   * The length of the salt value in octets.
   */
  private final int saltLength;

  /**
   * Create a new RSAPkcsOaepParameters object with the given attributes.
   *
   * @param hashAlgorithm
   *          The message digest algorithm used to calculate the digest of the encoding parameter.
   * @param maskGenerationFunction
   *          The mask to apply to the encoded block. One of the constants defined in the
   *          MessageGenerationFunctionType interface.
   * @param saltLength
   *          The length of the salt value in octets.
   */
  public RSAPkcsPssParameters(long hashAlgorithm, long maskGenerationFunction, int saltLength) {
    super(hashAlgorithm, maskGenerationFunction);
    this.saltLength = saltLength;
  }

  /**
   * Get this parameters object as an object of the CK_RSA_PKCS_PSS_PARAMS class.
   *
   * @return This object as a CK_RSA_PKCS_PSS_PARAMS object.
   *
   */
  @Override
  public CK_RSA_PKCS_PSS_PARAMS getPKCS11ParamsObject() {
    CK_RSA_PKCS_PSS_PARAMS params = new CK_RSA_PKCS_PSS_PARAMS();

    params.hashAlg = hashAlg;
    params.mgf = mgf;
    params.sLen = saltLength;

    return params;
  }

  /**
   * Returns the string representation of this object. Do not parse data from this string, it is for
   * debugging only.
   *
   * @return A string representation of this object.
   */
  @Override
  public String toString() {
    return super.toString() + "\n  Salt Length (octets, dec): " + saltLength;
  }

}
