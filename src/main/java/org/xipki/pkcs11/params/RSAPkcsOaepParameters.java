// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.
//
// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.params;

import iaik.pkcs.pkcs11.wrapper.CK_RSA_PKCS_OAEP_PARAMS;
import org.xipki.pkcs11.Functions;

import static org.xipki.pkcs11.PKCS11Constants.*;

/**
 * This class encapsulates parameters for the Mechanism.RSA_PKCS_OAEP.
 *
 * @author Karl Scheibelhofer (SIC)
 * @author Lijun Liao (xipki)
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
    this.source = Functions.requireAmong("source", source, 0, CKZ_SALT_SPECIFIED);
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
   * Returns the string representation of this object. Do not parse data from
   * this string, it is for debugging only.
   *
   * @return A string representation of this object.
   */
  @Override
  public String toString() {
    return super.toString() + "\n  Source: " + codeToName(Category.CKZ, source)
        + "\n  Source Data (hex): " + Functions.toHex(sourceData);
  }

}
