// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.params;

import iaik.pkcs.pkcs11.wrapper.CK_PKCS5_PBKD2_PARAMS;
import org.xipki.pkcs11.wrapper.Functions;
import org.xipki.pkcs11.wrapper.PKCS11Constants;

/**
 * Represents the CK_PKCS5_PBKD2_PARAMS.
 *
 * @author Lijun Liao (xipki)
 */
public class PKCS5_PBKD2_PARAMS extends CkParams {

  private final CK_PKCS5_PBKD2_PARAMS params;

  /**
   * Create a new PKCS5_PBKD2_PARAMS object with the given attributes.
   *
   * @param saltSource
   *          The source of the salt value. One of the constants defined in
   *          the SaltSourceType interface.
   * @param saltSourceData
   *          The data used as the input for the salt source.
   * @param iterations
   *          The number of iterations to perform when generating each block
   *          of random data.
   * @param prf
   *          The pseudo-random function (PRF) to used to generate the key.
   *          One of the constants defined in the PseudoRandomFunctionType
   *          interface.
   * @param prfData
   *          The data used as the input for PRF in addition to the salt
   *          value.
   */
  public PKCS5_PBKD2_PARAMS(long saltSource, byte[] saltSourceData, int iterations, long prf, byte[] prfData) {
    params = new CK_PKCS5_PBKD2_PARAMS();

    params.saltSource = Functions.requireAmong("saltSource", saltSource, PKCS11Constants.CKZ_SALT_SPECIFIED);
    params.pSaltSourceData = requireNonNull("saltSourceData", saltSourceData);
    params.iterations = iterations;
    params.prf = Functions.requireAmong("prf", prf, PKCS11Constants.CKP_PKCS5_PBKD2_HMAC_SHA1);
    params.pPrfData = requireNonNull("prfData", prfData);
  }

  @Override
  public CK_PKCS5_PBKD2_PARAMS getParams() {
    return params;
  }

  @Override
  protected int getMaxFieldLen() {
    return 16; // pSaltSourceData
  }

  @Override
  public String toString(String indent) {
    return indent + "CK_PKCS5_PBKD2_PARAMS:" +
        val2Str(indent, "saltSource",
            PKCS11Constants.codeToName(PKCS11Constants.Category.CKZ, params.saltSource)) +
        ptr2str(indent, "pSaltSourceData", params.pSaltSourceData) +
        val2Str(indent, "iterations", params.iterations) +
        val2Str(indent, "prf", PKCS11Constants.codeToName(PKCS11Constants.Category.CKP_PRF, params.prf)) +
        ptr2str(indent, "pPrfData", params.pPrfData);
  }

}
