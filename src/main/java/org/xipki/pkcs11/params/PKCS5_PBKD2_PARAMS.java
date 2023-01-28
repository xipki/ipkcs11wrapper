// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.params;

import iaik.pkcs.pkcs11.wrapper.CK_PKCS5_PBKD2_PARAMS;
import org.xipki.pkcs11.Functions;

import static org.xipki.pkcs11.PKCS11Constants.*;

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

    params.saltSource = Functions.requireAmong("saltSource", saltSource, CKZ_SALT_SPECIFIED);
    params.pSaltSourceData = requireNonNull("saltSourceData", saltSourceData);
    params.iterations = iterations;
    params.prf = Functions.requireAmong("prf", prf, CKP_PKCS5_PBKD2_HMAC_SHA1);
    params.pPrfData = requireNonNull("prfData", prfData);
  }

  @Override
  public CK_PKCS5_PBKD2_PARAMS getParams() {
    return params;
  }

  @Override
  public String toString() {
    return "CK_PKCS5_PBKD2_PARAMS:" +
        "\n  saltSource:      " + codeToName(Category.CKZ, params.saltSource) +
        ptrToString("\n  pSaltSourceData: ", params.pSaltSourceData) +
        "\n  iterations:      " + params.iterations +
        "\n  prf:             " + codeToName(Category.CKP_PRF, params.prf) +
        ptrToString("\n  pPrfData:        ", params.pPrfData);
  }

}
