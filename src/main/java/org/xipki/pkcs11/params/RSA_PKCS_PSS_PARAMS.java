// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.params;

import iaik.pkcs.pkcs11.wrapper.CK_RSA_PKCS_PSS_PARAMS;
import org.xipki.pkcs11.PKCS11Constants;

import static org.xipki.pkcs11.PKCS11Constants.ckmCodeToName;
import static org.xipki.pkcs11.PKCS11Constants.codeToName;

/**
 * Represents the CK_RSA_PKCS_PSS_PARAMS.
 *
 * @author Lijun Liao (xipki)
 */
public class RSA_PKCS_PSS_PARAMS extends CkParams {

  private final CK_RSA_PKCS_PSS_PARAMS params;

  /**
   * Create a new CK_RSA_PKCS_PSS_PARAMS object with the given attributes.
   *
   * @param hashAlg
   *          The message digest algorithm used to calculate the digest of the encoding parameter.
   * @param mgf
   *          The mask to apply to the encoded block. One of the constants defined in the
   *          MessageGenerationFunctionType interface.
   * @param saltLength
   *          The length of the salt value in octets.
   */
  public RSA_PKCS_PSS_PARAMS(long hashAlg, long mgf, int saltLength) {
    params = new CK_RSA_PKCS_PSS_PARAMS();
    params.hashAlg = hashAlg;
    params.mgf = mgf;
    params.sLen = saltLength;
  }

  @Override
  public CK_RSA_PKCS_PSS_PARAMS getParams() {
    return params;
  }

  @Override
  public String toString() {
    return "CK_RSA_PKCS_PSS_PARAMS:" +
        "\n  hashAlg: " + ckmCodeToName(params.hashAlg) +
        "\n  mgf:     " + codeToName(PKCS11Constants.Category.CKG_MGF, params.mgf) +
        "\n  sLen:    " + params.sLen;
  }

}
