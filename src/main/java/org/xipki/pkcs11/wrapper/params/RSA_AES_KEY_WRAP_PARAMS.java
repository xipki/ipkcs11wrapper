// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.params;

import iaik.pkcs.pkcs11.wrapper.CK_RSA_AES_KEY_WRAP_PARAMS;
import org.xipki.pkcs11.wrapper.PKCS11Constants;

/**
 * Represents the CK_RSA_AES_KEY_WRAP_PARAMS.
 *
 * @author Lijun Liao (xipki)
 */
public class RSA_AES_KEY_WRAP_PARAMS extends CkParams {

  private final CK_RSA_AES_KEY_WRAP_PARAMS params;

  /**
   * Create a new RSA_AES_KEY_WRAP_PARAMS object with the given attributes.
   *
   * @param  AESKeyBits length of the temporary AES key in bits. Can be only 128, 192 or 256.
   * @param  OAEPParams parameters of the temporary AES key wrapping. See also the description of <br>
   *                     PKCS #1 RSA OAEP mechanism parameters.
   */
  public RSA_AES_KEY_WRAP_PARAMS(int AESKeyBits, RSA_PKCS_OAEP_PARAMS OAEPParams) {
    params = new CK_RSA_AES_KEY_WRAP_PARAMS();
    params.ulAESKeyBits = AESKeyBits;
    params.pOAEPParams = OAEPParams.getParams0();
  }

  @Override
  protected CK_RSA_AES_KEY_WRAP_PARAMS getParams0() {
    return params;
  }

  @Override
  protected int getMaxFieldLen() {
    return 11; // pSourceData
  }

  @Override
  public String toString(String indent) {
    return indent + "CK_RSA_AES_KEY_WRAP_PARAMS:" +
        val2Str(indent, "AESKeyBits", params.ulAESKeyBits) +
        "\n" + indent + "  pOAEPParams:" +
        val2Str(indent + "  ", "source",
            PKCS11Constants.codeToName(PKCS11Constants.Category.CKZ, params.pOAEPParams.source)) +
        ptr2str(indent, "pSourceData", params.pOAEPParams.pSourceData);
  }

}
