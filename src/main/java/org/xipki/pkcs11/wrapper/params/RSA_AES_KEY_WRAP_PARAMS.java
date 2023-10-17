// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.params;

import iaik.pkcs.pkcs11.wrapper.CK_RSA_AES_KEY_WRAP_PARAMS;
import iaik.pkcs.pkcs11.wrapper.CK_RSA_PKCS_OAEP_PARAMS;
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
    params.pOAEPParams = OAEPParams.getParams();
  }

  @Override
  public CK_RSA_AES_KEY_WRAP_PARAMS getParams() {
    if (module == null) {
      return params;
    }

    long newSource = module.genericToVendorCode(PKCS11Constants.Category.CKZ, params.pOAEPParams.source);
    long newMgf = module.genericToVendorCode(PKCS11Constants.Category.CKG_MGF, params.pOAEPParams.mgf);
    long newHashAlg = module.genericToVendorCode(PKCS11Constants.Category.CKM, params.pOAEPParams.hashAlg);

    if (newSource == params.pOAEPParams.source && newMgf == params.pOAEPParams.mgf
        && newHashAlg == params.pOAEPParams.hashAlg) {
      return params;
    }

    CK_RSA_AES_KEY_WRAP_PARAMS params0 = new CK_RSA_AES_KEY_WRAP_PARAMS();
    params0.ulAESKeyBits = params.ulAESKeyBits;
    params0.pOAEPParams = new CK_RSA_PKCS_OAEP_PARAMS();
    params0.pOAEPParams.source = newSource;
    params0.pOAEPParams.hashAlg = newHashAlg;
    params0.pOAEPParams.mgf = newMgf;
    params0.pOAEPParams.pSourceData = params.pOAEPParams.pSourceData;

    return params0;
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
            codeToName(PKCS11Constants.Category.CKZ, params.pOAEPParams.source)) +
        ptr2str(indent, "pSourceData", params.pOAEPParams.pSourceData);
  }

}
