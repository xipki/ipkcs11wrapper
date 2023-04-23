// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.params;

import iaik.pkcs.pkcs11.wrapper.CK_RSA_PKCS_PSS_PARAMS;
import org.xipki.pkcs11.wrapper.PKCS11Constants.Category;

import static org.xipki.pkcs11.wrapper.PKCS11Constants.ckmCodeToName;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.codeToName;

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
    assertModuleSet();
    CK_RSA_PKCS_PSS_PARAMS params0 = new CK_RSA_PKCS_PSS_PARAMS();
    params0.hashAlg     = module.genericToVendorCode(Category.CKM, params.hashAlg);
    params0.mgf         = module.genericToVendorCode(Category.CKG_MGF, params.mgf);
    params0.sLen        = params.sLen;
    return params0;
  }

  @Override
  protected int getMaxFieldLen() {
    return 7; // hashAlg
  }

  @Override
  public String toString(String indent) {
    return indent + "CK_RSA_PKCS_PSS_PARAMS:" +
        val2Str(indent, "hashAlg", (module == null
            ? ckmCodeToName(params.hashAlg) : module.codeToName(Category.CKM, params.hashAlg))) +
        val2Str(indent, "mgf", (module == null
            ? codeToName(Category.CKG_MGF, params.mgf) : module.codeToName(Category.CKG_MGF, params.mgf))) +
        val2Str(indent, "sLen", params.sLen);
  }

}
