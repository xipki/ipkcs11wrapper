// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.params;

import iaik.pkcs.pkcs11.wrapper.CK_RSA_PKCS_PSS_PARAMS;
import org.xipki.pkcs11.wrapper.PKCS11Constants;
import org.xipki.pkcs11.wrapper.PKCS11Constants.Category;

import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKM_VENDOR_DEFINED;

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
    if (module == null || ((params.hashAlg & CKM_VENDOR_DEFINED) == 0) && (params.mgf & CKM_VENDOR_DEFINED) == 0) {
      return params;
    } else {
      long newHashAlg = module.genericToVendorCode(Category.CKM, params.hashAlg);
      long newMgf = module.genericToVendorCode(Category.CKG_MGF, params.mgf);
      if (newHashAlg == params.hashAlg && newMgf == params.mgf) {
        return params;
      } else {
        CK_RSA_PKCS_PSS_PARAMS params0 = new CK_RSA_PKCS_PSS_PARAMS();
        params0.hashAlg = newHashAlg;
        params0.mgf = newMgf;
        params0.sLen = params.sLen;
        return params0;
      }
    }
  }

  @Override
  protected int getMaxFieldLen() {
    return 7; // hashAlg
  }

  @Override
  public String toString(String indent) {
    return indent + "CK_RSA_PKCS_PSS_PARAMS:" +
        val2Str(indent, "hashAlg", (module == null
            ? PKCS11Constants.ckmCodeToName(params.hashAlg)
            : module.codeToName(Category.CKM, params.hashAlg))) +
        val2Str(indent, "mgf", (module == null
            ? PKCS11Constants.codeToName(Category.CKG_MGF, params.mgf)
            : module.codeToName(Category.CKG_MGF, params.mgf))) +
        val2Str(indent, "sLen", params.sLen);
  }

}
