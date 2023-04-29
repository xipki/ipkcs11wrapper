// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.params;

import iaik.pkcs.pkcs11.wrapper.CK_X9_42_DH1_DERIVE_PARAMS;
import org.xipki.pkcs11.wrapper.PKCS11Constants;

import static org.xipki.pkcs11.wrapper.PKCS11Constants.*;

/**
 * Represents the CK_X9_42_DH1_DERIVE_PARAMS.
 *
 * @author Lijun Liao (xipki)
 */
public class X9_42_DH1_DERIVE_PARAMS extends CkParams {

  private final CK_X9_42_DH1_DERIVE_PARAMS params;

  public X9_42_DH1_DERIVE_PARAMS(long kdf, byte[] otherInfo, byte[] publicData) {
    params = new CK_X9_42_DH1_DERIVE_PARAMS();
    params.kdf = kdf;
    params.pOtherInfo = otherInfo;
    params.pPublicData = requireNonNull("publicData", publicData);
  }

  @Override
  public CK_X9_42_DH1_DERIVE_PARAMS getParams() {
    if (module == null || (params.kdf & CKM_VENDOR_DEFINED) == 0) {
      return params;
    } else {
      long newKdf = module.genericToVendorCode(PKCS11Constants.Category.CKD, params.kdf);
      if (newKdf == params.kdf) {
        return params;
      } else {
        CK_X9_42_DH1_DERIVE_PARAMS params0 = new CK_X9_42_DH1_DERIVE_PARAMS();
        params0.kdf = newKdf;
        params0.pPublicData = params.pPublicData;
        params0.pOtherInfo = params.pOtherInfo;
        return params0;
      }
    }
  }

  @Override
  protected int getMaxFieldLen() {
    return 11; // pPublicData
  }

  @Override
  public String toString(String indent) {
    return indent + "CK_X9_42_DH2_DERIVE_PARAMS:" +
        val2Str(indent, "kdf", (module == null)
            ? codeToName(Category.CKD, params.kdf) : module.codeToName(Category.CKD, params.kdf)) +
        ptr2str(indent, "pPublicData", params.pPublicData) +
        ptr2str(indent, "pOtherInfo", params.pOtherInfo);
  }

}
