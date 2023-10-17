// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.params;

import iaik.pkcs.pkcs11.wrapper.CK_X9_42_DHMQV_DERIVE_PARAMS;
import org.xipki.pkcs11.wrapper.PKCS11Constants;
import org.xipki.pkcs11.wrapper.PKCS11Constants.Category;

/**
 * Represents the CK_X9_42_MQV_DERIVE_PARAMS.
 *
 * @author Lijun Liao (xipki)
 */
public class X9_42_MQV_DERIVE_PARAMS extends CkParams {

  private final CK_X9_42_DHMQV_DERIVE_PARAMS params;

  public X9_42_MQV_DERIVE_PARAMS(long kdf, byte[] otherInfo, byte[] publicData, int privateDataLength,
                                 long privateDataHandle, byte[] publicData2, long publicKeyHandle) {
    params = new CK_X9_42_DHMQV_DERIVE_PARAMS();
    params.kdf = kdf;
    params.pOtherInfo = otherInfo;
    params.pPublicData = publicData;
    params.ulPrivateDataLen = privateDataLength;
    params.hPrivateData = privateDataHandle;
    params.pPublicData2 = publicData2;
    params.hPublicKey = publicKeyHandle;
  }

  @Override
  public CK_X9_42_DHMQV_DERIVE_PARAMS getParams() {
    if (module == null) {
      return params;
    }

    long newKdf = module.genericToVendorCode(PKCS11Constants.Category.CKD, params.kdf);
    if (newKdf == params.kdf) {
      return params;
    }

    CK_X9_42_DHMQV_DERIVE_PARAMS params0 = new CK_X9_42_DHMQV_DERIVE_PARAMS();
    params0.kdf = newKdf;
    params0.pOtherInfo = params.pOtherInfo;
    params0.pPublicData = params.pPublicData;
    params0.ulPrivateDataLen = params.ulPrivateDataLen;
    params0.hPrivateData = params.hPrivateData;
    params0.pPublicData2 = params.pPublicData2;
    params0.hPublicKey = params.hPublicKey;
    return params0;
  }

  @Override
  protected int getMaxFieldLen() {
    return 16; // ulPrivateDataLen
  }

  @Override
  public String toString(String indent) {
    return indent + "CK_X9_42_MQV_DERIVE_PARAMS:" +
        val2Str(indent, "kdf", codeToName(Category.CKD, params.kdf)) +
        ptr2str(indent, "pOtherInfo", params.pOtherInfo) +
        ptr2str(indent, "pPublicData", params.pPublicData) +
        val2Str(indent, "ulPrivateDataLen", params.ulPrivateDataLen) +
        val2Str(indent, "hPrivateData", params.hPrivateData) +
        ptr2str(indent, "pPublicData2", params.pPublicData2) +
        val2Str(indent, "hPublicKey", params.hPublicKey);
  }

}
