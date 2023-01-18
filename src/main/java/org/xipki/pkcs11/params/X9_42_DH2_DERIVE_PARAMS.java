// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.params;

import iaik.pkcs.pkcs11.wrapper.CK_X9_42_DH2_DERIVE_PARAMS;
import org.xipki.pkcs11.PKCS11Constants;

/**
 * Represents the CK_X9_42_DH2_DERIVE_PARAMS.
 *
 * @author Lijun Liao (xipki)
 */
public class X9_42_DH2_DERIVE_PARAMS extends CkParams {

  private CK_X9_42_DH2_DERIVE_PARAMS params;

  public X9_42_DH2_DERIVE_PARAMS(long kdf, byte[] otherInfo, byte[] publicData,
                                 int privateDataLength, long privateDataHandle, byte[] publicData2) {
    params = new CK_X9_42_DH2_DERIVE_PARAMS();
    params.kdf = kdf;
    params.pOtherInfo = otherInfo;
    params.pPublicData = requireNonNull("publicData", publicData);
    params.ulPrivateDataLen = privateDataLength;
    params.hPrivateData = privateDataHandle;
    params.pPublicData2 = requireNonNull("publicData2", publicData2);
  }

  @Override
  public CK_X9_42_DH2_DERIVE_PARAMS getParams() {
    return params;
  }

  @Override
  public String toString() {
    return "CK_X9_42_DH2_DERIVE_PARAMS:" +
        "\n  kdf:              " + PKCS11Constants.codeToName(PKCS11Constants.Category.CKD, params.kdf) +
        "\n  pPublicData:      " + ptrToString(params.pPublicData) +
        "\n  pOtherInfo:       " + ptrToString(params.pOtherInfo)  +
        "\n  ulPrivateDataLen: " + params.ulPrivateDataLen +
        "\n  hPrivateData:     " + params.hPrivateData +
        "\n  pPublicData2:     " + ptrToString(params.pPublicData2);
  }

}
