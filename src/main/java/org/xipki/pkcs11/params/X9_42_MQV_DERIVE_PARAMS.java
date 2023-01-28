// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.params;

import iaik.pkcs.pkcs11.wrapper.CK_X9_42_DHMQV_DERIVE_PARAMS;
import org.xipki.pkcs11.PKCS11Constants;

import static org.xipki.pkcs11.PKCS11Constants.codeToName;

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
    return params;
  }

  @Override
  public String toString() {
    return "CK_X9_42_MQV_DERIVE_PARAMS:" +
        "\n  kdf:              " + codeToName(PKCS11Constants.Category.CKD, params.kdf) +
        ptrToString("\n  pPublicData:      ", params.pPublicData) +
        "\n  ulPrivateDataLen: " + params.ulPrivateDataLen +
        "\n  hPrivateData:     " + params.hPrivateData +
        ptrToString("\n  pPublicData2:     ", params.pPublicData2) +
        "\n  hPublicKey:       " + params.hPublicKey;
  }

}
