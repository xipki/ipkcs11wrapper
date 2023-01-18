// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.params;

import iaik.pkcs.pkcs11.wrapper.CK_ECMQV_DERIVE_PARAMS;
import org.xipki.pkcs11.Functions;
import org.xipki.pkcs11.PKCS11Constants;

import static org.xipki.pkcs11.PKCS11Constants.codeToName;

/**
 * Represents the CK_ECMQV_DERIVE_PARAMS.
 *
 * @author Lijun Liao (xipki)
 */
public class ECMQV_DERIVE_PARAMS extends CkParams {

  private CK_ECMQV_DERIVE_PARAMS params;

  /**
   * Create a new ECMQV_DERIVE_PARAMS object with the given attributes.
   *
   * @param kdf
   *          The key derivation function used on the shared secret value. One of the values defined
   *          in KeyDerivationFunctionType.
   * @param sharedData
   *          The data shared between the two parties.
   * @param publicData
   *          The other partie's public key value.
   * @param privateDataLen
   *          the length in bytes of the second EC private key
   * @param privateData
   *          Key handle for second EC private key value
   * @param publicData2
   *          pointer to other party's second EC public key value
   * @param publicKey
   *          Handle to the first party's ephemeral public key
   */
  public ECMQV_DERIVE_PARAMS(long kdf, byte[] sharedData, byte[] publicData,
                             int privateDataLen, long privateData, byte[] publicData2, long publicKey) {
    params = new CK_ECMQV_DERIVE_PARAMS();

    params.kdf = kdf;
    params.pSharedData = sharedData;
    params.pPublicData = requireNonNull("publicData", publicData);
    params.ulPrivateDataLen = privateDataLen;
    params.hPrivateData = privateData;
    params.pPublicData2 = publicData2;
    params.publicKey = publicKey;
  }

  @Override
  public CK_ECMQV_DERIVE_PARAMS getParams() {
    return params;
  }

  @Override
  public String toString() {
    return "CK_ECMQV_DERIVE_PARAMS:" +
        "\n  kdf:          " + codeToName(PKCS11Constants.Category.CKD, params.kdf) +
        "\n  pPublicData:  " + ptrToString(params.pPublicData) +
        "\n  pSharedData:  " + Functions.toHex(params.pSharedData) +
        "\n  hPrivateData: " + params.hPrivateData +
        "\n  pPublicData2: " + Functions.toHex(params.pPublicData2) +
        "\n  publicKey:    " + params.publicKey;
  }

}
