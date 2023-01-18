// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.params;

import iaik.pkcs.pkcs11.wrapper.CK_ECDH2_DERIVE_PARAMS;
import org.xipki.pkcs11.Functions;

import static org.xipki.pkcs11.PKCS11Constants.*;

/**
 * Represents the CK_ECDH2_DERIVE_PARAMS.
 *
 * @author Lijun Liao (xipki)
 */
public class ECDH2_DERIVE_PARAMS extends CkParams {

  private final CK_ECDH2_DERIVE_PARAMS params;

  /**
   * Create a new ECDH2_DERIVE_PARAMS object with the given
   * attributes.
   *
   * @param kdf
   *          The key derivation function used on the shared secret value.
   *          One of the values defined in KeyDerivationFunctionType.
   * @param sharedData
   *          The data shared between the two parties.
   * @param publicData
   *          The other partie's public key value.
   * @param privateDataLength
   *          The length in bytes of the second EC private key.
   * @param privateDataHandle
   *          The key for the second EC private key value.
   * @param publicData2
   *          The other party's second EC public key value.
   */
  public ECDH2_DERIVE_PARAMS(long kdf, byte[] sharedData, byte[] publicData,
                             int privateDataLength, long privateDataHandle, byte[] publicData2) {
    params = new CK_ECDH2_DERIVE_PARAMS();

    params.pPublicData = requireNonNull("publicData", publicData);
    params.kdf = Functions.requireAmong("kdf", kdf,
        CKD_NULL, CKD_SHA1_KDF, CKD_SHA1_KDF_ASN1, CKD_SHA1_KDF_CONCATENATE);

    params.pSharedData = sharedData;
    params.ulPrivateDataLen = privateDataLength;
    params.hPrivateData = privateDataHandle;
    params.pPublicData2 = requireNonNull("publicData2", publicData2);
  }

  @Override
  public CK_ECDH2_DERIVE_PARAMS getParams() {
    return params;
  }

  @Override
  public String toString() {
    return "CK_ECDH2_DERIVE_PARAMS:" +
        "\n  kdf:              " + codeToName(Category.CKD, params.kdf) +
        "\n  pPublicData:      " + ptrToString(params.pPublicData) +
        "\n  pSharedData:      " + Functions.toHex(params.pSharedData) +
        "\n  ulPrivateDataLen: " + params.ulPrivateDataLen +
        "\n  hPrivateData:     " + params.hPrivateData +
        "\n  pPublicData2:     " + ptrToString(params.pPublicData2);
  }

}
