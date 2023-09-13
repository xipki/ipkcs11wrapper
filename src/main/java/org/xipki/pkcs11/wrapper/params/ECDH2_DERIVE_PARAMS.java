// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.params;

import iaik.pkcs.pkcs11.wrapper.CK_ECDH2_DERIVE_PARAMS;

import static org.xipki.pkcs11.wrapper.PKCS11Constants.*;

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
   *          The other party's public key value.
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
    params.kdf = kdf;
    params.pSharedData = sharedData;
    params.ulPrivateDataLen = privateDataLength;
    params.hPrivateData = privateDataHandle;
    params.pPublicData2 = requireNonNull("publicData2", publicData2);
  }

  @Override
  public CK_ECDH2_DERIVE_PARAMS getParams() {
    if (module == null || (params.kdf & CKM_VENDOR_DEFINED) == 0) {
      return params;
    } else {
      long newKdf = module.genericToVendorCode(Category.CKD, params.kdf);
      if (newKdf == params.kdf) {
        return params;
      } else {
        CK_ECDH2_DERIVE_PARAMS params0 = new CK_ECDH2_DERIVE_PARAMS();
        params0.kdf = newKdf;
        params0.pPublicData = params.pPublicData;
        params0.pSharedData = params.pSharedData;
        params0.ulPrivateDataLen = params.ulPrivateDataLen;
        params0.hPrivateData = params.hPrivateData;
        params0.pPublicData2 = params.pPublicData2;
        return params0;
      }
    }
  }

  @Override
  protected int getMaxFieldLen() {
    return 16; // ulPrivateDataLen
  }

  @Override
  public String toString(String indent) {
    return indent + "CK_ECDH2_DERIVE_PARAMS:" +
        val2Str(indent, "kdf", (module == null)
            ? codeToName(Category.CKD, params.kdf) : module.codeToName(Category.CKD, params.kdf)) +
        ptr2str(indent, "pPublicData", params.pPublicData) +
        ptr2str(indent, "pSharedData", params.pSharedData) +
        val2Str(indent, "ulPrivateDataLen", params.ulPrivateDataLen) +
        val2Str(indent, "hPrivateData", params.hPrivateData) +
        ptr2str(indent, "pPublicData2", params.pPublicData2);
  }

}
