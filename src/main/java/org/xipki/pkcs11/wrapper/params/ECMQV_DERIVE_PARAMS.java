// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.params;

import iaik.pkcs.pkcs11.wrapper.CK_ECMQV_DERIVE_PARAMS;
import org.xipki.pkcs11.wrapper.PKCS11Constants.Category;

import static org.xipki.pkcs11.wrapper.PKCS11Constants.codeToName;

/**
 * Represents the CK_ECMQV_DERIVE_PARAMS.
 *
 * @author Lijun Liao (xipki)
 */
public class ECMQV_DERIVE_PARAMS extends CkParams {

  private final CK_ECMQV_DERIVE_PARAMS params;

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
    assertModuleSet();
    CK_ECMQV_DERIVE_PARAMS params0 = new CK_ECMQV_DERIVE_PARAMS();
    params0.kdf              = module.genericToVendorCode(Category.CKD, params.kdf);
    params0.pPublicData      = params.pPublicData;
    params0.pSharedData      = params.pSharedData;
    params0.ulPrivateDataLen = params.ulPrivateDataLen;
    params0.hPrivateData     = params.hPrivateData;
    params0.pPublicData2     = params.pPublicData2;
    params0.publicKey        = params.publicKey;
    return params0;
  }

  @Override
  protected int getMaxFieldLen() {
    return 12; // hPrivateData
  }

  @Override
  public String toString(String indent) {
    return indent + "CK_ECMQV_DERIVE_PARAMS:" +
        val2Str(indent, "kdf", (module == null)
            ? codeToName(Category.CKD, params.kdf) : module.codeToName(Category.CKD, params.kdf)) +
        ptr2str(indent, "pPublicData", params.pPublicData) +
        ptr2str(indent, "pSharedData", params.pSharedData) +
        val2Str(indent, "hPrivateData", params.hPrivateData) +
        ptr2str(indent, "pPublicData2", params.pPublicData2) +
        val2Str(indent, "publicKey", params.publicKey);
  }

}
