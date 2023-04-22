// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.params;

import iaik.pkcs.pkcs11.wrapper.CK_ECDH1_DERIVE_PARAMS;
import org.xipki.pkcs11.wrapper.Functions;

import static org.xipki.pkcs11.wrapper.PKCS11Constants.*;

/**
 * Represents the CK_ECDH1_DERIVE_PARAMS.
 *
 * @author Lijun Liao (xipki)
 */
public class ECDH1_DERIVE_PARAMS extends CkParams {

  private final CK_ECDH1_DERIVE_PARAMS params;

  /**
   * Create a new ECDH1_DERIVE_PARAMS object with the given
   * attributes.
   *
   * @param kdf
   *          The key derivation function used on the shared secret value.
   *          One of the values defined in KeyDerivationFunctionType.
   * @param sharedData
   *          The data shared between the two parties.
   * @param publicData
   *          The other party's public key value.
   */
  public ECDH1_DERIVE_PARAMS(long kdf, byte[] sharedData, byte[] publicData) {
    params = new CK_ECDH1_DERIVE_PARAMS();
    params.pPublicData = requireNonNull("publicData", publicData);
    params.kdf = Functions.requireAmong("kdf", kdf,
        CKD_NULL, CKD_SHA1_KDF, CKD_SHA1_KDF_ASN1, CKD_SHA1_KDF_CONCATENATE);
    params.pSharedData = sharedData;
  }

  @Override
  public CK_ECDH1_DERIVE_PARAMS getParams() {
    assertModuleSet();
    CK_ECDH1_DERIVE_PARAMS params0 = new CK_ECDH1_DERIVE_PARAMS();
    params0.kdf         = module.genericToVendor(Category.CKD, params.kdf);
    params0.pPublicData = params.pPublicData;
    params0.pSharedData = params.pSharedData;
    return params0;
  }

  @Override
  protected int getMaxFieldLen() {
    return 11; // pSharedData
  }

  @Override
  public String toString(String indent) {
    return indent + "CK_ECDH1_DERIVE_PARAMS:" +
        val2Str(indent, "kdf", (module == null)
            ? codeToName(Category.CKD, params.kdf) : module.codeToName(Category.CKD, params.kdf)) +
        ptr2str(indent, "pPublicData", params.pPublicData) +
        ptr2str(indent, "pSharedData", params.pSharedData);
  }

}
