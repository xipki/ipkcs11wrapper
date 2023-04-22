// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.params;

import iaik.pkcs.pkcs11.wrapper.CK_ECDSA_ECIES_PARAMS;
import org.xipki.pkcs11.wrapper.PKCS11Constants;
import org.xipki.pkcs11.wrapper.PKCS11Constants.Category;

/**
 * Represents Utimaco's vendor CK_ECDSA_ECIES_PARAMS, which is used in
 * Utimaco's vendor mechanism CKM_ECDSA_ECIES
 *
 * hashAlg:<br>
 * CKM_SHA_1, CKM_SHA224, CKM_SHA256, CKM_SHA384,
 * CKM_SHA512, CKM_RIPEMD160, CKM_MD5
 * <br>
 *
 * cryptAlg:<br>
 * CKM_AES_ECB, CKM_AES_CBC, CKM_ECDSA_ECIES_XOR
 * <br>
 *
 * cryptOpt:<br>
 * Key Length of cryptAlg . (0 for CKM_ECDSA_ECIES_XOR )
 *
 * macAlg: <br>
 * CKM_SHA_1_HMAC, CKM_SHA224_HMAC, CKM_SHA256_HMAC,
 * CKM_SHA384_HMAC, CKM_SHA512_HMAC, CKM_MD5_HMAC,
 * CKM_RIPEMD160_HMAC
 * <br>
 * macOpt:<br>
 * currently ignored
 *
 * @author Lijun Liao (xipki)
 */
public class Utimaco_ECDSA_ECIES_PARAMS extends CkParams {

  private final CK_ECDSA_ECIES_PARAMS params;

  public Utimaco_ECDSA_ECIES_PARAMS(long hashAlg, long cryptAlg, long cryptOpt, long macAlg, long macOpt) {
    this(hashAlg, cryptAlg, cryptOpt, macAlg, macOpt, null, null);
  }

  public Utimaco_ECDSA_ECIES_PARAMS(long hashAlg, long cryptAlg, long cryptOpt, long macAlg, long macOpt,
                                    byte[] sharedSecret1, byte[] sharedSecret2) {
    params = new CK_ECDSA_ECIES_PARAMS();
    params.hashAlg = hashAlg;
    params.cryptAlg = cryptAlg;
    params.cryptOpt = cryptOpt;
    params.macAlg = macAlg;
    params.macOpt = macOpt;
    params.pSharedSecret1 = sharedSecret1;
    params.pSharedSecret2 = sharedSecret2;
  }

  @Override
  protected CK_ECDSA_ECIES_PARAMS getParams0() {
    CK_ECDSA_ECIES_PARAMS params0 = new CK_ECDSA_ECIES_PARAMS();
    params0.hashAlg        = module.genericToVendor(Category.CKM, params.hashAlg);
    params0.cryptAlg       = module.genericToVendor(Category.CKM, params.cryptAlg);;
    params0.cryptOpt       = params.cryptOpt;
    params0.macAlg         = module.genericToVendor(Category.CKM, params.macAlg);;
    params0.macOpt         = params.macOpt;
    params0.pSharedSecret1 = params.pSharedSecret1;
    params0.pSharedSecret2 = params.pSharedSecret2;
    return params0;
  }

  @Override
  protected int getMaxFieldLen() {
    return 13; // sharedSecret1
  }

  @Override
  public String toString(String indent) {
    return indent + "CK_ECDSA_ECIES_PARAMS:" +
        val2Str(indent, "hashAlg", PKCS11Constants.ckmCodeToName(params.hashAlg)) +
        val2Str(indent, "cryptAlg", PKCS11Constants.ckmCodeToName(params.cryptAlg)) +
        val2Str(indent, "cryptOpt", params.cryptOpt) +
        val2Str(indent, "macAlg", PKCS11Constants.ckmCodeToName(params.macAlg)) +
        val2Str(indent, "mac options", params.macOpt) +
        ptr2str(indent, "sharedSecret1", params.pSharedSecret1) +
        ptr2str(indent, "sharedSecret2", params.pSharedSecret2);
  }

}
