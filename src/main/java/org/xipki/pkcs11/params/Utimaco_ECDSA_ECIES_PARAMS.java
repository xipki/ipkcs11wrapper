// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.params;

import iaik.pkcs.pkcs11.wrapper.CK_ECDSA_ECIES_PARAMS;

import static org.xipki.pkcs11.PKCS11Constants.ckmCodeToName;

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
  public CK_ECDSA_ECIES_PARAMS getParams() {
    return params;
  }

  @Override
  public String toString() {
    return "CK_ECDSA_ECIES_PARAMS:" +
        "\n  hashAlg:       " + ckmCodeToName(params.hashAlg) +
        "\n  cryptAlg:      " + ckmCodeToName(params.cryptAlg) +
        "\n  cryptOpt:      " + params.cryptOpt +
        "\n  macAlg:        " + ckmCodeToName(params.macAlg) +
        "\n  mac options:   " + params.macOpt +
        ptrToString("\n  sharedSecret1: ", params.pSharedSecret1) +
        ptrToString("\n  sharedSecret2: ", params.pSharedSecret2);
  }

}
