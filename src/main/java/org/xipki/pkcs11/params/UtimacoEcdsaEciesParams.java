// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.
//
// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.params;

import iaik.pkcs.pkcs11.wrapper.CK_ECDSA_ECIES_PARAMS;

import static org.xipki.pkcs11.PKCS11Constants.ckmCodeToName;

/**
 * Parameter class for the utimaco vendor defined ECIES encryption operation.
 * Possible values according to utimaco documentation: <br><br>
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
 * @author Stiftung SIC
 * @author Lijun Liao (xipki)
 */
public class UtimacoEcdsaEciesParams implements Parameters {

  private final long hashAlg;
  private final long cryptAlg;
  private final long cryptOpt;
  private final long macAlg;
  private final long macOpt;
  private final byte[] sharedSecret1;
  private final byte[] sharedSecret2;

  public UtimacoEcdsaEciesParams(long hashAlg, long cryptAlg, long cryptOpt, long macAlg, long macOpt) {
    this(hashAlg, cryptAlg, cryptOpt, macAlg, macOpt, null, null);
  }

  public UtimacoEcdsaEciesParams(long hashAlg, long cryptAlg, long cryptOpt, long macAlg, long macOpt,
                                 byte[] sharedSecret1, byte[] sharedSecret2) {
    this.hashAlg = hashAlg;
    this.cryptAlg = cryptAlg;
    this.cryptOpt = cryptOpt;
    this.macAlg = macAlg;
    this.macOpt = macOpt;
    this.sharedSecret1 = sharedSecret1 == null ? null : sharedSecret1.clone();
    this.sharedSecret2 = sharedSecret2 == null ? null : sharedSecret2.clone();
  }

  @Override
  public CK_ECDSA_ECIES_PARAMS getPKCS11ParamsObject() {
    CK_ECDSA_ECIES_PARAMS pkcs11Params = new CK_ECDSA_ECIES_PARAMS();
    pkcs11Params.hashAlg = hashAlg;
    pkcs11Params.cryptAlg = cryptAlg;
    pkcs11Params.cryptOpt = cryptOpt;
    pkcs11Params.macAlg = macAlg;
    pkcs11Params.macOpt = macOpt;
    pkcs11Params.pSharedSecret1 = sharedSecret1 == null ? null : sharedSecret1.clone();
    pkcs11Params.pSharedSecret2 = sharedSecret2 == null ? null : sharedSecret2.clone();

    return pkcs11Params;
  }

  @Override
  public String toString() {
    String ret = "Class: " + getClass().getName() + "\n  hash algorithm:   " + ckmCodeToName(hashAlg) +
        "\n  crypto algorithm: " + ckmCodeToName(cryptAlg) + "\n  crypto options:   " + cryptOpt +
        "\n  mac algorithm:    " + ckmCodeToName(macAlg) + "\n  mac options:      " + macOpt;

    if (sharedSecret1 != null) ret += "\n  shared secret1 (len): " + sharedSecret1.length;
    if (sharedSecret2 != null) ret += "\n  shared secret2 (len): " + sharedSecret2.length;

    return ret;
  }

}
