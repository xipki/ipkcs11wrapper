// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.params;

import iaik.pkcs.pkcs11.wrapper.CK_SALSA20_CHACHA20_POLY1305_PARAMS;

/**
 * Represents the CK_SALSA20_CHACHA20_POLY1305_PARAMS.
 *
 * @author Lijun Liao (xipki)
 */
public class SALSA20_CHACHA20_POLY1305_PARAMS extends CkParams implements CkMessageParams{

  private CK_SALSA20_CHACHA20_POLY1305_PARAMS params;

  /**
   * Create a new CK_SALSA20_CHACHA20_POLY1305_PARAMS object with the given attributes.
   *
   * @param nonce nonce (This should be never re-used with the same key.) <br>
   *               length of nonce in bits (is 64 for original, 96 for IETF (only for
   *               chacha20) and 192 for xchacha20/xsalsa20 variant)
   * @param aad additional authentication data. This data is authenticated but not encrypted.
   *
   */
  public SALSA20_CHACHA20_POLY1305_PARAMS(byte[] nonce, byte[] aad) {
    params = new CK_SALSA20_CHACHA20_POLY1305_PARAMS();
    params.pNonce = nonce;
    params.pAAD = aad;
  }

  @Override
  public CK_SALSA20_CHACHA20_POLY1305_PARAMS getParams() {
    return params;
  }

  /**
   * Read the parameters from the PKCS11Object and overwrite the values into this object.
   *
   * @param obj Object to read the parameters from
   */
  @Override
  public void setValuesFromPKCS11Object(Object obj) {
    this.params = (CK_SALSA20_CHACHA20_POLY1305_PARAMS) obj;
  }

  @Override
  public String toString() {
    return "CK_SALSA20_CHACHA20_POLY1305_PARAMS:" +
        "\n  pNonce: " + ptrToString(params.pNonce) +
        "\n  pAAD:   " + ptrToString(params.pAAD);
  }

}
