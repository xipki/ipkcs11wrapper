// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.params;

import iaik.pkcs.pkcs11.wrapper.CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS;

/**
 * Represents the CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS.
 *
 * @author Lijun Liao (xipki)
 */
public class SALSA20_CHACHA20_POLY1305_MSG_PARAMS extends CkParams implements CkMessageParams {

  private CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS params;

  /**
   * Create a new CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS object with the given attributes.
   *
   * @param nonce The nonce.
   * @param tag authentication tag which is returned on MessageEncrypt, and provided on MessageDecrypt.
   *
   */
  public SALSA20_CHACHA20_POLY1305_MSG_PARAMS(byte[] nonce, byte[] tag) {
    params = new CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS();
    params.pNonce = nonce;
    params.pTag = tag;
  }

  @Override
  protected CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS getParams0() {
    return params;
  }

  @Override
  public void setValuesFromPKCS11Object(Object obj) {
    this.params = (CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS) obj;
  }

  @Override
  protected int getMaxFieldLen() {
    return 6; // pNonce
  }

  @Override
  public String toString(String indent) {
    return indent + "CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS:" +
        ptr2str(indent, "pNonce", params.pNonce) +
        ptr2str(indent, "pTag", params.pTag);
  }

}
