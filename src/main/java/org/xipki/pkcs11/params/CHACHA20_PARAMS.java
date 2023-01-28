// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.params;

import iaik.pkcs.pkcs11.wrapper.CK_CHACHA20_PARAMS;

/**
 * Represents the CK_CHACHA20_PARAMS.
 *
 * @author Lijun Liao (xipki)
 */
public class CHACHA20_PARAMS extends CkParams {

  private final CK_CHACHA20_PARAMS params;

  /**
   * Create a new CHACHA20_PARAMS object with the given attributes.
   *
   * @param blockCounter the Blockcounter
   * @param nonce       the nonce
   */
  public CHACHA20_PARAMS(byte[] blockCounter, byte[] nonce) {
    params = new CK_CHACHA20_PARAMS();
    params.pBlockCounter = blockCounter;
    params.pNonce = nonce;
  }

  @Override
  public iaik.pkcs.pkcs11.wrapper.CK_CHACHA20_PARAMS getParams() {
    return params;
  }

  @Override
  public String toString() {
    return "CK_CHACHA20_PARAMS:" +
        ptrToString("\n  BlockCounter: ", params.pBlockCounter) +
        ptrToString("\n  pNonce:       ", params.pNonce);
  }

}

