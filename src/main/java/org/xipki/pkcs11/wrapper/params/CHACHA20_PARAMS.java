// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.params;

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
   * @param blockCounter the Block counter
   * @param nonce       the nonce
   */
  public CHACHA20_PARAMS(byte[] blockCounter, byte[] nonce) {
    params = new CK_CHACHA20_PARAMS();
    params.pBlockCounter = blockCounter;
    params.pNonce = nonce;
  }

  @Override
  public CK_CHACHA20_PARAMS getParams() {
    return params;
  }

  @Override
  protected int getMaxFieldLen() {
    return 12; // BlockCounter
  }

  @Override
  public String toString(String indent) {
    return indent + "CK_CHACHA20_PARAMS:" +
        ptr2str(indent, "BlockCounter", params.pBlockCounter) +
        ptr2str(indent, "pNonce", params.pNonce);
  }

}

