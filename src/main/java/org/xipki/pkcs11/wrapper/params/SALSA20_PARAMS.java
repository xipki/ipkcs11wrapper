// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.params;

import iaik.pkcs.pkcs11.wrapper.CK_SALSA20_PARAMS;

/**
 * Represents the CK_SALSA20_PARAMS.
 *
 * @author Lijun Liao (xipki)
 */
public class SALSA20_PARAMS extends CkParams {

  private final CK_SALSA20_PARAMS params;

  /**
   * Create a new SALSA20_PARAMS object with the given attributes.
   *
   * @param blockCounter the Blockcounter
   * @param nonce    the nonce
   */
  public SALSA20_PARAMS(byte[] blockCounter, byte[] nonce) {
    params = new CK_SALSA20_PARAMS();
    params.pBlockCounter = blockCounter;
    params.pNonce = nonce;
  }

  @Override
  protected CK_SALSA20_PARAMS getParams0() {
    return params;
  }

  @Override
  protected int getMaxFieldLen() {
    return 13; // pBlockCounter
  }

  @Override
  public String toString(String indent) {
    return indent + "CK_SALSA20_PARAMS: " +
        ptr2str(indent, "pBlockCounter", params.pBlockCounter) +
        ptr2str(indent, "pNonce", params.pNonce);
  }

}

