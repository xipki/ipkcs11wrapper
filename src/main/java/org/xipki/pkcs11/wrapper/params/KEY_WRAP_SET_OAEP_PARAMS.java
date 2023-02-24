// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.params;

import iaik.pkcs.pkcs11.wrapper.CK_KEY_WRAP_SET_OAEP_PARAMS;

/**
 * Represents the CK_KEY_WRAP_SET_OAEP_PARAMS.
 *
 * @author Lijun Liao (xipki)
 */
public class KEY_WRAP_SET_OAEP_PARAMS extends CkParams {

  private final CK_KEY_WRAP_SET_OAEP_PARAMS params;

  /**
   * Create a new KEY_WRAP_SET_OAEP_PARAMS object with the given attributes.
   *
   * @param blockContents
   *          The block contents byte.
   * @param x
   *          The concatenation of hash of plaintext data (if present) and extra data (if present).
   */
  public KEY_WRAP_SET_OAEP_PARAMS(byte blockContents, byte[] x) {
    params = new CK_KEY_WRAP_SET_OAEP_PARAMS();
    params.bBC = blockContents;
    params.pX = x;
  }

  @Override
  public CK_KEY_WRAP_SET_OAEP_PARAMS getParams() {
    return params;
  }

  @Override
  protected int getMaxFieldLen() {
    return 3; // bBC
  }

  @Override
  public String toString(String indent) {
    return indent + "CK_KEY_WRAP_SET_OAEP_PARAMS:" +
        val2Str(indent, "bBC", "0x" + Integer.toHexString(0xFF & params.bBC)) +
        ptr2str(indent, "pX", params.pX);
  }

}
