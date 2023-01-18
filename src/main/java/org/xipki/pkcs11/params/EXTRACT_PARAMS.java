// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.params;

/**
 * Represents the params of type CK_LONG for the extract mechanism.
 *
 * @author Lijun Liao (xipki)
 */
public class EXTRACT_PARAMS extends LongParams {

  /**
   * Create a new EXTRACT_PARAMS object with the given bit index.
   *
   * @param bitIndex
   *          The bit of the base key that should be used as the first bit of
   *          the derived key.
   */
  public EXTRACT_PARAMS(int bitIndex) {
    super((long) bitIndex);
  }

  @Override
  public String toString() {
    return "EXTRACT_PARAMS: " + getClass().getName() + "\n  Bit Index: " + params;
  }

}
