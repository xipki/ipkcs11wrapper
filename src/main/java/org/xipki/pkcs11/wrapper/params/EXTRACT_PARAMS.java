// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.params;

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
    super(bitIndex);
  }

  @Override
  protected int getMaxFieldLen() {
    return 9; // Bit Index
  }

  @Override
  public String toString(String indent) {
    return indent + "EXTRACT_PARAMS: " + getClass().getName() +
        val2Str(indent, "Bit Index", params);
  }

}
