// Copyright (c) 2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.params;

/**
 * Provides extra parameters. E.g. the order bit size of an EC curve.
 *
 * @author Lijun Liao
 */
public class ExtraParams {

  private int ecOrderBitSize;

  public int ecOrderBitSize() {
    return ecOrderBitSize;
  }

  public ExtraParams ecOrderBitSize(int ecOrderBitSize) {
    this.ecOrderBitSize = ecOrderBitSize;
    return this;
  }

}
