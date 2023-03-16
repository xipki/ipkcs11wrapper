package org.xipki.pkcs11.wrapper.params;

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
