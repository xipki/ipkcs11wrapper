// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.params;

import org.xipki.pkcs11.Functions;

/**
 * This class encapsulates parameters byte arrays.
 *
 * @author Lijun Liao (xipki)
 */
public class ByteArrayParams extends CkParams {

  private final byte[] bytes;

  public ByteArrayParams(byte[] bytes) {
    this.bytes = Functions.requireNonNull("bytes", bytes);
  }

  @Override
  public byte[] getParams() {
    return bytes;
  }

  @Override
  public String toString() {
    return "ByteArray Params: " + getClass().getName() + "  : " + Functions.toHex(bytes);
  }

}
