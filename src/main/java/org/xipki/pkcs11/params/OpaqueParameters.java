// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.params;

import org.xipki.pkcs11.Functions;

/**
 * This class encapsulates parameters byte arrays.
 *
 * @author Lijun Liao (xipki)
 */
public class OpaqueParameters implements Parameters {

  private final byte[] bytes;

  public OpaqueParameters(byte[] bytes) {
    this.bytes = Functions.requireNonNull("bytes", bytes);
  }

  /**
   * Get this parameters object as a byte array.
   *
   * @return This object as a byte array.
   */
  @Override
  public byte[] getPKCS11ParamsObject() {
    return bytes;
  }

  @Override
  public String toString() {
    return "Class: " + getClass().getName() + "\n  Bytes (hex): " + Functions.toHex(bytes);
  }

}
