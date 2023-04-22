// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.params;

import org.xipki.pkcs11.wrapper.Functions;

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
  protected byte[] getParams0() {
    return bytes;
  }

  @Override
  protected int getMaxFieldLen() {
    return 0;
  }

  @Override
  public String toString(String indent) {
    return  indent + "ByteArray Params:\n" + Functions.toString(indent + "  ", bytes);
  }

}
