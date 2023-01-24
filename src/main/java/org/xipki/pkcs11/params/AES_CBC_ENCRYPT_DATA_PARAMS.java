// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.params;

import iaik.pkcs.pkcs11.wrapper.CK_AES_CBC_ENCRYPT_DATA_PARAMS;
import org.xipki.pkcs11.Functions;

/**
 * Represents the AES_CBC_ENCRYPT_DATA_PARAMS.
 *
 * @author Lijun Liao (xipki)
 */
public class AES_CBC_ENCRYPT_DATA_PARAMS extends CkParams {

  private final CK_AES_CBC_ENCRYPT_DATA_PARAMS params;

  /**
   * Create a new AES_CBC_ENCRYPT_DATA_PARAMS object with the given IV and data.
   *
   * @param iv
   *          The initialization vector.
   * @param data
   *          The key derivation data.
   *
   */
  public AES_CBC_ENCRYPT_DATA_PARAMS(byte[] iv, byte[] data) {
    params = new CK_AES_CBC_ENCRYPT_DATA_PARAMS();

    params.iv = requireNonNull("iv", iv);
    Functions.requireAmong("iv.length", iv.length, 16);

    params.pData = requireNonNull("data", data);
    if (data.length % 16 != 0) {
      throw new IllegalArgumentException("Argument data must have a length that is a multiple of blockSize.");
    }
  }

  @Override
  public CK_AES_CBC_ENCRYPT_DATA_PARAMS getParams() {
    return params;
  }

  @Override
  public String toString() {
    return "CK_AES_CBC_ENCRYPT_DATA_PARAMS: " +
        "\n  iv:    0x" + ptrToString(params.iv) +
        "\n  pData: 0x" + ptrToString(params.pData);
  }

}
