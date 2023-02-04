// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.params;

import iaik.pkcs.pkcs11.wrapper.CK_KEY_DERIVATION_STRING_DATA;

/**
 * Represents the CK_KEY_DERIVATION_STRING_DATA.
 *
 * @author Lijun Liao (xipki)
 */
public class KEY_DERIVATION_STRING_DATA extends CkParams {

  private final CK_KEY_DERIVATION_STRING_DATA params;

  /**
   * Create a new KEY_DERIVATION_STRING_DATA object with the given data.
   *
   * @param data
   *          The string data.
   */
  public KEY_DERIVATION_STRING_DATA(byte[] data) {
    params = new CK_KEY_DERIVATION_STRING_DATA();
    params.pData = requireNonNull("data", data);
  }

  @Override
  public CK_KEY_DERIVATION_STRING_DATA getParams() {
    return params;
  }

  @Override
  public String toString() {
    return "CK_KEY_DERIVATION_STRING_DATA:" +
        ptrToString("\n  pData: ", params.pData);
  }

}
