// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.params;

import iaik.pkcs.pkcs11.wrapper.CK_CCM_PARAMS;
import org.xipki.pkcs11.wrapper.Functions;

/**
 * Represents the CK_CCM_PARAMS.
 *
 * @author Lijun Liao (xipki)
 */
public class CCM_PARAMS extends CkParams {

  private final CK_CCM_PARAMS params;

  /**
   * Create a new CCM_PARAMS object with the given attributes.
   *
   * @param dataLen length of the data where 0 &le; ulDataLen &lt; 2^8L. This length should not include the length
   *                of the MAC that is appended to the cipher text.
   *                (where L is the size in bytes of the data length's length(2 &lt; L &lt; 8)
   * @param nonce   the nonce
   * @param aad     additional authentication data. This data is authenticated but not encrypted.
   * @param macLen  length of the MAC (output following cipher text) in bytes. Valid values are
   *                (4, 6, 8, 10, 12, 14 and 16)
   */
  public CCM_PARAMS(int dataLen, byte[] nonce, byte[] aad, int macLen) {
    params = new CK_CCM_PARAMS();
    params.pNonce = requireNonNull("nonce", nonce);
    Functions.requireRange("nonce.length", nonce.length, 7, 13);
    params.ulMacLen = Functions.requireAmong("macLen", macLen, 4, 6, 8, 10, 12, 14, 16);
    params.ulDataLen = dataLen;
    params.pAAD = aad;
  }

  @Override
  public CK_CCM_PARAMS getParams() {
    return params;
  }

  public void setDataLen(int dataLen) {
    params.ulDataLen = dataLen;
  }

  @Override
  public String toString() {
    return "CK_CCM_PARAMS:" +
        "\n  ulDataLen: " + params.ulDataLen +
        ptrToString("\n, pNonce:    ", params.pNonce) +
        ptrToString("\n  pAAD:      ", params.pAAD) +
        "\n  ulMacLen:  " + params.ulMacLen;
  }

}
