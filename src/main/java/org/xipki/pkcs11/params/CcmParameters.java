// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.
//
// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.params;

import iaik.pkcs.pkcs11.wrapper.CK_CCM_PARAMS;
import org.xipki.pkcs11.Functions;

/**
 * This class encapsulates parameters for the AES-CCM en/decryption
 *
 * @author Otto Touzil (SIC)
 * @author Lijun Liao (xipki)
 */
public class CcmParameters implements Parameters {
  private int dataLen;
  private final byte[] nonce;
  private final byte[] aad;
  private final int macLen;

  /**
   * Create a new CCMParameters object with the given attributes.
   *
   * @param dataLen length of the data where 0 &le; ulDataLen &lt; 2^8L. This length should not include the length
   *                of the MAC that is appended to the cipher text.
   *                (where L is the size in bytes of the data length's length(2 &lt; L &lt; 8)
   * @param nonce   the nonce
   * @param aad     additional authentication data. This data is authenticated but not encrypted.
   * @param macLen  length of the MAC (output following cipher text) in bytes. Valid values are
   *                (4, 6, 8, 10, 12, 14 and 16)
   */
  public CcmParameters(int dataLen, byte[] nonce, byte[] aad, int macLen) {
    this.nonce = Functions.requireNonNull("nonce", nonce);
    Functions.requireRange("nonce.length", nonce.length, 7, 13);
    this.macLen = Functions.requireAmong("macLen", macLen, 4, 6, 8, 10, 12, 14, 16);
    this.dataLen = dataLen;
    this.aad = aad;
  }

  /**
   * Get this parameters object as an object of the CK_CCM_PARAMS class.
   *
   * @return This object as a CK_CCM_PARAMS object.
   */
  @Override
  public CK_CCM_PARAMS getPKCS11ParamsObject() {
    CK_CCM_PARAMS params = new CK_CCM_PARAMS();
    params.pNonce = nonce;
    params.pAAD = aad;
    params.ulMacLen = macLen;
    params.ulDataLen = dataLen;

    return params;
  }

  public void setDataLen(int dataLen) {
    this.dataLen = dataLen;
  }

  /**
   * Returns the string representation of this object. Do not parse data from this string, it is for
   * debugging only.
   *
   * @return A string representation of this object.
   */
  @Override
  public String toString() {
    return "Class: " + getClass().getName() + "\n  DataLen: " + dataLen + ", MacLen: " + macLen +
        "\n  Nonce: " + Functions.toHex(nonce) + "\n  AAD: " + (aad == null ? "null" : Functions.toHex(nonce));
  }

}
