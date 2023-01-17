// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.
//
// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.params;

import iaik.pkcs.pkcs11.wrapper.CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS;
import org.xipki.pkcs11.Functions;

/**
 * This class encapsulates parameters for the Salsa20Chacha20 en/decryption.
 *
 * @author Patrick Schuster (SIC)
 * @author Lijun Liao (xipki)
 */
public class Salsa20Chacha20Poly1305MessageParameters implements MessageParameters {

  private byte[] nonce;
  private byte[] tag;

  /**
   * Create a new Salsa20Chacha20Poly1305MessageParameters object with the given attributes.
   *
   * @param nonce The nonce.
   * @param tag authentication tag which is returned on MessageEncrypt, and provided on MessageDecrypt.
   *
   */
  public Salsa20Chacha20Poly1305MessageParameters(byte[] nonce, byte[] tag) {
    this.nonce = nonce;
    this.tag = tag;
  }

  /**
   * Get this parameters object as an object of the CK_SALSA20_CHACHA20_MSG_POLY1305_PARAMS class.
   *
   * @return This object as a CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS object.
   */
  @Override
  public CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS getPKCS11ParamsObject() {
    CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS params = new CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS();
    params.pNonce = nonce;
    params.pTag = tag;
    return params;
  }

  /**
   * Read the parameters from the PKCS11Object and overwrite the values into this object.
   *
   * @param obj Object to read the parameters from
   */
  @Override
  public void setValuesFromPKCS11Object(Object obj) {
    this.nonce = ((CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS) obj).pNonce;
    this.tag = ((CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS) obj).pTag;
  }

  /**
   * Returns the string representation of this object. Do not parse data from this string, it is for
   * debugging only.
   *
   * @return A string representation of this object.
   */
  @Override
  public String toString() {
    return "Class: " + getClass().getName() + "\n  Nonce: " + Functions.toHex(nonce) +
        "\n  pTag: " + Functions.toHex(tag);
  }

}
