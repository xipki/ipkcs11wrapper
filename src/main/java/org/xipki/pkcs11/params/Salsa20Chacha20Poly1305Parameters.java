// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.
//
// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.params;

import iaik.pkcs.pkcs11.wrapper.CK_SALSA20_CHACHA20_POLY1305_PARAMS;
import org.xipki.pkcs11.Functions;

/**
 * This class encapsulates parameters for the Salsa20Chacha20 en/decryption.
 *
 * @author Patrick Schuster (SIC)
 * @author Lijun Liao (xipki)
 */
public class Salsa20Chacha20Poly1305Parameters implements Parameters {

  protected byte[] nonce;
  protected byte[] aad;

  /**
   * Create a new Salsa20Chacha20Poly1305Parameters object with the given attributes.
   *
   * @param nonce nonce (This should be never re-used with the same key.) <br>
   *               length of nonce in bits (is 64 for original, 96 for IETF (only for
   *               chacha20) and 192 for xchacha20/xsalsa20 variant)
   * @param aad additional authentication data. This data is authenticated but not encrypted.
   *
   */
  public Salsa20Chacha20Poly1305Parameters(byte[] nonce, byte[] aad) {
    this.nonce = nonce;
    this.aad = aad;
  }

  /**
   * Get this parameters object as an object of the CK_SALSA20_CHACHA20_POLY1305_PARAMS class.
   *
   * @return This object as a CK_SALSA20_CHACHA20_POLY1305_PARAMS object.
   */
  @Override
  public CK_SALSA20_CHACHA20_POLY1305_PARAMS getPKCS11ParamsObject() {
    CK_SALSA20_CHACHA20_POLY1305_PARAMS params = new CK_SALSA20_CHACHA20_POLY1305_PARAMS();
    params.pNonce = nonce;
    params.pAAD = aad;

    return params;
  }

  /**
   * Read the parameters from the PKCS11Object and overwrite the values into this object.
   *
   * @param obj Object to read the parameters from
   */
  public void setValuesFromPKCS11Object(Object obj) {
    this.nonce = ((CK_SALSA20_CHACHA20_POLY1305_PARAMS) obj).pNonce;
    this.aad = ((CK_SALSA20_CHACHA20_POLY1305_PARAMS) obj).pAAD;
  }

  /**
   * Returns the string representation of this object. Do not parse data from this string, it is for
   * debugging only.
   *
   * @return A string representation of this object.
   */
  @Override
  public String toString() {
    return "Class: " + getClass().getName() +
        "\n  Nonce: " + Functions.toHex(nonce) + "\n  AAD: " + (aad == null ? " " : Functions.toHex(aad));
  }

}
