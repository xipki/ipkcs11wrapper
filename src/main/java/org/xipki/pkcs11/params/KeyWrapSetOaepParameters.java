// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.
//
// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.params;

import iaik.pkcs.pkcs11.wrapper.CK_KEY_WRAP_SET_OAEP_PARAMS;
import org.xipki.pkcs11.Functions;

/**
 * This class encapsulates parameters for the Mechanism.KEY_WRAP_SET_OAEP.
 *
 * @author Karl Scheibelhofer (SIC)
 * @author Lijun Liao (xipki)
 */
public class KeyWrapSetOaepParameters implements Parameters {

  /**
   * The block contents byte.
   */
  private byte blockContents;

  /**
   * The concatenation of hash of plaintext data (if present) and extra data (if present).
   */
  private byte[] x;

  /**
   * Create a new KEADeriveParameters object with the given attributes.
   *
   * @param blockContents
   *          The block contents byte.
   * @param x
   *          The concatenation of hash of plaintext data (if present) and extra data (if present).
   */
  public KeyWrapSetOaepParameters(byte blockContents, byte[] x) {
    this.blockContents = blockContents;
    this.x = x;
  }

  /**
   * Get this parameters object as an object of the CK_KEY_WRAP_SET_OAEP_PARAMS class.
   *
   * @return This object as a CK_KEY_WRAP_SET_OAEP_PARAMS object.
   *
   */
  @Override
  public CK_KEY_WRAP_SET_OAEP_PARAMS getPKCS11ParamsObject() {
    CK_KEY_WRAP_SET_OAEP_PARAMS params = new CK_KEY_WRAP_SET_OAEP_PARAMS();

    params.bBC = blockContents;
    params.pX = x;

    return params;
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
        "\n  Block Contents Byte: 0x" + Integer.toHexString(0xFF & blockContents) + "\n  X: " + Functions.toHex(x);
  }

}
