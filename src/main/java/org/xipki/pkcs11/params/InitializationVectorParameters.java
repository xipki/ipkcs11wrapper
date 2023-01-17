// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.
//
// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.params;

import org.xipki.pkcs11.Functions;

/**
 * This class encapsulates parameters for general block ciphers in CBC mode.
 * Those are all Mechanism.*_CBC and Mechanism.*_CBC_PAD mechanisms. This class
 * also applies to other mechanisms which require just an initialization vector
 * as parameter.
 *
 * @author Karl Scheibelhofer (SIC)
 * @author Lijun Liao (xipki)
 */
public class InitializationVectorParameters implements Parameters {

  /**
   * The initialization vector.
   */
  private final byte[] iv;

  /**
   * Create a new InitializationVectorParameters object with the given
   * initialization vector.
   *
   * @param iv
   *          The initialization vector.
   */
  public InitializationVectorParameters(byte[] iv) {
    this.iv = Functions.requireNonNull("iv", iv);
  }

  /**
   * Get this parameters object as a byte array.
   *
   * @return This object as a byte array.
   */
  @Override
  public byte[] getPKCS11ParamsObject() {
    return iv;
  }

  /**
   * Returns the string representation of this object. Do not parse data from
   * this string, it is for debugging only.
   *
   * @return A string representation of this object.
   */
  @Override
  public String toString() {
    return "Class: " + getClass().getName() + "\n  IV: " + Functions.toHex(iv);
  }

}
