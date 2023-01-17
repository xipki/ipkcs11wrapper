// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.
//
// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.params;

import iaik.pkcs.pkcs11.wrapper.CK_KEY_DERIVATION_STRING_DATA;
import org.xipki.pkcs11.Functions;

/**
 * This class encapsulates parameters for several key derivation mechanisms that need string data as
 * parameter.
 *
 * @author Karl Scheibelhofer (SIC)
 * @author Lijun Liao (xipki)
 */
public class KeyDerivationStringDataParameters implements Parameters {

  /**
   * The data.
   */
  private byte[] data;

  /**
   * Create a new KeyDerivationStringDataParameters object with the given data.
   *
   * @param data
   *          The string data.
   *
   */
  public KeyDerivationStringDataParameters(byte[] data) {
    this.data = Functions.requireNonNull("data", data);
  }

  /**
   * Get this parameters object as a byte array.
   *
   * @return This object as a byte array.
   *
   */
  @Override
  public CK_KEY_DERIVATION_STRING_DATA getPKCS11ParamsObject() {
    CK_KEY_DERIVATION_STRING_DATA params = new CK_KEY_DERIVATION_STRING_DATA();
    params.pData = data;
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
    return "Class: " + getClass().getName() + "\n  String data: " + Functions.toHex(data);
  }

}
