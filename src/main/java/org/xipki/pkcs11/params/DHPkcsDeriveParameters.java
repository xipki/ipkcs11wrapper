// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.
//
// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.params;

import org.xipki.pkcs11.Functions;

/**
 * This class encapsulates parameters for the algorithms
 * Mechanism.DH_PKCS_DERIVE.
 *
 * @author Karl Scheibelhofer (SIC)
 * @author Lijun Liao (xipki)
 */
public class DHPkcsDeriveParameters implements Parameters {

  /**
   * The initialization vector.
   */
  private final byte[] publicValue;

  /**
   * Create a new DHPkcsDeriveParameters object with the given public value.
   *
   * @param publicValue
   *          The public value of the other party in the key agreement
   *          protocol.
   */
  public DHPkcsDeriveParameters(byte[] publicValue) {
    this.publicValue = Functions.requireNonNull("publicValue", publicValue);
  }

  /**
   * Get this parameters object as a byte array.
   *
   * @return This object as a byte array.
   */
  @Override
  public byte[] getPKCS11ParamsObject() {
    return publicValue;
  }

  /**
   * Returns the string representation of this object. Do not parse data from
   * this string, it is for debugging only.
   *
   * @return A string representation of this object.
   */
  @Override
  public String toString() {
    return "Class: " + getClass().getName() + "\n  Public Value: " + Functions.toHex(publicValue);
  }

}
