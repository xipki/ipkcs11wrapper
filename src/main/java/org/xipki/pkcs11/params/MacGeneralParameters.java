// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.
//
// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.params;

/**
 * This class encapsulates parameters for the MAC algorithms for the following
 * mechanisms: DES, DES3 (triple-DES), CAST, CAST3, CAST128 (CAST5), IDEA, and
 * CDMF ciphers.
 *
 * @author Karl Scheibelhofer (SIC)
 * @author Lijun Liao (xipki)
 */
public class MacGeneralParameters implements Parameters {

  /**
   * The length of the MAC produced, in bytes.
   */
  private int macLength;

  /**
   * Create a new MacGeneralParameters object with the given MAC length.
   *
   * @param macLength
   *          The length of the MAC produced, in bytes.
   */
  public MacGeneralParameters(int macLength) {
    this.macLength = macLength;
  }

  /**
   * Get this parameters object as a Long object.
   *
   * @return This object as a Long object.
   */
  @Override
  public Long getPKCS11ParamsObject() {
    return (long) macLength;
  }

  /**
   * Returns the string representation of this object. Do not parse data from
   * this string, it is for debugging only.
   *
   * @return A string representation of this object.
   */
  @Override
  public String toString() {
    return "Class: " + getClass().getName() + "\n  Mac Length (dec): " + macLength;
  }

}
