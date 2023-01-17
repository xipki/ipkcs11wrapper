// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.
//
// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.params;

/**
 * This class encapsulates parameters for Mechanisms.EXTRACT_KEY_FROM_KEY.
 *
 * @author Karl Scheibelhofer (SIC)
 * @author Lijun Liao (xipki)
 */
public class ExtractParameters implements Parameters {

  /**
   * The bit of the base key that should be used as the first bit of the
   * derived key.
   */
  private final int bitIndex;

  /**
   * Create a new ExtractParameters object with the given bit index.
   *
   * @param bitIndex
   *          The bit of the base key that should be used as the first bit of
   *          the derived key.
   */
  public ExtractParameters(int bitIndex) {
    this.bitIndex = bitIndex;
  }

  /**
   * Get this parameters object as a Long object.
   *
   * @return This object as a Long object.
   */
  @Override
  public Long getPKCS11ParamsObject() {
    return (long) bitIndex;
  }

  /**
   * Returns the string representation of this object. Do not parse data from
   * this string, it is for debugging only.
   *
   * @return A string representation of this object.
   */
  @Override
  public String toString() {
    return "Class: " + getClass().getName() + "\n  Bit Index (dec): " + bitIndex;
  }

}
