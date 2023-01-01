// Copyright (c) 2002 Graz University of Technology. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// 3. The end-user documentation included with the redistribution, if any, must
//    include the following acknowledgment:
//
//    "This product includes software developed by IAIK of Graz University of
//     Technology."
//
//    Alternately, this acknowledgment may appear in the software itself, if and
//    wherever such third-party acknowledgments normally appear.
//
// 4. The names "Graz University of Technology" and "IAIK of Graz University of
//    Technology" must not be used to endorse or promote products derived from
//    this software without prior written permission.
//
// 5. Products derived from this software may not be called "IAIK PKCS Wrapper",
//    nor may "IAIK" appear in their name, without prior written permission of
//    Graz University of Technology.
//
// THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESSED OR IMPLIED
// WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE LICENSOR BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
// OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
// OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
// ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

package iaik.pkcs.pkcs11.parameters;

import iaik.pkcs.pkcs11.Util;

import java.util.Arrays;

/**
 * This class encapsulates parameters for the algorithms
 * Mechanism.DH_PKCS_DERIVE.
 *
 * @author Karl Scheibelhofer
 * @version 1.0
 */
public class DHPkcsDeriveParameters implements Parameters {

  /**
   * The initialization vector.
   */
  protected byte[] publicValue;

  /**
   * Create a new DHPkcsDeriveParameters object with the given public value.
   *
   * @param publicValue
   *          The public value of the other party in the key agreement
   *          protocol.
   */
  public DHPkcsDeriveParameters(byte[] publicValue) {
    this.publicValue = publicValue;
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
   * Get the public value of the other party in the key agreement protocol.
   *
   * @return The public value of the other party in the key agreement
   *         protocol.
   */
  public byte[] getPublicValue() {
    return publicValue;
  }

  /**
   * Set the public value of the other party in the key agreement protocol.
   *
   * @param publicValue
   *          The public value of the other party in the key agreement
   *          protocol.
   */
  public void setPublicValue(byte[] publicValue) {
    this.publicValue = Util.requireNonNull("publicValue", publicValue);
  }

  /**
   * Returns the string representation of this object. Do not parse data from
   * this string, it is for debugging only.
   *
   * @return A string representation of this object.
   */
  @Override
  public String toString() {
    return "  Public Value (hex): " + Util.toHex(publicValue);
  }

  /**
   * Compares all member variables of this object with the other object.
   * Returns only true, if all are equal in both objects.
   *
   * @param otherObject
   *          The other object to compare to.
   * @return True, if other is an instance of this class and all member
   *         variables of both objects are equal. False, otherwise.
   */
  @Override
  public boolean equals(Object otherObject) {
    if (this == otherObject) return true;
    else if (!(otherObject instanceof DHPkcsDeriveParameters)) return false;

    DHPkcsDeriveParameters other = (DHPkcsDeriveParameters) otherObject;
    return Arrays.equals(publicValue, other.publicValue);
  }

  /**
   * The overriding of this method should ensure that the objects of this
   * class work correctly in a hashtable.
   *
   * @return The hash code of this object.
   */
  @Override
  public int hashCode() {
    return Arrays.hashCode(publicValue);
  }

}
