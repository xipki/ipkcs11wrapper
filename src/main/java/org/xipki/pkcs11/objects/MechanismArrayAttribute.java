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

package org.xipki.pkcs11.objects;

import org.xipki.pkcs11.Functions;

/**
 * Objects of this class represent a mechanism array attribute of a PKCS#11
 * object as specified by PKCS#11. This attribute is available since
 * cryptoki version 2.20.
 *
 * @author Birgit Haas
 * @author Lijun Liao (xipki)
 */
public class MechanismArrayAttribute extends Attribute {

  /**
   * Constructor taking the PKCS#11 type of the attribute.
   *
   * @param type
   *          The PKCS#11 type of this attribute; e.g. CKA_VALUE.
   */
  public MechanismArrayAttribute(long type) {
    super(type);
  }

  /**
   * Set the attributes of this mechanism attribute array by specifying a
   * Mechanism[]. Null, is also valid.
   * A call to this method sets the present flag to true.
   *
   * @param value
   *          The MechanismArrayAttribute value to set. May be null.
   */
  public MechanismArrayAttribute mechanismAttributeArrayValue(long[] value) {
    ckAttribute.pValue = value.clone();
    present = true;
    return this;
  }

  /**
   * Get the mechanism attribute array value of this attribute as Mechanism[].
   * Null, is also possible.
   *
   * @return The mechanism attribute array value of this attribute or null.
   */
  public long[] getMechanismAttributeArrayValue() {
    return ckAttribute.pValue == null ? null : ((long[]) ckAttribute.pValue).clone();
  }

  /**
   * Get a string representation of the value of this attribute.
   *
   * @return A string representation of the value of this attribute.
   */
  protected String getValueString() {
    long[] allowedMechanisms = getMechanismAttributeArrayValue();
    if (allowedMechanisms != null && allowedMechanisms.length > 0) {
      StringBuilder sb = new StringBuilder(200);
      for (long mech : allowedMechanisms) {
        sb.append("\n      ").append(Functions.ckmCodeToName(mech));
      }
      return sb.toString();
    } else {
      return "<NULL_PTR>";
    }
  }

}
