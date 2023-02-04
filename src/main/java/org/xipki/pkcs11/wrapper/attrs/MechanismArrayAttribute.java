// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.
//
// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.attrs;

import org.xipki.pkcs11.wrapper.PKCS11Constants;

/**
 * Objects of this class represent a mechanism array attribute of a PKCS#11
 * object as specified by PKCS#11. This attribute is available since
 * cryptoki version 2.20.
 *
 * @author Birgit Haas (SIC)
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
  @Override
  public long[] getValue() {
    return isNullValue() ? null : ((long[]) ckAttribute.pValue).clone();
  }

  /**
   * Get a string representation of the value of this attribute.
   *
   * @return A string representation of the value of this attribute.
   */
  @Override
  protected String getValueString() {
    long[] allowedMechanisms = getValue();
    if (allowedMechanisms != null && allowedMechanisms.length > 0) {
      StringBuilder sb = new StringBuilder(200);
      for (long mech : allowedMechanisms) {
        sb.append("\n      ").append(PKCS11Constants.ckmCodeToName(mech));
      }
      return sb.toString();
    } else {
      return "<NULL_PTR>";
    }
  }

}
