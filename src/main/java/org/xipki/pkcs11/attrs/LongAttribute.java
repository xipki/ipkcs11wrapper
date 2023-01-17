// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.
//
// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.attrs;

/**
 * Objects of this class represent a long attribute of a PKCS#11 object
 * as specified by PKCS#11.
 *
 * @author Karl Scheibelhofer (SIC)
 * @author Lijun Liao (xipki)
 */
public class LongAttribute extends Attribute {

  /**
   * Constructor taking the PKCS#11 type of the attribute.
   *
   * @param type
   *          The PKCS#11 type of this attribute; e.g. CKA_VALUE_LEN.
   */
  public LongAttribute(long type) {
    super(type);
  }

  /**
   * Set the long value of this attribute. Null, is also valid.
   * A call to this method sets the present flag to true.
   *
   * @param value
   *          The long value to set. May be null.
   */
  public LongAttribute longValue(Long value) {
    ckAttribute.pValue = value;
    present = true;
    return this;
  }

  /**
   * Get the long value of this attribute. Null, is also possible.
   *
   * @return The long value of this attribute or null.
   */
  @Override
  public Long getValue() {
    return (Long) ckAttribute.pValue;
  }

  /**
   * Get the int value of this attribute. Null, is also possible.
   *
   * @return The int value of this attribute or null.
   */
  public Integer getIntValue() {
    return ckAttribute.pValue == null ? null : ((Long) ckAttribute.pValue).intValue();
  }

  /**
   * Get a string representation of this attribute. The radix for the
   * presentation of the value can be specified; e.g. 16 for hex, 10 for
   * decimal.
   *
   * @param radix
   *          The radix for the representation of the value.
   * @return A string representation of the value of this attribute.
   */
  public String toString(int radix) {
    String valueText = ((ckAttribute == null) || (ckAttribute.pValue == null)) ? "<NULL_PTR>"
        : Long.toString(((Long) ckAttribute.pValue), radix);
    return present ? (sensitive ? "<Value is sensitive>" : valueText) : "<Attribute not present>";
  }

}
