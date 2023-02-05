// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.
//
// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.attrs;

/**
 * Objects of this class represent a char-array attribute of a PKCS#11 object
 * as specified by PKCS#11.
 *
 * @author Karl Scheibelhofer (SIC)
 * @author Lijun Liao (xipki)
 */
public class CharArrayAttribute extends Attribute {

  /**
   * Constructor taking the PKCS#11 type of the attribute.
   *
   * @param type
   *          The PKCS#11 type of this attribute; e.g. CKA_LABEL.
   */
  public CharArrayAttribute(long type) {
    super(type);
  }

  /**
   * Set the char-array value of this attribute. Null, is also valid.
   * A call to this method sets the present flag to true.
   *
   * @param value
   *          The char-array value to set. May be null.
   * @return a reference to this object.
   */
  protected CharArrayAttribute charArrayValue(char[] value) {
    ckAttribute.pValue = value;
    present = true;
    return this;
  }

  /**
   * Set the char-array value of this attribute. Null, is also valid.
   * A call to this method sets the present flag to true.
   *
   * @param value
   *          The char-array value to set. May be null.
   * @return a reference to this object.
   */
  public CharArrayAttribute stringValue(String value) {
    return charArrayValue(value == null ? null : value.toCharArray());
  }

  /**
   * Get the string value of this attribute. Null, is also possible.
   *
   * @return The char-array value of this attribute or null.
   */
  @Override
  public String getValue() {
    return isNullValue() ? null : new String((char[]) ckAttribute.pValue);
  }

  /**
   * Get a string representation of the value of this attribute.
   *
   * @return A string representation of the value of this attribute.
   */
  @Override
  protected String getValueString() {
    String value = getValue();
    return (value != null) ? value : "<NULL_PTR>";
  }

}
