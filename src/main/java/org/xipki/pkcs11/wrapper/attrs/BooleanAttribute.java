// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.
//
// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.attrs;

/**
 * Objects of this class represent a boolean attribute of a PKCS#11 object
 * as specified by PKCS#11.
 *
 * @author Karl Scheibelhofer (SIC)
 * @author Lijun Liao (xipki)
 */
public class BooleanAttribute extends Attribute {

  /**
   * Constructor taking the PKCS#11 type of the attribute.
   *
   * @param type
   *          The PKCS#11 type of this attribute; e.g. CKA_PRIVATE.
   */
  public BooleanAttribute(long type) {
    super(type);
  }

  /**
   * Set the boolean value of this attribute. Null, is also valid.
   * A call to this method sets the present flag to true.
   *
   * @param value
   *          The boolean value to set. May be null.
   */
  public BooleanAttribute booleanValue(Boolean value) {
    ckAttribute.pValue = value;
    present = true;
    return this;
  }

  /**
   * Get the boolean value of this attribute. Null, is also possible.
   *
   * @return The boolean value of this attribute or null.
   */
  @Override
  public Boolean getValue() {
    return (Boolean) ckAttribute.pValue;
  }

  @Override
  protected String getValueString() {
    return isNullValue() ? "<NULL_PTR>" : (boolean) ckAttribute.pValue ? "TRUE" : "FALSE";
  }

}
