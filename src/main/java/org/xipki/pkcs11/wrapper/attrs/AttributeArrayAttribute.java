// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.
//
// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.attrs;

import iaik.pkcs.pkcs11.wrapper.CK_ATTRIBUTE;
import org.xipki.pkcs11.wrapper.AttributeVector;
import org.xipki.pkcs11.wrapper.PKCS11Constants;

/**
 * Objects of this class represent an attribute array of a PKCS#11 object
 * as specified by PKCS#11. This attribute is available since
 * cryptoki version 2.20.
 *
 *
 * @author Birgit Haas (SIC)
 * @author Lijun Liao (xipki)
 */
public class AttributeArrayAttribute extends Attribute {

  /**
   * The attributes of this attribute array in their object class
   * representation. Needed for printing and comparing this attribute array.
   */
  private AttributeVector template;

  /**
   * Constructor taking the PKCS#11 type of the attribute.
   *
   * @param type
   *          The PKCS#11 type of this attribute; e.g. CKA_VALUE.
   */
  public AttributeArrayAttribute(long type) {
    super(type);
  }

  /**
   * Set the attributes of this attribute array by specifying an
   * AttributeVector. Null, is also valid.
   * A call to this method sets the present flag to true.
   *
   * @param value
   *          The AttributeArray value to set. May be null.
   * @return a reference to this object.
   */
  public AttributeArrayAttribute attributeArrayValue(AttributeVector value) {
    template = value;
    ckAttribute.pValue = value == null ? null : value.toCkAttributes();
    present = true;
    return this;
  }

  /**
   * Get the attribute array value of this attribute. Null, is also possible.
   *
   * @return The attribute array value of this attribute or null.
   */
  @Override
  public AttributeVector getValue() {
    if (template != null) {
      return template;
    }

    if (isNullValue() || ((CK_ATTRIBUTE[]) ckAttribute.pValue).length == 0) {
      return null;
    }

    CK_ATTRIBUTE[] attributesArray = (CK_ATTRIBUTE[]) ckAttribute.pValue;
    AttributeVector template = new AttributeVector();
    for (CK_ATTRIBUTE ck_attribute : attributesArray) {
      long type = ck_attribute.type;
      Attribute attr = getInstance0(type);
      if (attr == null) {
        // ignore
        System.err.println("Could not create attribute for the attribute type " + PKCS11Constants.ckaCodeToName(type));
      } else {
        template.attr(attr.ckAttribute(ck_attribute).present(true));
      }
    }
    return template;
  }

  /**
   * Get a string representation of the value of this attribute.
   *
   * @return A string representation of the value of this attribute.
   */
  @Override
  protected String getValueString() {
    if (template == null) {
      template = getValue();
    }

    return (template == null) ? "<NULL_PTR>" : "\n" + template.toString("    ");
  }

}
