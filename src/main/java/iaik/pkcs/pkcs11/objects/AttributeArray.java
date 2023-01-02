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

package iaik.pkcs.pkcs11.objects;

import sun.security.pkcs11.wrapper.CK_ATTRIBUTE;

/**
 * Objects of this class represent an attribute array of a PKCS#11 object
 * as specified by PKCS#11. This attribute is available since
 * cryptoki version 2.20.
 *
 *
 * @author Birgit Haas
 * @version 1.0
 */
public class AttributeArray extends Attribute {

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
  public AttributeArray(Long type) {
    super(type);
  }

  /**
   * Set the attributes of this attribute array by specifying a
   * GenericTemplate. Null, is also valid.
   * A call to this method sets the present flag to true.
   *
   * @param value
   *          The AttributeArray value to set. May be null.
   */
  public void setAttributeArrayValue(AttributeVector value) {
    template = value;
    ckAttribute.pValue = value.toCkAttributes();
    present = true;
  }

  /**
   * Get the attribute array value of this attribute. Null, is also possible.
   *
   * @return The attribute array value of this attribute or null.
   */
  public AttributeVector getAttributeArrayValue() {
    if (template != null) {
      return template;
    }

    if (!(ckAttribute.pValue != null && ((CK_ATTRIBUTE[]) ckAttribute.pValue).length > 0)) {
      return null;
    }

    CK_ATTRIBUTE[] attributesArray = (CK_ATTRIBUTE[]) ckAttribute.pValue;
    AttributeVector template = new AttributeVector();
    for (CK_ATTRIBUTE ck_attribute : attributesArray) {
      long type = ck_attribute.type;
      Class<?> implementation = Attribute.getAttributeClass(type);
      Attribute attribute;
      if (implementation == null) {
        attribute = new OtherAttribute(type);
        attribute.setType(type);
        attribute.setCkAttribute(ck_attribute);
      } else {
        try {
          attribute = (Attribute) implementation.getDeclaredConstructor(Attribute.class).newInstance();
          attribute.setCkAttribute(ck_attribute);
          attribute.setPresent(true);
          template.attr(attribute);
        } catch (Exception ex) {
          System.err.println("Error when trying to create a " + implementation
              + " instance for " + type + ": " + ex.getMessage());
        }
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
      template = getAttributeArrayValue();
    }

    return (template == null) ? "<NULL_PTR>" : template.toString();
  }

  @Override
  public void setValue(Object value) throws UnsupportedOperationException {
    setAttributeArrayValue((AttributeVector) value);
  }

}
