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

package org.xipki.pkcs11.attrs;

import iaik.pkcs.pkcs11.wrapper.CK_ATTRIBUTE;
import org.xipki.pkcs11.AttributeVector;
import org.xipki.pkcs11.Functions;

import java.math.BigInteger;
import java.util.*;

import static org.xipki.pkcs11.PKCS11Constants.*;

/**
 * This is the base-class for all types of attributes. In general, all PKCS#11
 * objects are just a collection of attributes. PKCS#11 specifies which
 * attributes each type of objects must have.
 * In some cases, attributes are optional (e.g. in RSAPrivateKey). In such a
 * case, this attribute will return false when the application calls
 * isPresent() on this attribute. This means, that the object does not
 * possess this attribute (maybe even though it should, but not all drivers
 * seem to implement the standard correctly). Handling attributes in this
 * fashion ensures that this library can work also with drivers that are
 * not fully compliant.
 * Moreover, certain attributes can be sensitive; i.e. their values cannot
 * be read, e.g. the private exponent of an RSA private key.
 *
 * @author Karl Scheibelhofer
 * @author Lijun Liao (xipki)
 */
public abstract class Attribute {

  private static final Map<Long, Class<?>> attributeClasses;

  /**
   * True, if the object really possesses this attribute.
   */
  protected boolean present;

  /**
   * True, if this attribute is sensitive.
   */
  protected boolean sensitive;

  /**
   * True, if status of this attribute is known.
   */
  protected boolean stateKnown;

  /**
   * The CK_ATTRIBUTE that is used to hold the PKCS#11 type of this attribute
   * and the value.
   */
  protected CK_ATTRIBUTE ckAttribute;

  static {
    attributeClasses = new HashMap<>(130);
    String propFile = "org/xipki/pkcs11/type-CKA.properties";
    Properties props = new Properties();
    try {
      props.load(Functions.class.getClassLoader().getResourceAsStream(propFile));
      for (String name : props.stringPropertyNames()) {
        name = name.trim();
        String type = props.getProperty(name).trim();
        long code = nameToCode(Category.CKA, name);
        if (code == -1) throw new IllegalStateException("unknown CKA: " + name);

        if (attributeClasses.containsKey(code)) {
          throw new IllegalStateException("duplicated definition of CKA: " + name);
        }

        Class<?> clazz = "Boolean".equalsIgnoreCase(type) ? BooleanAttribute.class
            : "Long".equalsIgnoreCase(type) ? LongAttribute.class
            : "CharArray".equalsIgnoreCase(type) ? CharArrayAttribute.class
            : "ByteArray".equalsIgnoreCase(type) ? ByteArrayAttribute.class
            : "Date".equalsIgnoreCase(type) ? DateAttribute.class
            : "Mechanism".equalsIgnoreCase(type) ? MechanismAttribute.class
            : "MechanismArray".equalsIgnoreCase(type) ? MechanismArrayAttribute.class
            : "AttributeArray".equalsIgnoreCase(type) ? AttributeArrayAttribute.class : null;

        if (clazz == null) throw new IllegalStateException("unknown type " + type);

        attributeClasses.put(code, clazz);
      }
    } catch (Throwable t) {
      throw new IllegalStateException("error reading properties file " + propFile + ": " + t.getMessage());
    }

    if (attributeClasses.isEmpty()) {
      throw new IllegalStateException("no code to name map is defined properties file " + propFile);
    }
  }

  public abstract Object getValue();

  /**
   * Constructor taking the PKCS#11 type of the attribute.
   *
   * @param type
   *          The PKCS#11 type of this attribute; e.g. CKA_PRIVATE.
   */
  protected Attribute(long type) {
    present = false;
    sensitive = false;
    stateKnown = true;
    ckAttribute = new CK_ATTRIBUTE();
    ckAttribute.type = type;
  }

  public static Attribute getInstance(long type) {
    Class<?> clazz = getAttributeClass(type);
    if (clazz == null) {
      throw new IllegalArgumentException("Unknown attribute type " + codeToName(Category.CKA, type));
    }
    Attribute attr = (clazz == BooleanAttribute.class) ? new BooleanAttribute(type)
        : (clazz == ByteArrayAttribute.class) ? new ByteArrayAttribute(type)
        : (clazz == CharArrayAttribute.class) ? new CharArrayAttribute(type)
        : (clazz == DateAttribute.class)      ? new DateAttribute(type)
        : (clazz == LongAttribute.class)      ? new LongAttribute(type)
        : (clazz == MechanismAttribute.class) ? new MechanismAttribute(type)
        : (clazz == MechanismArrayAttribute.class) ? new MechanismArrayAttribute(type)
        : (clazz == AttributeArrayAttribute.class) ? new AttributeArrayAttribute(type)
        : null;
    if (attr == null) {
      throw new IllegalStateException("unknown class " + clazz);
    }
    return attr;
  }

  public static Attribute getInstance(long type, Object value) {
    Class<?> clazz = getAttributeClass(type);
    if (clazz == null) {
      throw new IllegalArgumentException("Unknown attribute type " + codeToName(Category.CKA, type));
    }

    if (clazz == BooleanAttribute.class) {
      return new BooleanAttribute(type).booleanValue((Boolean) value);
    } else if (clazz == ByteArrayAttribute.class) {
      byte[] baValue;
      if (value == null)                baValue = null;
      else if (value instanceof byte[]) baValue = (byte[]) value;
      else {
        baValue = ((BigInteger) value).toByteArray();
        if (baValue[0] == 0) baValue = Arrays.copyOfRange(baValue, 1, baValue.length);
      }
      return new ByteArrayAttribute(type).byteArrayValue(baValue);
    } else if (clazz == CharArrayAttribute.class) {
      CharArrayAttribute attr = new CharArrayAttribute(type);
      if (value == null)                return attr.charArrayValue(null);
      else if (value instanceof char[]) return attr.charArrayValue((char[]) value);
      else                              return attr.stringValue((String) value);
    } else if (clazz == DateAttribute.class) {
      return new DateAttribute(type).dateValue((Date) value);
    } else if (clazz == LongAttribute.class || clazz == MechanismAttribute.class) {
      LongAttribute attr = (clazz == LongAttribute.class) ? new LongAttribute(type) : new MechanismAttribute(type);
      if (value == null)              return attr.longValue(null);
      else if (value instanceof Long) return attr.longValue((Long) value);
      else                            return attr.longValue((long) (int) value);
    } else if (clazz == MechanismArrayAttribute.class) {
      return new MechanismArrayAttribute(type).mechanismAttributeArrayValue((long[]) value);
    } else if (clazz == AttributeArrayAttribute.class) {
      return new AttributeArrayAttribute(type).attributeArrayValue((AttributeVector) value);
    } else {
      throw new IllegalStateException("unknown class " + clazz); // should not reach here
    }
  }

  /**
   * Get the class of the given attribute type.
   * Current existing Attribute classes are:
   *           AttributeArray
   *           BooleanAttribute
   *           ByteArrayAttribute
   *           CharArrayAttribute
   *           DateAttribute
   *           LongAttribute
   *           MechanismAttribute
   *           MechanismArrayAttribute
   * @param type
   *          The attribute type.
   * @return The class of the attribute type, or null if there is no such type.
   */
  protected static Class<?> getAttributeClass(long type) {
    return attributeClasses.get(type);
  }

  public Attribute stateKnown(boolean stateKnown) {
    this.stateKnown = stateKnown;
    return this;
  }

  /**
   * Set, if this attribute is really present in the associated object.
   * Does only make sense if used in combination with template objects.
   *
   * @param present
   *          True, if attribute is present.
   */
  public Attribute present(boolean present) {
    this.present = present;
    return this;
  }

  /**
   * Set, if this attribute is sensitive in the associated object.
   * Does only make sense if used in combination with template objects.
   *
   * @param sensitive
   *          True, if attribute is sensitive.
   */
  public Attribute sensitive(boolean sensitive) {
    this.sensitive = sensitive;
    return this;
  }

  /**
   * Set the CK_ATTRIBUTE of this Attribute. Only for internal use.
   *
   * @param ckAttribute
   *          The new CK_ATTRIBUTE of this Attribute.
   */
  public Attribute ckAttribute(CK_ATTRIBUTE ckAttribute) {
    this.ckAttribute = Functions.requireNonNull("ckAttribute", ckAttribute);
    return this;
  }

  /**
   * Check, if this attribute is really present in the associated object.
   *
   * @return True, if this attribute is really present in the associated
   *         object.
   */
  public boolean isPresent() {
    return present;
  }

  /**
   * Check, if this attribute is sensitive in the associated object.
   *
   * @return True, if this attribute is sensitive in the associated object.
   */
  public boolean isSensitive() {
    return sensitive;
  }

  public boolean isStateKnown() {
    return stateKnown;
  }

  /**
   * Get the CK_ATTRIBUTE object of this Attribute that contains the attribute
   * type and value .
   *
   * @return The CK_ATTRIBUTE of this Attribute.
   */
  public CK_ATTRIBUTE getCkAttribute() {
    return ckAttribute;
  }

  public long type() {
    return ckAttribute.type;
  }

  /**
   * Get a string representation of the value of this attribute.
   *
   * @return A string representation of the value of this attribute.
   */
  protected String getValueString() {
    return (ckAttribute == null || ckAttribute.pValue == null) ? "<NULL_PTR>"
        : (ckAttribute.type == CKA_CLASS)            ? codeToName(Category.CKO, (long) ckAttribute.pValue)
        : (ckAttribute.type == CKA_KEY_TYPE)         ? codeToName(Category.CKK, (long) ckAttribute.pValue)
        : (ckAttribute.type == CKA_CERTIFICATE_TYPE) ? codeToName(Category.CKC, (long) ckAttribute.pValue)
        : (ckAttribute.type == CKA_HW_FEATURE_TYPE)  ? codeToName(Category.CKH, (long) ckAttribute.pValue)
        : ckAttribute.pValue.toString();
  }

  /**
   * Get a string representation of this attribute. If the attribute is not
   * present or if it is sensitive, the output of this method shows just a
   * message telling this. This string does not contain the attribute's type
   * name.
   *
   * @return A string representation of the value of this attribute.
   */
  public String toString() {
    return toString(true, "");
  }

  /**
   * Get a string representation of this attribute. If the attribute is not
   * present or if it is sensitive, the output of this method shows just
   * a message telling this.
   *
   * @param withName
   *          If true, the string contains the attribute type name and the
   *          value. If false, it just contains the value.
   * @return A string representation of this attribute.
   */
  public String toString(boolean withName, String indent) {
    StringBuilder sb = new StringBuilder(32).append(indent);

    if (withName) sb.append(codeToName(Category.CKA, ckAttribute.type)).append(": ");

    String valueString = (!stateKnown) ? "<Value is not present or sensitive>"
        : present ? (sensitive ? "<Value is sensitive>" : getValueString()) : "<Attribute not present>";
    return sb.append(valueString).toString();
  }

  /**
   * Get the PKCS#11 type of this attribute.
   *
   * @return The PKCS#11 type of this attribute.
   */
  public long getType() {
    return ckAttribute.type;
  }

}