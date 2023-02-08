// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.
//
// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.attrs;

import iaik.pkcs.pkcs11.wrapper.CK_ATTRIBUTE;
import org.xipki.pkcs11.wrapper.AttributeVector;
import org.xipki.pkcs11.wrapper.Functions;
import org.xipki.pkcs11.wrapper.PKCS11Constants;

import java.math.BigInteger;
import java.util.*;

/**
 * This is the base-class for all types of attributes. In general, all PKCS#11
 * objects are just a collection of attributes. PKCS#11 specifies which
 * attributes each type of objects must have.
 * <p>
 * In some cases, attributes are optional. In such a case, this attribute will
 * return false when the application calls present() on this attribute. This
 * means, that the object does not possess this attribute (maybe even though
 * it should, but not all drivers seem to implement the standard correctly).
 * Handling attributes in this fashion ensures that this library can work also
 * with drivers that are not fully standard-compliant.
 * <p>
 * Moreover, certain attributes can be sensitive; i.e. their values cannot
 * be read, e.g. the private exponent of an RSA private key.
 *
 * @author Karl Scheibelhofer (SIC)
 * @author Lijun Liao (xipki)
 */
public abstract class Attribute {

  private enum AttrType {
    ATTRIBUTEARRAY,
    BOOLEAN,
    BYTEARRAY,
    CHARARRAY,
    DATE,
    LONG,
    MECHANISM,
    MECHANISMARRAY
  }

  private static final Map<Long, AttrType> attributeTypes;

  /**
   * True, if the object really possesses this attribute.
   */
  protected boolean present;

  /**
   * True, if this attribute is sensitive.
   */
  protected boolean sensitive;

  /**
   * The CK_ATTRIBUTE that is used to hold the PKCS#11 type of this attribute
   * and the value.
   */
  protected CK_ATTRIBUTE ckAttribute;

  static {
    attributeTypes = new HashMap<>(130);
    String propFile = "org/xipki/pkcs11/wrapper/type-CKA.properties";
    Properties props = new Properties();
    try {
      props.load(Functions.class.getClassLoader().getResourceAsStream(propFile));
      for (String name : props.stringPropertyNames()) {
        name = name.trim();
        String type = props.getProperty(name).trim();
        Long code = PKCS11Constants.ckaNameToCode(name);
        if (code == null) {
          throw new IllegalStateException("unknown CKA: " + name);
        }

        if (attributeTypes.containsKey(code)) {
          throw new IllegalStateException("duplicated definition of CKA: " + name);
        }

        AttrType attrType = AttrType.valueOf(type.toUpperCase(Locale.ROOT));

        attributeTypes.put(code, attrType);
      }
    } catch (Throwable t) {
      throw new IllegalStateException("error reading properties file " + propFile + ": " + t.getMessage());
    }

    if (attributeTypes.isEmpty()) {
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
    ckAttribute = new CK_ATTRIBUTE();
    ckAttribute.type = type;
  }

  public static Attribute getInstance(long type) {
    Attribute attr = getInstance0(type);
    if (attr == null) {
      throw new IllegalArgumentException("Unknown attribute type " + PKCS11Constants.ckaCodeToName(type));
    }

    return attr;
  }

  static Attribute getInstance0(long type) {
    AttrType attrType = attributeTypes.get(type);
    return (attrType == AttrType.BOOLEAN)  ? new BooleanAttribute(type)
        : (attrType == AttrType.BYTEARRAY) ? new ByteArrayAttribute(type)
        : (attrType == AttrType.CHARARRAY) ? new CharArrayAttribute(type)
        : (attrType == AttrType.DATE)      ? new DateAttribute(type)
        : (attrType == AttrType.LONG)      ? new LongAttribute(type)
        : (attrType == AttrType.MECHANISM) ? new MechanismAttribute(type)
        : (attrType == AttrType.MECHANISMARRAY) ? new MechanismArrayAttribute(type)
        : (attrType == AttrType.ATTRIBUTEARRAY) ? new AttributeArrayAttribute(type)
        : null;
  }

  public static Attribute getInstance(long type, Object value) {
    AttrType attrType = attributeTypes.get(type);

    if (attrType == AttrType.BOOLEAN) {
      return new BooleanAttribute(type).booleanValue((Boolean) value);
    } else if (attrType == AttrType.BYTEARRAY) {
      return (value == null || value instanceof byte[])
          ? new ByteArrayAttribute(type).byteArrayValue((byte[]) value)
          : new ByteArrayAttribute(type).bigIntValue((BigInteger) value);
    } else if (attrType == AttrType.CHARARRAY) {
      return (value == null || value instanceof char[])
          ? new CharArrayAttribute(type).charArrayValue((char[]) value)
          : new CharArrayAttribute(type).stringValue((String) value);
    } else if (attrType == AttrType.DATE) {
      return new DateAttribute(type).dateValue((Date) value);
    } else if (attrType == AttrType.LONG || attrType == AttrType.MECHANISM) {
      LongAttribute attr = (attrType == AttrType.LONG) ? new LongAttribute(type) : new MechanismAttribute(type);
      return (value == null || value instanceof Long)
          ? attr.longValue((Long) value) : attr.longValue((long) (int) value);
    } else if (attrType == AttrType.MECHANISMARRAY) {
      return new MechanismArrayAttribute(type).mechanismAttributeArrayValue((long[]) value);
    } else if (attrType == AttrType.ATTRIBUTEARRAY) {
      return new AttributeArrayAttribute(type).attributeArrayValue((AttributeVector) value);
    } else {
      throw new IllegalStateException("unknown attribute type " + PKCS11Constants.ckaCodeToName(type));
    }
  }

  /**
   * Set, if this attribute is really present in the associated object.
   * Does only make sense if used in combination with template objects.
   *
   * @param present
   *          True, if attribute is present.
   * @return a reference to this object.
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
   * @return a reference to this object.
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
   * @return a reference to this object.
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
    if (ckAttribute == null || ckAttribute.pValue == null) {
      return "<NULL_PTR>";
    }

    long type = ckAttribute.type;
    Object value = ckAttribute.pValue;

    return    (type == PKCS11Constants.CKA_CLASS)            ? PKCS11Constants.ckoCodeToName((long) value)
            : (type == PKCS11Constants.CKA_KEY_TYPE)         ? PKCS11Constants.ckkCodeToName((long) value)
            : (type == PKCS11Constants.CKA_CERTIFICATE_TYPE)
                  ? PKCS11Constants.codeToName(PKCS11Constants.Category.CKC, (long) value)
            : (type == PKCS11Constants.CKA_HW_FEATURE_TYPE)
                  ? PKCS11Constants.codeToName(PKCS11Constants.Category.CKH, (long) value)
            : value.toString();
  }

  /**
   * Get a string representation of this attribute. If the attribute is not
   * present or if it is sensitive, the output of this method shows just a
   * message telling this. This string does not contain the attribute's type
   * name.
   *
   * @return A string representation of the value of this attribute.
   */
  @Override
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
   * @param indent The indent.
   * @return A string representation of this attribute.
   */
  public String toString(boolean withName, String indent) {
    StringBuilder sb = new StringBuilder(32).append(indent);

    if (withName) {
      sb.append(PKCS11Constants.ckaCodeToName(ckAttribute.type)).append(": ");
    }

    String valueString = present ? (sensitive ? "<Value is sensitive>" : getValueString()) : "<Attribute not present>";
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

  protected boolean isNullValue() {
    return ckAttribute == null || ckAttribute.pValue == null;
  }

}
