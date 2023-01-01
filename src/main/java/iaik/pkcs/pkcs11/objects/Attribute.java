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

import iaik.pkcs.pkcs11.Util;
import iaik.pkcs.pkcs11.wrapper.Functions;
import sun.security.pkcs11.wrapper.CK_ATTRIBUTE;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Date;
import java.util.Hashtable;
import java.util.Objects;

import static iaik.pkcs.pkcs11.wrapper.PKCS11Constants.*;

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
 * @version 1.0
 */
public abstract class Attribute {

  protected static Hashtable<Long, Class<?>> attributeClasses;

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

  public static Attribute getInstance(long type, Object value) {
    Class<?> clazz = getAttributeClass(type);
    if (clazz == null) {
      throw new IllegalArgumentException(Functions.ckaCodeToName(type));
    }

    if (clazz == BooleanAttribute.class) {
      BooleanAttribute attr = new BooleanAttribute(type);
      attr.setBooleanValue((Boolean) value);
      return attr;
    } else if (clazz == ByteArrayAttribute.class) {
      ByteArrayAttribute attr = new ByteArrayAttribute(type);
      byte[] baValue;
      if (value instanceof BigInteger) {
        baValue = ((BigInteger) value).toByteArray();
        if (baValue[0] == 0) {
          baValue = Arrays.copyOfRange(baValue, 1, baValue.length);
        }
      } else {
        baValue = (byte[]) value;
      }
      attr.setByteArrayValue(baValue);
      return attr;
    } else if (clazz == CharArrayAttribute.class) {
      CharArrayAttribute attr = new CharArrayAttribute(type);
      if (value instanceof String) {
        attr.setCharArrayValue(((String) value).toCharArray());
      } else {
        attr.setCharArrayValue((char[]) value);
      }
      return attr;
    } else if (clazz == DateAttribute.class) {
      DateAttribute attr = new DateAttribute(type);
      attr.setDateValue((Date) value);
      return attr;
    } else if (clazz == LongAttribute.class) {
      LongAttribute attr = new LongAttribute(type);
      setLongAttrValue(attr, value);
      return attr;
    } else if (clazz == MechanismAttribute.class) {
      MechanismAttribute attr = new MechanismAttribute(type);
      setLongAttrValue(attr, value);
      return attr;
    } else {
      throw new IllegalStateException("unknown class " + clazz); // should not reach here
    }
  }

  private static void setLongAttrValue(LongAttribute attr, Object value) {
    if (value instanceof Integer) {
      attr.setLongValue((long) (int) value);
    } else {
      attr.setLongValue((Long) value);
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
  protected static synchronized Class<?> getAttributeClass(long type) {
    if (attributeClasses == null) {
      attributeClasses = new Hashtable<>(85);

      long[] codes = new long[] {CKA_TOKEN, CKA_PRIVATE, CKA_TRUSTED, CKA_SENSITIVE, CKA_ENCRYPT,
          CKA_DECRYPT, CKA_WRAP, CKA_UNWRAP, CKA_SIGN, CKA_SIGN_RECOVER, CKA_VERIFY,
          CKA_VERIFY_RECOVER, CKA_DERIVE, CKA_EXTRACTABLE, CKA_LOCAL, CKA_NEVER_EXTRACTABLE,
          CKA_WRAP_WITH_TRUSTED, CKA_ALWAYS_SENSITIVE, CKA_ALWAYS_AUTHENTICATE, CKA_MODIFIABLE,
          CKA_RESET_ON_INIT, CKA_HAS_RESET, CKA_COPYABLE, CKA_DESTROYABLE, CKA_COLOR,
          CKA_OTP_USER_FRIENDLY_MODE};
      for (long code : codes) {
        attributeClasses.put(code, BooleanAttribute.class);
      }

      codes = new long[] {
          CKA_CLASS, CKA_CERTIFICATE_CATEGORY, CKA_CERTIFICATE_TYPE, CKA_JAVA_MIDP_SECURITY_DOMAIN, CKA_KEY_TYPE,
          CKA_PRIME_BITS, CKA_SUBPRIME_BITS, CKA_VALUE_BITS, CKA_VALUE_LEN, CKA_HW_FEATURE_TYPE, CKA_MODULUS_BITS,
          CKA_NAME_HASH_ALGORITHM, CKA_PROFILE_ID,
          CKA_PIXEL_X, CKA_PIXEL_Y, CKA_RESOLUTION, CKA_CHAR_ROWS, CKA_CHAR_COLUMNS, CKA_BITS_PER_PIXEL,
          CKA_MECHANISM_TYPE, CKA_OTP_FORMAT, CKA_OTP_LENGTH, CKA_OTP_CHALLENGE_REQUIREMENT,
          CKA_OTP_TIME_INTERVAL, CKA_OTP_TIME_REQUIREMENT, CKA_OTP_COUNTER_REQUIREMENT, CKA_OTP_PIN_REQUIREMENT
      };
      for (long code : codes) {
        attributeClasses.put(code, LongAttribute.class);
      }

      codes = new long[] {CKA_VALUE, CKA_OBJECT_ID, CKA_ISSUER, CKA_SERIAL_NUMBER,
          CKA_HASH_OF_ISSUER_PUBLIC_KEY, CKA_HASH_OF_SUBJECT_PUBLIC_KEY, CKA_AC_ISSUER,
          CKA_OWNER, CKA_ATTR_TYPES, CKA_SUBJECT, CKA_ID, CKA_CHECK_VALUE, CKA_MODULUS,
          CKA_PUBLIC_EXPONENT, CKA_PRIVATE_EXPONENT, CKA_PRIME_1, CKA_PRIME_2,
          CKA_EXPONENT_1, CKA_EXPONENT_2, CKA_COEFFICIENT, CKA_PRIME, CKA_SUBPRIME,
          CKA_BASE, CKA_EC_PARAMS, CKA_EC_POINT, CKA_PUBLIC_KEY_INFO,
          CKA_OTP_COUNTER, CKA_OTP_SERVICE_LOGO,
          CKA_REQUIRED_CMS_ATTRIBUTES, CKA_DEFAULT_CMS_ATTRIBUTES, CKA_SUPPORTED_CMS_ATTRIBUTES,
          CKA_GOSTR3410_PARAMS, CKA_GOSTR3411_PARAMS, CKA_GOST28147_PARAMS};
      for (long code : codes) {
        attributeClasses.put(code, ByteArrayAttribute.class);
      }

      codes = new long[] {CKA_URL, CKA_LABEL, CKA_APPLICATION, CKA_UNIQUE_ID,
          CKA_CHAR_SETS, CKA_ENCODING_METHODS, CKA_MIME_TYPES, CKA_OTP_TIME, CKA_OTP_USER_IDENTIFIER,
          CKA_OTP_SERVICE_IDENTIFIER, CKA_OTP_SERVICE_LOGO_TYPE
      };
      for (long code : codes) {
        attributeClasses.put(code, CharArrayAttribute.class);
      }

      attributeClasses.put(CKA_DERIVE_TEMPLATE, AttributeArray.class); //CK_ATTRIBUTE_PTR
      attributeClasses.put(CKA_WRAP_TEMPLATE, AttributeArray.class); //CK_ATTRIBUTE_PTR
      attributeClasses.put(CKA_UNWRAP_TEMPLATE, AttributeArray.class); //CK_ATTRIBUTE_PTR
      attributeClasses.put(CKA_START_DATE, DateAttribute.class); //CK_DATE
      attributeClasses.put(CKA_END_DATE, DateAttribute.class); //CK_DATE
      attributeClasses.put(CKA_KEY_GEN_MECHANISM, MechanismAttribute.class); //CK_MECHANISM_TYPE
      attributeClasses.put(CKA_ALLOWED_MECHANISMS, MechanismArrayAttribute.class); //CK_MECHANISM_TYPE_PTR
    }

    return attributeClasses.get(type);
  }

  public void setStateKnown(boolean stateKnown) {
    this.stateKnown = stateKnown;
  }

  /**
   * Set, if this attribute is really present in the associated object.
   * Does only make sense if used in combination with template objects.
   *
   * @param present
   *          True, if attribute is present.
   */
  public void setPresent(boolean present) {
    this.present = present;
  }

  /**
   * Set, if this attribute is sensitive in the associated object.
   * Does only make sense if used in combination with template objects.
   *
   * @param sensitive
   *          True, if attribute is sensitive.
   */
  public void setSensitive(boolean sensitive) {
    this.sensitive = sensitive;
  }

  /**
   * Redirects the request for setting the attribute value to the implementing
   * attribute class.
   *
   * @param value
   *          the new value
   * @throws ClassCastException
   *           the given value type is not valid for this very
   *           {@link Attribute}.
   * @throws UnsupportedOperationException
   *           the {@link OtherAttribute} implementation does not support
   *           setting a value directly.
   */
  public abstract void setValue(Object value);

  /**
   * Set the CK_ATTRIBUTE of this Attribute. Only for internal use.
   *
   * @param ckAttribute
   *          The new CK_ATTRIBUTE of this Attribute.
   */
  public void setCkAttribute(CK_ATTRIBUTE ckAttribute) {
    this.ckAttribute = Util.requireNonNull("ckAttribute", ckAttribute);
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
    if (ckAttribute == null || ckAttribute.pValue == null) return "<NULL_PTR>";

    if (ckAttribute.type == CKA_CLASS) {
      return Functions.ckoCodeToName((long) ckAttribute.pValue);
    } else if (ckAttribute.type == CKA_KEY_TYPE) {
      return Functions.ckkCodeToName((long) ckAttribute.pValue);
    } else if (ckAttribute.type == CKA_CERTIFICATE_TYPE) {
      return Functions.ckcCodeToName((long) ckAttribute.pValue);
    } else if (ckAttribute.type == CKA_HW_FEATURE_TYPE) {
      return Functions.ckhCodeToName((long) ckAttribute.pValue);
    } else {
      return ckAttribute.pValue.toString();
    }
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
   * @return A string representation of this attribute.
   */
  public String toString(boolean withName, String indent) {
    StringBuilder sb = new StringBuilder(32).append(indent);

    if (withName) {
      sb.append(Functions.ckaCodeToName(ckAttribute.type)).append(": ");
    }

    if (!stateKnown) {
      sb.append("<Value is not present or sensitive>");
    } else if (present) {
      if (sensitive) {
        sb.append("<Value is sensitive>" );
      } else {
        sb.append(getValueString());
      }
    } else {
      sb.append("<Attribute not present>");
    }

    return sb.toString();
  }

  /**
   * Set the PKCS#11 type of this attribute.
   *
   * @param type
   *          The PKCS#11 type of this attribute.
   */
  protected void setType(long type) {
    ckAttribute.type = type;
  }

  /**
   * Get the PKCS#11 type of this attribute.
   *
   * @return The PKCS#11 type of this attribute.
   */
  public long getType() {
    return ckAttribute.type;
  }

  /**
   * True, if both attributes are not present or if both attributes are
   * present and all other member variables are equal. False, otherwise.
   *
   * @param otherObject
   *          The other object to compare to.
   * @return True, if both attributes are not present or if both attributes
   *         are present and all other member variables are equal. False,
   *         otherwise.
   */
  @Override
  public final boolean equals(Object otherObject) {
    if (this == otherObject)  return true;
    else if (!(otherObject instanceof Attribute)) return false;

    Attribute other = (Attribute) otherObject;
    if (this.getType() != other.getType()) {
      return false;
    }

    if (this.stateKnown && other.stateKnown) {
      // state both known
      if (!this.present && !other.present) {
        // both not present
        return true;
      } else if (this.present && other.present) {
        // both present
        return this.sensitive == other.sensitive &&
            Objects.deepEquals(this.ckAttribute.pValue, other.ckAttribute.pValue);
      } else {
        // one absent and other present
        return false;
      }
    } else if (!this.stateKnown && !other.stateKnown) {
      // state both known
      return true;
    } else {
      // one with known state and other with unknown state
      return false;
    }
  }

  /**
   * The overriding of this method should ensure that the objects of this
   * class work correctly in a hashtable.
   *
   * @return The hash code of this object.
   */
  @Override
  public final int hashCode() {
    int valueHashCode = (ckAttribute.pValue != null) ? ckAttribute.pValue.hashCode() : 0;
    return ((int) ckAttribute.type) ^ valueHashCode;
  }

}
