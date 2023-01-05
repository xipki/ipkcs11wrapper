package iaik.pkcs.pkcs11.objects;

import iaik.pkcs.pkcs11.wrapper.CK_ATTRIBUTE;

import java.math.BigInteger;
import java.util.*;

import static iaik.pkcs.pkcs11.wrapper.PKCS11Constants.*;

public class AttributeVector {

  private final List<Attribute> attributes;

  public AttributeVector() {
    this.attributes = new LinkedList<>();
  }

  public AttributeVector(Attribute... attributes) {
    if (attributes == null || attributes.length == 0) {
      this.attributes = new LinkedList<>();
    } else {
      this.attributes = new ArrayList<>(attributes.length);
      for (Attribute attr : attributes) {
        if (attr != null) {
          attr(attr);
        }
      }
    }
  }

  public AttributeVector acIssuer(char[] acIssuer) {
    return attr(CKA_AC_ISSUER, acIssuer);
  }

  public AttributeVector alwaysSensitive(char[] alwaysSensitive) {
    return attr(CKA_ALWAYS_SENSITIVE, alwaysSensitive);
  }

  public AttributeVector alwaysAuthenticate(char[] alwaysAuthenticate) {
    return attr(CKA_ALWAYS_AUTHENTICATE, alwaysAuthenticate);
  }

  public AttributeVector application(char[] application) {
    return attr(CKA_APPLICATION, application);
  }

  public AttributeVector application(String application) {
    return attr(CKA_APPLICATION, application);
  }

  public AttributeVector attrTypes(byte[] attrTypes) {
    return attr(CKA_ATTR_TYPES, attrTypes);
  }

  public AttributeVector base(BigInteger base) {
    return attr(CKA_BASE, base);
  }

  public AttributeVector certificateCategory(long certificateCategory) {
    return attr(CKA_CERTIFICATE_CATEGORY, certificateCategory);
  }

  public AttributeVector certificateType(long certificateType) {
    return attr(CKA_CERTIFICATE_TYPE, certificateType);
  }

  public AttributeVector checkValue(byte[] checkValue) {
    return attr(CKA_CHECK_VALUE, checkValue);
  }

  public AttributeVector class_(long class_) {
    return attr(CKA_CLASS, class_);
  }

  public AttributeVector coefficient(BigInteger coefficient) {
    return attr(CKA_COEFFICIENT, coefficient);
  }

  public AttributeVector copyable(boolean copyable) {
    return attr(CKA_COPYABLE, copyable);
  }

  public AttributeVector decrypt(boolean decrypt) {
    return attr(CKA_DECRYPT, decrypt);
  }

  public AttributeVector defaultCmsAttributes(boolean defaultCmsAttributes) {
    return attr(CKA_DEFAULT_CMS_ATTRIBUTES, defaultCmsAttributes);
  }

  public AttributeVector derive(boolean derive) {
    return attr(CKA_DERIVE, derive);
  }

  public AttributeVector deriveTemplate(AttributeVector deriveTemplate) {
    return attr(CKA_DERIVE_TEMPLATE, deriveTemplate);
  }

  public AttributeVector destroyable(boolean destroyable) {
    return attr(CKA_DESTROYABLE, destroyable);
  }

  public AttributeVector ecParams(byte[] ecParams) {
    return attr(CKA_EC_PARAMS, ecParams);
  }

  public AttributeVector ecPoint(byte[] ecParams) {
    return attr(CKA_EC_PARAMS, ecParams);
  }

  public AttributeVector endDate(Date endDate) {
    return attr(CKA_END_DATE, endDate);
  }

  public AttributeVector encrypt(boolean encrypt) {
    return attr(CKA_ENCRYPT, encrypt);
  }

  public AttributeVector exponent1(BigInteger exponent1) {
    return attr(CKA_EXPONENT_1, exponent1);
  }

  public AttributeVector exponent2(BigInteger exponent2) {
    return attr(CKA_EXPONENT_2, exponent2);
  }

  public AttributeVector extractable(boolean extractable) {
    return attr(CKA_EXTRACTABLE, extractable);
  }

  public AttributeVector gost28417Params(byte[] gost28417Params) {
    return attr(CKA_GOST28147_PARAMS, gost28417Params);
  }

  public AttributeVector gostr3410Params(byte[] gostr3410Params) {
    return attr(CKA_GOSTR3410_PARAMS, gostr3410Params);
  }

  public AttributeVector gostr3411Params(byte[] gostr3411Params) {
    return attr(CKA_GOSTR3411_PARAMS, gostr3411Params);
  }

  public AttributeVector hwFeatureType(long hwFeatureType) {
    return attr(CKA_HW_FEATURE_TYPE, hwFeatureType);
  }

  public AttributeVector hashOfIssuerPublicKey(byte[] hashOfIssuerPublicKey) {
    return attr(CKA_HASH_OF_ISSUER_PUBLIC_KEY, hashOfIssuerPublicKey);
  }

  public AttributeVector hashOfSubjectPublicKey(byte[] hashOfSubjectPublicKey) {
    return attr(CKA_HASH_OF_SUBJECT_PUBLIC_KEY, hashOfSubjectPublicKey);
  }

  public AttributeVector id(byte[] id) {
    return attr(CKA_ID, id);
  }

  public AttributeVector issuer(byte[] issuer) {
    return attr(CKA_ISSUER, issuer);
  }

  public AttributeVector keyType(long keyType) {
    return attr(CKA_KEY_TYPE, keyType);
  }

  public AttributeVector label(char[] label) {
    return attr(CKA_LABEL, label);
  }

  public AttributeVector label(String label) {
    return attr(CKA_LABEL, label);
  }

  public AttributeVector local(boolean local) {
    return attr(CKA_LOCAL, local);
  }

  public AttributeVector mechanismType(long mechanismType) {
    return attr(CKA_MECHANISM_TYPE, mechanismType);
  }

  public AttributeVector modifiable(boolean modifiable) {
    return attr(CKA_MODIFIABLE, modifiable);
  }

  public AttributeVector modulusBits(int modulusBits) {
    return attr(CKA_MODULUS_BITS, modulusBits);
  }

  public AttributeVector modulus(BigInteger modulus) {
    return attr(CKA_MODULUS, modulus);
  }

  public AttributeVector nameHashAlgorithm(long nameHashAlgorithm) {
    return attr(CKA_NAME_HASH_ALGORITHM, nameHashAlgorithm);
  }

  public AttributeVector neverExtractable(boolean neverExtractable) {
    return attr(CKA_NEVER_EXTRACTABLE, neverExtractable);
  }

  public AttributeVector objectId(byte[] objectId) {
    return attr(CKA_OBJECT_ID, objectId);
  }

  public AttributeVector owner(byte[] owner) {
    return attr(CKA_OWNER, owner);
  }

  public AttributeVector private_(boolean private_) {
    return attr(CKA_PRIVATE, private_);
  }

  public AttributeVector prime(BigInteger prime) {
    return attr(CKA_PRIME, prime);
  }

  public AttributeVector prime1(BigInteger prime1) {
    return attr(CKA_PRIME_1, prime1);
  }

  public AttributeVector prime2(BigInteger prime2) {
    return attr(CKA_PRIME_2, prime2);
  }

  public AttributeVector primeBits(int primeBits) {
    return attr(CKA_PRIME_BITS, primeBits);
  }

  public AttributeVector privateExponent(BigInteger privateExponent) {
    return attr(CKA_PRIVATE_EXPONENT, privateExponent);
  }

  public AttributeVector profileId(long profileId) {
    return attr(CKA_PROFILE_ID, profileId);
  }

  public AttributeVector publicExponent(BigInteger publicExponent) {
    return attr(CKA_PUBLIC_EXPONENT, publicExponent);
  }

  public AttributeVector publicKeyInfo(byte[] publicKeyInfo) {
    return attr(CKA_PUBLIC_KEY_INFO, publicKeyInfo);
  }

  public AttributeVector requiredCmsAttributes(boolean requiredCmsAttributes) {
    return attr(CKA_REQUIRED_CMS_ATTRIBUTES, requiredCmsAttributes);
  }

  public AttributeVector sensitive(boolean sensitive) {
    return attr(CKA_SENSITIVE, sensitive);
  }

  public AttributeVector serialNumber(byte[] serialNumber) {
    return attr(CKA_SERIAL_NUMBER, serialNumber);
  }

  public AttributeVector sign(boolean sign) {
    return attr(CKA_SIGN, sign);
  }

  public AttributeVector signRecover(boolean signRecover) {
    return attr(CKA_SIGN_RECOVER, signRecover);
  }

  public AttributeVector startDate(Date startDate) {
    return attr(CKA_START_DATE, startDate);
  }

  public AttributeVector subject(byte[] subject) {
    return attr(CKA_SUBJECT, subject);
  }

  public AttributeVector subprime(BigInteger subprime) {
    return attr(CKA_SUBPRIME, subprime);
  }

  public AttributeVector subprimeBits(int subprimeBits) {
    return attr(CKA_SUBPRIME_BITS, subprimeBits);
  }

  public AttributeVector supportedCmsAttributes(boolean supportedCmsAttributes) {
    return attr(CKA_SUPPORTED_CMS_ATTRIBUTES, supportedCmsAttributes);
  }

  public AttributeVector token(boolean token) {
    return attr(CKA_TOKEN, token);
  }

  public AttributeVector trusted(boolean trusted) {
    return attr(CKA_TRUSTED, trusted);
  }

  public AttributeVector uniqueId(char[] uniqueId) {
    return attr(CKA_UNIQUE_ID, uniqueId);
  }

  public AttributeVector unwrap(boolean unwrap) {
    return attr(CKA_UNWRAP, unwrap);
  }

  public AttributeVector unwrapTemplate(AttributeVector unwrapTemplate) {
    return attr(CKA_UNWRAP_TEMPLATE, unwrapTemplate);
  }

  public AttributeVector value(byte[] value) {
    return attr(CKA_VALUE, value);
  }

  public AttributeVector valueBits(int valueBits) {
    return attr(CKA_VALUE_BITS, valueBits);
  }

  public AttributeVector valueLen(int valueLen) {
    return attr(CKA_VALUE_LEN, valueLen);
  }

  public AttributeVector verify(boolean verify) {
    return attr(CKA_SIGN, verify);
  }

  public AttributeVector verifyRecover(boolean verifyRecover) {
    return attr(CKA_VERIFY_RECOVER, verifyRecover);
  }

  public AttributeVector wrap(boolean wrap) {
    return attr(CKA_WRAP, wrap);
  }

  public AttributeVector wrapTemplate(AttributeVector wrapTemplate) {
    return attr(CKA_WRAP_TEMPLATE, wrapTemplate);
  }

  public AttributeVector wrapWithTrusted(boolean wrapWithTrusted) {
    return attr(CKA_WRAP_WITH_TRUSTED, wrapWithTrusted);
  }

  public AttributeVector attr(long attrType, Object attrValue) {
    return attr(Attribute.getInstance(attrType, attrValue));
  }

  public AttributeVector attr(Attribute attr) {
    if (!attributes.isEmpty()) {
      long type = attr.getType();
      int oldAttrIdx = -1;
      for (int i = 0; i < attributes.size(); i++) {
        if (attributes.get(i).getType() == type) {
          oldAttrIdx = i;
          break;
        }
      }

      if (oldAttrIdx != -1) {
        attributes.remove(oldAttrIdx);
      }
    }

    attributes.add(attr);
    return this;
  }

  public List<Attribute> snapshot() {
    return Collections.unmodifiableList(attributes);
  }

  public CK_ATTRIBUTE[] toCkAttributes() {
    List<CK_ATTRIBUTE> attributeList = new ArrayList<>();
    for (Attribute attribute : attributes) {
      if (attribute.present) {
        attributeList.add(attribute.getCkAttribute());
      }
    }
    return attributeList.toArray(new CK_ATTRIBUTE[0]);
  }

  public Attribute getAttribute(long type) {
    for (Attribute attr : attributes) {
      if (attr.getType() == type) {
        return attr;
      }
    }
    return null;
  }

  public Boolean getAttributeBooleanValue(long type) {
    Attribute attr = getAttribute(type);
    return attr == null ? null : ((BooleanAttribute) attr).getBooleanValue();
  }

  public Long getAttributeLongValue(long type) {
    Attribute attr = getAttribute(type);
    return attr == null ? null : ((LongAttribute) attr).getLongValue();
  }

  public Integer getAttributeIntValue(long type) {
    Long value = getAttributeLongValue(type);
    return value == null ? null : value.intValue();
  }

  public char[] getAttributeCharArrayValue(long type) {
    Attribute attr = getAttribute(type);
    return attr == null ? null : ((CharArrayAttribute) attr).getCharArrayValue();
  }

  public String getAttributeStringValue(long type) {
    Attribute attr = getAttribute(type);
    return attr == null ? null : ((CharArrayAttribute) attr).getStringValue();
  }

  public byte[] getAttributeByteArrayValue(long type) {
    Attribute attr = getAttribute(type);
    return attr == null ? null : ((ByteArrayAttribute) attr).getByteArrayValue();
  }

  @Override
  public String toString() {
    return toString("");
  }

  public String toString(String indent) {
    StringBuilder sb = new StringBuilder(32);
    sb.append(indent).append("Attribute Vector:");

    String indent2 = indent + "  ";
    for (Attribute attribute : attributes) {
      if (sb.length() > 0) {
        sb.append("\n");
      }
      sb.append(attribute.toString(true, indent2));
    }

    return sb.toString();
  }

}
