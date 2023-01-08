/*
 *
 * Copyright (c) 2022 - 2023 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.xipki.pkcs11;

import iaik.pkcs.pkcs11.wrapper.CK_ATTRIBUTE;
import org.xipki.pkcs11.objects.*;

import java.math.BigInteger;
import java.util.*;

import static org.xipki.pkcs11.PKCS11Constants.*;

/**
 * @author Lijun Liao (xipki)
 */
public class AttributesTemplate {

  private final List<Attribute> attributes = new LinkedList<>();

  public AttributesTemplate() {
  }

  public AttributesTemplate(Attribute... attributes) {
    if (attributes != null) {
      for (Attribute attr : attributes) {
        if (attr != null) attr(attr);
      }
    }
  }

  public static AttributesTemplate newSecretKey(long keyType) {
    return new AttributesTemplate().class_(CKO_SECRET_KEY).keyType(keyType);
  }

  public static AttributesTemplate newAESSecretKey() {
    return new AttributesTemplate().class_(CKO_SECRET_KEY).keyType(CKK_AES);
  }

  public static AttributesTemplate newPrivateKey(long keyType) {
    return new AttributesTemplate().class_(CKO_PRIVATE_KEY).keyType(keyType);
  }

  public static AttributesTemplate newRSAPrivateKey() {
    return new AttributesTemplate().class_(CKO_PRIVATE_KEY).keyType(CKK_RSA);
  }

  public static AttributesTemplate newECPrivateKey() {
    return new AttributesTemplate().class_(CKO_PRIVATE_KEY).keyType(CKK_EC);
  }

  public static AttributesTemplate newPublicKey(long keyType) {
    return new AttributesTemplate().class_(CKO_PUBLIC_KEY).keyType(keyType);
  }

  public static AttributesTemplate newRSAPublicKey() {
    return new AttributesTemplate().class_(CKO_PUBLIC_KEY).keyType(CKK_RSA);
  }

  public static AttributesTemplate newECPublicKey() {
    return new AttributesTemplate().class_(CKO_PUBLIC_KEY).keyType(CKK_EC);
  }

  public static AttributesTemplate newCertificate(long certificateType) {
    return new AttributesTemplate().class_(CKO_CERTIFICATE).certificateType(certificateType);
  }

  public static AttributesTemplate newX509Certificate() {
    return new AttributesTemplate().class_(CKO_CERTIFICATE).certificateType(CKC_X_509);
  }

  public AttributesTemplate acIssuer(String acIssuer) {
    return attr(CKA_AC_ISSUER, acIssuer);
  }

  public AttributesTemplate alwaysSensitive(Boolean alwaysSensitive) {
    return attr(CKA_ALWAYS_SENSITIVE, alwaysSensitive);
  }

  public AttributesTemplate alwaysAuthenticate(Boolean alwaysAuthenticate) {
    return attr(CKA_ALWAYS_AUTHENTICATE, alwaysAuthenticate);
  }

  public AttributesTemplate application(String application) {
    return attr(CKA_APPLICATION, application);
  }

  public AttributesTemplate attrTypes(byte[] attrTypes) {
    return attr(CKA_ATTR_TYPES, attrTypes);
  }

  public AttributesTemplate base(BigInteger base) {
    return attr(CKA_BASE, base);
  }

  public AttributesTemplate certificateCategory(Long certificateCategory) {
    return attr(CKA_CERTIFICATE_CATEGORY, certificateCategory);
  }

  public AttributesTemplate certificateType(Long certificateType) {
    return attr(CKA_CERTIFICATE_TYPE, certificateType);
  }

  public AttributesTemplate checkValue(byte[] checkValue) {
    return attr(CKA_CHECK_VALUE, checkValue);
  }

  public AttributesTemplate class_(Long class_) {
    return attr(CKA_CLASS, class_);
  }

  public AttributesTemplate coefficient(BigInteger coefficient) {
    return attr(CKA_COEFFICIENT, coefficient);
  }

  public AttributesTemplate copyable(Boolean copyable) {
    return attr(CKA_COPYABLE, copyable);
  }

  public AttributesTemplate decrypt(Boolean decrypt) {
    return attr(CKA_DECRYPT, decrypt);
  }

  public AttributesTemplate defaultCmsAttributes(Boolean defaultCmsAttributes) {
    return attr(CKA_DEFAULT_CMS_ATTRIBUTES, defaultCmsAttributes);
  }

  public AttributesTemplate derive(Boolean derive) {
    return attr(CKA_DERIVE, derive);
  }

  public AttributesTemplate deriveTemplate(AttributesTemplate deriveTemplate) {
    return attr(CKA_DERIVE_TEMPLATE, deriveTemplate);
  }

  public AttributesTemplate destroyable(Boolean destroyable) {
    return attr(CKA_DESTROYABLE, destroyable);
  }

  public AttributesTemplate ecParams(byte[] ecParams) {
    return attr(CKA_EC_PARAMS, ecParams);
  }

  public AttributesTemplate ecPoint(byte[] ecParams) {
    return attr(CKA_EC_POINT, ecParams);
  }

  public AttributesTemplate endDate(Date endDate) {
    return attr(CKA_END_DATE, endDate);
  }

  public AttributesTemplate encrypt(Boolean encrypt) {
    return attr(CKA_ENCRYPT, encrypt);
  }

  public AttributesTemplate exponent1(BigInteger exponent1) {
    return attr(CKA_EXPONENT_1, exponent1);
  }

  public AttributesTemplate exponent2(BigInteger exponent2) {
    return attr(CKA_EXPONENT_2, exponent2);
  }

  public AttributesTemplate extractable(Boolean extractable) {
    return attr(CKA_EXTRACTABLE, extractable);
  }

  public AttributesTemplate gost28417Params(byte[] gost28417Params) {
    return attr(CKA_GOST28147_PARAMS, gost28417Params);
  }

  public AttributesTemplate gostr3410Params(byte[] gostr3410Params) {
    return attr(CKA_GOSTR3410_PARAMS, gostr3410Params);
  }

  public AttributesTemplate gostr3411Params(byte[] gostr3411Params) {
    return attr(CKA_GOSTR3411_PARAMS, gostr3411Params);
  }

  public AttributesTemplate hwFeatureType(Long hwFeatureType) {
    return attr(CKA_HW_FEATURE_TYPE, hwFeatureType);
  }

  public AttributesTemplate hashOfIssuerPublicKey(byte[] hashOfIssuerPublicKey) {
    return attr(CKA_HASH_OF_ISSUER_PUBLIC_KEY, hashOfIssuerPublicKey);
  }

  public AttributesTemplate hashOfSubjectPublicKey(byte[] hashOfSubjectPublicKey) {
    return attr(CKA_HASH_OF_SUBJECT_PUBLIC_KEY, hashOfSubjectPublicKey);
  }

  public AttributesTemplate id(byte[] id) {
    return attr(CKA_ID, id);
  }

  public AttributesTemplate issuer(byte[] issuer) {
    return attr(CKA_ISSUER, issuer);
  }

  public AttributesTemplate keyType(Long keyType) {
    return attr(CKA_KEY_TYPE, keyType);
  }

  public AttributesTemplate label(String label) {
    return attr(CKA_LABEL, label);
  }

  public AttributesTemplate local(Boolean local) {
    return attr(CKA_LOCAL, local);
  }

  public AttributesTemplate mechanismType(Long mechanismType) {
    return attr(CKA_MECHANISM_TYPE, mechanismType);
  }

  public AttributesTemplate modifiable(Boolean modifiable) {
    return attr(CKA_MODIFIABLE, modifiable);
  }

  public AttributesTemplate modulusBits(Integer modulusBits) {
    return attr(CKA_MODULUS_BITS, modulusBits);
  }

  public AttributesTemplate modulus(BigInteger modulus) {
    return attr(CKA_MODULUS, modulus);
  }

  public AttributesTemplate nameHashAlgorithm(Long nameHashAlgorithm) {
    return attr(CKA_NAME_HASH_ALGORITHM, nameHashAlgorithm);
  }

  public AttributesTemplate neverExtractable(Boolean neverExtractable) {
    return attr(CKA_NEVER_EXTRACTABLE, neverExtractable);
  }

  public AttributesTemplate objectId(byte[] objectId) {
    return attr(CKA_OBJECT_ID, objectId);
  }

  public AttributesTemplate owner(byte[] owner) {
    return attr(CKA_OWNER, owner);
  }

  public AttributesTemplate private_(Boolean private_) {
    return attr(CKA_PRIVATE, private_);
  }

  public AttributesTemplate prime(BigInteger prime) {
    return attr(CKA_PRIME, prime);
  }

  public AttributesTemplate prime1(BigInteger prime1) {
    return attr(CKA_PRIME_1, prime1);
  }

  public AttributesTemplate prime2(BigInteger prime2) {
    return attr(CKA_PRIME_2, prime2);
  }

  public AttributesTemplate primeBits(Integer primeBits) {
    return attr(CKA_PRIME_BITS, primeBits);
  }

  public AttributesTemplate privateExponent(BigInteger privateExponent) {
    return attr(CKA_PRIVATE_EXPONENT, privateExponent);
  }

  public AttributesTemplate profileId(Long profileId) {
    return attr(CKA_PROFILE_ID, profileId);
  }

  public AttributesTemplate publicExponent(BigInteger publicExponent) {
    return attr(CKA_PUBLIC_EXPONENT, publicExponent);
  }

  public AttributesTemplate publicKeyInfo(byte[] publicKeyInfo) {
    return attr(CKA_PUBLIC_KEY_INFO, publicKeyInfo);
  }

  public AttributesTemplate requiredCmsAttributes(Boolean requiredCmsAttributes) {
    return attr(CKA_REQUIRED_CMS_ATTRIBUTES, requiredCmsAttributes);
  }

  public AttributesTemplate sensitive(Boolean sensitive) {
    return attr(CKA_SENSITIVE, sensitive);
  }

  public AttributesTemplate serialNumber(byte[] serialNumber) {
    return attr(CKA_SERIAL_NUMBER, serialNumber);
  }

  public AttributesTemplate sign(Boolean sign) {
    return attr(CKA_SIGN, sign);
  }

  public AttributesTemplate signRecover(Boolean signRecover) {
    return attr(CKA_SIGN_RECOVER, signRecover);
  }

  public AttributesTemplate startDate(Date startDate) {
    return attr(CKA_START_DATE, startDate);
  }

  public AttributesTemplate subject(byte[] subject) {
    return attr(CKA_SUBJECT, subject);
  }

  public AttributesTemplate subprime(BigInteger subprime) {
    return attr(CKA_SUBPRIME, subprime);
  }

  public AttributesTemplate subprimeBits(Integer subprimeBits) {
    return attr(CKA_SUBPRIME_BITS, subprimeBits);
  }

  public AttributesTemplate supportedCmsAttributes(Boolean supportedCmsAttributes) {
    return attr(CKA_SUPPORTED_CMS_ATTRIBUTES, supportedCmsAttributes);
  }

  public AttributesTemplate token(Boolean token) {
    return attr(CKA_TOKEN, token);
  }

  public AttributesTemplate trusted(Boolean trusted) {
    return attr(CKA_TRUSTED, trusted);
  }

  public AttributesTemplate uniqueId(String uniqueId) {
    return attr(CKA_UNIQUE_ID, uniqueId);
  }

  public AttributesTemplate unwrap(Boolean unwrap) {
    return attr(CKA_UNWRAP, unwrap);
  }

  public AttributesTemplate unwrapTemplate(AttributesTemplate unwrapTemplate) {
    return attr(CKA_UNWRAP_TEMPLATE, unwrapTemplate);
  }

  public AttributesTemplate value(byte[] value) {
    return attr(CKA_VALUE, value);
  }

  public AttributesTemplate valueBits(Integer valueBits) {
    return attr(CKA_VALUE_BITS, valueBits);
  }

  public AttributesTemplate valueLen(Integer valueLen) {
    return attr(CKA_VALUE_LEN, valueLen);
  }

  public AttributesTemplate verify(Boolean verify) {
    return attr(CKA_VERIFY, verify);
  }

  public AttributesTemplate verifyRecover(Boolean verifyRecover) {
    return attr(CKA_VERIFY_RECOVER, verifyRecover);
  }

  public AttributesTemplate wrap(Boolean wrap) {
    return attr(CKA_WRAP, wrap);
  }

  public AttributesTemplate wrapTemplate(AttributesTemplate wrapTemplate) {
    return attr(CKA_WRAP_TEMPLATE, wrapTemplate);
  }

  public AttributesTemplate wrapWithTrusted(Boolean wrapWithTrusted) {
    return attr(CKA_WRAP_WITH_TRUSTED, wrapWithTrusted);
  }

  public AttributesTemplate attr(long attrType, Object attrValue) {
    return attr(Attribute.getInstance(attrType, attrValue));
  }

  public AttributesTemplate attr(Attribute attr) {
    if (!attributes.isEmpty()) {
      long type = attr.getType();
      int oldAttrIdx = -1;
      for (int i = 0; i < attributes.size(); i++) {
        if (attributes.get(i).getType() == type) {
          oldAttrIdx = i;
          break;
        }
      }

      if (oldAttrIdx != -1) attributes.remove(oldAttrIdx);
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
      if (attribute.isPresent()) attributeList.add(attribute.getCkAttribute());
    }
    return attributeList.toArray(new CK_ATTRIBUTE[0]);
  }

  public Attribute getAttribute(long type) {
    for (Attribute attr : attributes) {
      if (attr.getType() == type) return attr;
    }
    return null;
  }

  public Boolean getBooleanAttrValue(long type) {
    Attribute attr = getAttribute(type);
    return attr == null ? null : ((BooleanAttribute) attr).getValue();
  }

  public Long getLongAttrValue(long type) {
    Attribute attr = getAttribute(type);
    return attr == null ? null : ((LongAttribute) attr).getValue();
  }

  public Integer getIntAttrValue(long type) {
    Long value = getLongAttrValue(type);
    return value == null ? null : value.intValue();
  }

  public String getStringAttrValue(long type) {
    Attribute attr = getAttribute(type);
    return attr == null ? null : ((CharArrayAttribute) attr).getValue();
  }

  public byte[] getByteArrayAttrValue(long type) {
    Attribute attr = getAttribute(type);
    return attr == null ? null : ((ByteArrayAttribute) attr).getValue();
  }

  public String toString() {
    return toString("");
  }

  public String toString(String indent) {
    StringBuilder sb = new StringBuilder(200);
    sb.append(indent).append("Attribute Vector:");

    String indent2 = indent + "  ";
    for (Attribute attribute : attributes) {
      if (sb.length() > 0) sb.append("\n");

      sb.append(attribute.toString(true, indent2));
    }

    return sb.toString();
  }

}
