package org.xipki.pkcs11;

import java.util.Date;
import java.util.Objects;

public class KeyPairTemplate {

  private final AttributeVector privateKey;
  private final AttributeVector publicKey;

  public KeyPairTemplate(long keyType) {
    this.privateKey = AttributeVector.newPrivateKey(keyType);
    this.publicKey = AttributeVector.newPublicKey(keyType);
  }

  public KeyPairTemplate(AttributeVector privateKey, AttributeVector publicKey) {
    this.privateKey = Objects.requireNonNull(privateKey, "privateKey must not be null");
    this.publicKey = Objects.requireNonNull(publicKey, "publicKey must not be null");
    if (!Objects.equals(privateKey.keyType(), publicKey.keyType())) {
      throw new IllegalArgumentException("privateKey and publicKey do not have the same key type.");
    }

    if (privateKey.class_() == null) {
      privateKey.class_(PKCS11Constants.CKO_PRIVATE_KEY);
    } else if (privateKey.class_() != PKCS11Constants.CKO_PRIVATE_KEY) {
      throw new IllegalArgumentException("privateKey must have the class CKO_PRIVATE_KEY");
    }

    if (publicKey.class_() == null) {
      publicKey.class_(PKCS11Constants.CKO_PUBLIC_KEY);
    } else if (publicKey.class_() != PKCS11Constants.CKO_PUBLIC_KEY) {
      throw new IllegalArgumentException("publicKey must have the class CKO_PUBLIC_KEY");
    }
  }

  public AttributeVector privateKey() {
    return privateKey;
  }

  public AttributeVector publicKey() {
    return publicKey;
  }

  public KeyPairTemplate derive(Boolean derive) {
    privateKey.derive(derive);
    publicKey.derive(derive);
    return this;
  }

  public KeyPairTemplate decryptEncrypt(Boolean decryptEncrypt) {
    privateKey.decrypt(decryptEncrypt);
    publicKey.encrypt(decryptEncrypt);
    return this;
  }

  public KeyPairTemplate endDate(Date endDate) {
    privateKey.endDate(endDate);
    publicKey.endDate(endDate);
    return this;
  }

  public KeyPairTemplate id(byte[] id) {
    privateKey.id(id);
    publicKey.id(id);
    return this;
  }

  public KeyPairTemplate keyType(long keyType) {
    privateKey.keyType(keyType);
    publicKey.keyType(keyType);
    return this;
  }

  public KeyPairTemplate label(String label) {
    return label(label, label);
  }

  public KeyPairTemplate label(String privateKeyLabel, String publicKeyLabel) {
    if (privateKeyLabel != null) {
      privateKey.label(privateKeyLabel);
    }
    if (publicKeyLabel != null) {
      publicKey.label(publicKeyLabel);
    }
    return this;
  }

  public KeyPairTemplate local(Boolean local) {
    privateKey.local(local);
    publicKey.local(local);
    return this;
  }

  public KeyPairTemplate modifiable(Boolean modifiable) {
    privateKey.modifiable(modifiable);
    publicKey.modifiable(modifiable);
    return this;
  }

  public KeyPairTemplate private_(Boolean private_) {
    return private_(private_, private_);
  }

  public KeyPairTemplate private_(Boolean privateKeyPrivate, Boolean publicKeyPrivate) {
    if (privateKeyPrivate != null) {
      privateKey.private_(privateKeyPrivate);
    }

    if (publicKeyPrivate != null) {
      publicKey.private_(publicKeyPrivate);
    }
    return this;
  }

  public KeyPairTemplate signVerify(Boolean signVerify) {
    privateKey.sign(signVerify);
    publicKey.verify(signVerify);
    return this;
  }

  public KeyPairTemplate signVerifyRecover(Boolean signVerifyRecover) {
    privateKey.signRecover(signVerifyRecover);
    publicKey.verifyRecover(signVerifyRecover);
    return this;
  }

  public KeyPairTemplate startDate(Date startDate) {
    privateKey.startDate(startDate);
    publicKey.startDate(startDate);
    return this;
  }

  public KeyPairTemplate subject(byte[] subject) {
    privateKey.subject(subject);
    publicKey.subject(subject);
    return this;
  }

  public KeyPairTemplate token(Boolean token) {
    privateKey.token(token);
    publicKey.token(token);
    return this;
  }

  public KeyPairTemplate unwrapWrap(Boolean unwrapWrap) {
    privateKey.unwrap(unwrapWrap);
    publicKey.wrap(unwrapWrap);
    return this;
  }

}
