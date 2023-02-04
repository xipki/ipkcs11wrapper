// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.
//
// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.wrapper.encryption;

import test.pkcs11.wrapper.TestBase;
import test.pkcs11.wrapper.util.Util;
import org.junit.Test;
import org.xipki.pkcs11.wrapper.*;

import java.math.BigInteger;
import java.security.SecureRandom;

import static org.xipki.pkcs11.wrapper.PKCS11Constants.*;

/**
 * This demo program uses a PKCS#11 module to wrap and unwrap a MAC secret key.
 * The key to be wrapped must be extractable otherwise it can't be wrapped.
 */
public class WrapUnwrapHmacKey extends TestBase {

  @Test
  public void main() throws PKCS11Exception {
    Token token = getNonNullToken();
    Session session = openReadWriteSession(token);
    try {
      main0(token, session);
    } finally {
      session.closeSession();
    }
  }

  private void main0(Token token, Session session) throws PKCS11Exception {
    LOG.info("##################################################");
    AttributeVector secretMACKeyTemplate = newSecretKey(CKK_GENERIC_SECRET).token(false)
        .sign(true).verify(true).private_(true).sensitive(true).extractable(true);

    long hmacKey;
    int keyBytesLen = 32;
    Mechanism keyMechanism = new Mechanism(CKM_GENERIC_SECRET_KEY_GEN);
    if (Util.supports(token, keyMechanism.getMechanismCode())) {
      LOG.info("generate secret MAC key");
      secretMACKeyTemplate.valueLen(keyBytesLen);
      hmacKey = session.generateKey(keyMechanism, secretMACKeyTemplate);
    } else {
      LOG.info("import secret MAC key (generation not supported)");
      byte[] keyValue = new byte[keyBytesLen];
      new SecureRandom().nextBytes(keyValue);
      secretMACKeyTemplate.value(keyValue);

      hmacKey = session.createObject(secretMACKeyTemplate);
    }

    LOG.info("##################################################");

    // be sure that your token can process the specified mechanism
    Mechanism signatureMechanism = getSupportedMechanism(token, CKM_SHA256_HMAC);
    // initialize for signing
    session.signInit(signatureMechanism, hmacKey);

    byte[] rawData = randomBytes(1057);

    byte[] macValue = session.sign(rawData);

    LOG.info("The MAC value is: " + new BigInteger(1, macValue).toString(16));
    LOG.info("##################################################");
    LOG.info("generate secret wrapping key");
    Mechanism wrapKeyMechanism = new Mechanism(CKM_AES_KEY_GEN);
    AttributeVector wrapKeyTemplate = newSecretKey(CKK_AES).valueLen(16)
        .encrypt(true).decrypt(true).private_(true).sensitive(true).extractable(true).wrap(true).token(false);

    long wrappingKey = session.generateKey(wrapKeyMechanism, wrapKeyTemplate);

    LOG.info("wrapping key");

    Mechanism wrapMechanism = new Mechanism(CKM_AES_KEY_WRAP);
    byte[] wrappedKey = session.wrapKey(wrapMechanism, wrappingKey, hmacKey);
    LOG.info("unwrapping key");

    AttributeVector keyTemplate = newSecretKey(CKK_GENERIC_SECRET).verify(true).token(false);

    long unwrappedKey = session.unwrapKey(wrapMechanism, wrappingKey, wrappedKey, keyTemplate);

    LOG.info("##################################################");
    LOG.info("verification of the MAC... ");

    // initialize for verification
    session.verifyInit(signatureMechanism, unwrappedKey);

    session.verify(rawData, macValue); // throws an exception upon
    // unsuccessful verification

    LOG.info("##################################################");
  }

}
