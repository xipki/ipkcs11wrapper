// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.
//
// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.wrapper.encryption;

import org.junit.Test;
import org.xipki.pkcs11.wrapper.AttributeVector;
import org.xipki.pkcs11.wrapper.Mechanism;
import org.xipki.pkcs11.wrapper.PKCS11Token;
import org.xipki.pkcs11.wrapper.TokenException;
import test.pkcs11.wrapper.TestBase;

import java.math.BigInteger;
import java.security.SecureRandom;

import static org.xipki.pkcs11.wrapper.PKCS11Constants.*;

/**
 * This demo program uses a PKCS#11 module to wrap and unwrap a MAC secret key.
 * The key to be wrapped must be extractable otherwise it can't be wrapped.
 */
public class WrapUnwrapHmacKey extends TestBase {

  @Test
  public void main() throws TokenException {
    PKCS11Token token = getToken();
    LOG.info("##################################################");
    AttributeVector secretMACKeyTemplate = newSecretKey(CKK_GENERIC_SECRET).token(false)
        .sign(true).verify(true).private_(true).sensitive(true).extractable(true);

    long hmacKey;
    int keyBytesLen = 32;
    Mechanism keyMechanism = new Mechanism(CKM_GENERIC_SECRET_KEY_GEN);
    if (token.supportsMechanism(keyMechanism.getMechanismCode(), CKF_GENERATE)) {
      LOG.info("generate secret MAC key");
      secretMACKeyTemplate.valueLen(keyBytesLen);
      hmacKey = token.generateKey(keyMechanism, secretMACKeyTemplate);
    } else {
      LOG.info("import secret MAC key (generation not supported)");
      byte[] keyValue = new byte[keyBytesLen];
      new SecureRandom().nextBytes(keyValue);
      secretMACKeyTemplate.value(keyValue);

      hmacKey = token.createObject(secretMACKeyTemplate);
    }

    LOG.info("##################################################");

    // be sure that your token can process the specified mechanism
    Mechanism signatureMechanism = getSupportedMechanism(CKM_SHA256_HMAC, CKF_SIGN);
    // initialize for signing
    byte[] rawData = randomBytes(1057);

    byte[] macValue = token.sign(signatureMechanism, hmacKey, rawData);

    LOG.info("The MAC value is: " + new BigInteger(1, macValue).toString(16));
    LOG.info("##################################################");
    LOG.info("generate secret wrapping key");
    Mechanism wrapKeyMechanism = new Mechanism(CKM_AES_KEY_GEN);
    AttributeVector wrapKeyTemplate = newSecretKey(CKK_AES).valueLen(16)
        .encrypt(true).decrypt(true).private_(true).sensitive(true).extractable(true).wrap(true).token(false);

    long wrappingKey = token.generateKey(wrapKeyMechanism, wrapKeyTemplate);

    LOG.info("wrapping key");

    Mechanism wrapMechanism = new Mechanism(CKM_AES_KEY_WRAP);
    byte[] wrappedKey = token.wrapKey(wrapMechanism, wrappingKey, hmacKey);
    LOG.info("unwrapping key");

    AttributeVector keyTemplate = newSecretKey(CKK_GENERIC_SECRET).verify(true).token(false);

    long unwrappedKey = token.unwrapKey(wrapMechanism, wrappingKey, wrappedKey, keyTemplate);

    LOG.info("##################################################");
    LOG.info("verification of the MAC... ");

    // initialize for verification
    token.verify(signatureMechanism, unwrappedKey, rawData, macValue); // throws an exception upon
    // unsuccessful verification

    LOG.info("##################################################");
  }

}
