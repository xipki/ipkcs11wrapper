// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.
//
// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.wrapper.macs;

import org.junit.Test;
import org.xipki.pkcs11.wrapper.*;
import test.pkcs11.wrapper.TestBase;

import java.math.BigInteger;
import java.security.SecureRandom;

import static org.xipki.pkcs11.wrapper.PKCS11Constants.*;

/**
 * This demo program uses a PKCS#11 module to MAC a given file and test if the
 * MAC can be verified.
 */
public class MAC extends TestBase {

  @Test
  public void main() throws TokenException {
    LOG.info("##################################################");
    LOG.info("generate secret MAC key");

    AttributeVector macKeyTemplate = newSecretKey(CKK_GENERIC_SECRET).sign(true).token(false);

    PKCS11Token token = getToken();

    long secretMACKey;
    int keyBytesLen = 32;
    Mechanism keyMechanism = new Mechanism(CKM_GENERIC_SECRET_KEY_GEN);
    if (token.supportsMechanism(keyMechanism.getMechanismCode(), CKF_GENERATE)) {
      LOG.info("generate secret MAC key");
      macKeyTemplate.attr(CKA_VALUE_LEN, keyBytesLen);
      secretMACKey = token.generateKey(keyMechanism, macKeyTemplate);
    } else {
      LOG.info("import secret MAC key (generation not supported)");
      byte[] keyValue = new byte[keyBytesLen];
      new SecureRandom().nextBytes(keyValue);
      macKeyTemplate.attr(CKA_VALUE, keyValue);
      secretMACKey = token.createObject(macKeyTemplate);
    }

    LOG.info("##################################################");
    Mechanism signatureMechanism = getSupportedMechanism(CKM_SHA256_HMAC, CKF_SIGN);
    byte[] rawData = randomBytes(1057);

    byte[] macValue = token.sign(signatureMechanism, secretMACKey, rawData);
    LOG.info("The MAC value is: {}", new BigInteger(1, macValue).toString(16));

    LOG.info("##################################################");
    LOG.info("verification of the MAC... ");

    // throws an exception upon unsuccessful verification
    token.verify(signatureMechanism, secretMACKey, rawData, macValue);

    LOG.info("##################################################");
  }

}
