// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.wrapper.keygeneration;

import org.junit.Test;
import org.xipki.pkcs11.wrapper.*;
import test.pkcs11.wrapper.TestBase;

import static org.xipki.pkcs11.wrapper.PKCS11Constants.*;

/**
 * This demo program shows how to generate secret keys.
 */
public class GenerateKey extends TestBase {

  @Test
  public void main() throws TokenException {
    Mechanism mech = getSupportedMechanism(CKM_GENERIC_SECRET_KEY_GEN, CKF_GENERATE);
    LOG.info("##################################################");
    LOG.info("Generating generic secret key");

    PKCS11Token token = getToken();

    AttributeVector secretKeyTemplate = newSecretKey(CKK_GENERIC_SECRET).token(false).valueLen(16);
    long secretKey = token.generateKey(mech, secretKeyTemplate);

    LOG.info("the secret key is {}", secretKey);
    LOG.info("##################################################");
  }

}
