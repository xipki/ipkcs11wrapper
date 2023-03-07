// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.wrapper.keygeneration;

import org.junit.Test;
import org.xipki.pkcs11.wrapper.*;
import test.pkcs11.wrapper.TestBase;

import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKK_GENERIC_SECRET;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKM_GENERIC_SECRET_KEY_GEN;

/**
 * This demo program shows how to generate secret keys.
 */
public class GenerateKey extends TestBase {

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
    Mechanism mech = getSupportedMechanism(token, CKM_GENERIC_SECRET_KEY_GEN);
    LOG.info("##################################################");
    LOG.info("Generating generic secret key");

    AttributeVector secretKeyTemplate = newSecretKey(CKK_GENERIC_SECRET).token(false).valueLen(16);
    long secretKey = session.generateKey(mech, secretKeyTemplate);

    LOG.info("the secret key is {}", secretKey);
    LOG.info("##################################################");
  }

}
