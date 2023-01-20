// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.
//
// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package demo.pkcs.pkcs11.wrapper.basics;

import demo.pkcs.pkcs11.wrapper.TestBase;
import org.junit.Test;
import org.xipki.pkcs11.*;

import static org.xipki.pkcs11.PKCS11Constants.CKK_GENERIC_SECRET;

/**
 * This demo program allows to delete certain objects on a certain token.
 */
public class DeleteObject extends TestBase {

  @Test
  public void main() throws PKCS11Exception {
    Token token = getNonNullToken();
    Session session = openReadWriteSession(token);
    try {
      main0(session);
    } finally {
      session.closeSession();
    }
  }

  private void main0(Session session) throws PKCS11Exception {
    SessionInfo sessionInfo = session.getSessionInfo();
    LOG.info("using session: {}", sessionInfo);

    // create a new object to be deleted later
    AttributeVector secKeyTemplate = newSecretKey(CKK_GENERIC_SECRET).token(true).value(new byte[32]);

    long secKeyHandle = session.createObject(secKeyTemplate);
    session.destroyObject(secKeyHandle);
    LOG.info("deleted object");
  }

}
