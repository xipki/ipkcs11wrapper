// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.
//
// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.wrapper.basics;

import org.junit.Test;
import org.xipki.pkcs11.wrapper.*;
import test.pkcs11.wrapper.TestBase;

import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKK_GENERIC_SECRET;

/**
 * This demo program allows to delete certain objects on a certain token.
 */
public class DeleteObject extends TestBase {

  @Test
  public void main() throws TokenException {
    // create a new object to be deleted later
    AttributeVector secKeyTemplate = newSecretKey(CKK_GENERIC_SECRET).token(true).value(new byte[32]);

    PKCS11Token token = getToken();
    long secKeyHandle = token.createObject(secKeyTemplate);
    token.destroyObject(secKeyHandle);
    LOG.info("deleted object");
  }

}
