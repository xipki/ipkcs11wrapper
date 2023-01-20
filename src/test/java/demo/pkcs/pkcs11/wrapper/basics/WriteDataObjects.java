// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.
//
// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package demo.pkcs.pkcs11.wrapper.basics;

import demo.pkcs.pkcs11.wrapper.TestBase;
import org.junit.Test;
import org.xipki.pkcs11.AttributeVector;
import org.xipki.pkcs11.PKCS11Exception;
import org.xipki.pkcs11.Session;
import org.xipki.pkcs11.Token;

import static org.xipki.pkcs11.PKCS11Constants.CKO_DATA;

/**
 * This demo program can be used to download data to the card.
 */
public class WriteDataObjects extends TestBase {

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
    LOG.info("##################################################");
    // read the data from the file
    byte[] data = "hello world".getBytes();
    LOG.info("##################################################");
    LOG.info("creating data object on the card... ");

    String label = "dummy-label-" + System.currentTimeMillis();

    // create certificate object template
    AttributeVector dataObjectTemplate = new AttributeVector().class_(CKO_DATA)
        // we could also set the name that manages this data object
        //.application("Application Name")
        .label(label).value(data).token(true);

    // print template
    LOG.info("{}", dataObjectTemplate);

    // create object
    long newObject = session.createObject(dataObjectTemplate);
    // destroy after the creation
    session.destroyObject(newObject);

    LOG.info("##################################################");
  }

}
