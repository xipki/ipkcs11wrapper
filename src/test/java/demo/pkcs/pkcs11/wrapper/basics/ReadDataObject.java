// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.
//
// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package demo.pkcs.pkcs11.wrapper.basics;

import demo.pkcs.pkcs11.wrapper.TestBase;
import org.junit.Test;
import org.xipki.pkcs11.*;

import static org.xipki.pkcs11.PKCS11Constants.*;

/**
 * This demo program read a data object with a specific label from the token.
 */
public class ReadDataObject extends TestBase {

  @Test
  public void main() throws PKCS11Exception {
    Token token = getNonNullToken();
    TokenInfo tokenInfo = token.getTokenInfo();

    LOG.info("##################################################");
    LOG.info("Information of Token:\n{}", tokenInfo);
    LOG.info("##################################################");

    // open a read-write user session
    Session session = openReadWriteSession(token);
    try {
      main0(session);
    } finally {
      session.closeSession();
    }
  }

  private void main0(Session session) throws PKCS11Exception {
    LOG.info("##################################################");
    LOG.info("searching for data object on the card using this search template... ");

    String label = "pkcs11demo-data-" + System.currentTimeMillis();

    // Create a new PKCS#11 object first
    AttributeVector newDataTemplate = new AttributeVector().class_(CKO_DATA).label(label)
        .value("hello world".getBytes());
    long newDataHandle = session.createObject(newDataTemplate);

    try {
      // create certificate object template
      AttributeVector dataObjectTemplate = new AttributeVector();

      // we could also set the name that manages this data object
      // dataObjectTemplate.getApplication().setCharArrayValue("Application Name");

      // set the data object's label
      dataObjectTemplate.label(label);

      // print template
      LOG.info("{}", dataObjectTemplate);

      // start find operation
      session.findObjectsInit(dataObjectTemplate);

      long[] foundDataObjects = session.findObjects(1); // find first

      long dataObjectHandle;
      if (foundDataObjects.length > 0) {
        dataObjectHandle = foundDataObjects[0];
        LOG.info("___________________________________________________");
        LOG.info("found this data object with handle: {}", dataObjectHandle);
        LOG.info("  Class: {}", ckoCodeToName(session.getLongAttrValue(dataObjectHandle, CKA_CLASS)));
        LOG.info("  Label: {}", session.getStringAttrValue(dataObjectHandle, CKA_LABEL));
        LOG.info("___________________________________________________");
        // FIXME, there may be more than one that matches the given template,
        // the label is not unique in general
        // foundDataObjects = session.findObjects(1); //find next
      }

      session.findObjectsFinal();
    } finally {
      session.destroyObject(newDataHandle);
    }
  }

}
