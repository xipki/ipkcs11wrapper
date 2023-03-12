// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.
//
// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.wrapper.basics;

import org.junit.Test;
import org.xipki.pkcs11.wrapper.*;
import test.pkcs11.wrapper.TestBase;

import static org.xipki.pkcs11.wrapper.PKCS11Constants.*;

/**
 * This demo program read a data object with a specific label from the token.
 */
public class ReadDataObject extends TestBase {

  @Test
  public void main() throws TokenException {
    LOG.info("##################################################");
    LOG.info("searching for data object on the card using this search template... ");

    String label = "pkcs11demo-data-" + System.currentTimeMillis();

    // Create a new PKCS#11 object first
    AttributeVector newDataTemplate = new AttributeVector().class_(CKO_DATA).label(label)
        .value("hello world".getBytes());

    PKCS11Token token = getToken();

    long newDataHandle = token.createObject(newDataTemplate);

    try {
      // create certificate object template
      AttributeVector dataObjectTemplate = new AttributeVector();

      // we could also set the name that manages this data object
      // dataObjectTemplate.getApplication().setCharArrayValue("Application Name");

      // set the data object's label
      dataObjectTemplate.label(label);

      // print template
      LOG.info("{}", dataObjectTemplate);

      long[] foundDataObjects = token.findObjects(dataObjectTemplate, 1); // find first 1

      long dataObjectHandle;
      if (foundDataObjects.length > 0) {
        dataObjectHandle = foundDataObjects[0];
        AttributeVector attrs = token.getAttrValues(dataObjectHandle, CKA_CLASS, CKA_LABEL);
        LOG.info("___________________________________________________");
        LOG.info("found this data object with handle: {}", dataObjectHandle);
        LOG.info("  Class: {}", ckoCodeToName(attrs.class_()));
        LOG.info("  Label: {}", attrs.label());
        LOG.info("___________________________________________________");
      }
    } finally {
      token.destroyObject(newDataHandle);
    }
  }

}
