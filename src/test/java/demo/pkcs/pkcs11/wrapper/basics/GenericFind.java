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
import org.xipki.pkcs11.attrs.Attribute;
import org.xipki.pkcs11.attrs.ByteArrayAttribute;

import java.util.*;

import static org.xipki.pkcs11.PKCS11Constants.*;

/**
 * This class demonstrates how to use the GenericSearchTemplate class.
 */
public class GenericFind extends TestBase {

  @Test
  public void main() throws PKCS11Exception {
    Token token = getNonNullToken();
    Session session = openReadOnlySession(token);
    try {
      main0(session);
    } finally {
      session.closeSession();
    }
  }

  private void main0(Session session) throws PKCS11Exception {
    // limit output if required
    int limit = 0, counter = 1;

    LOG.info("##################################################");
    LOG.info("Find all signature private keys.");
    AttributeVector signatureKeyTemplate = AttributeVector.newPrivateKey().attr(CKA_SIGN, true);

    // this find operation will find all objects that possess a CKA_SIGN
    // attribute with value true
    session.findObjectsInit(signatureKeyTemplate);

    // find first
    long[] foundSignatureKeyObjects = session.findObjects(1);

    List<Long> signatureKeys;
    if (foundSignatureKeyObjects.length > 0) {
      signatureKeys = new Vector<>();
      LOG.info("handle={}, label={}", foundSignatureKeyObjects[0], getLabel(session, foundSignatureKeyObjects[0]));
      signatureKeys.add(foundSignatureKeyObjects[0]);

      while ((foundSignatureKeyObjects = session.findObjects(1)).length > 0
          && (0 == limit || counter < limit)) {
        LOG.info("handle={}, label={}", foundSignatureKeyObjects[0], getLabel(session, foundSignatureKeyObjects[0]));
        signatureKeys.add(foundSignatureKeyObjects[0]);
        counter++;
      }
    } else {
      String msg = "There is no object with a CKA_SIGN attribute set to true.";
      LOG.info(msg);
      return;
    }
    session.findObjectsFinal();
    LOG.info("##################################################\n{}",
        "Find corresponding certificates for private signature keys.");

    List<Long> privateSignatureKeys = new LinkedList<>();

    // sort out all signature keys that are private keys
    privateSignatureKeys.addAll(signatureKeys);

    // for each private signature key try to find a public key certificate with the same ID
    Map<Long, Long> privateKeyToCertificateTable = new HashMap<>(privateSignatureKeys.size() * 5 / 4);
    for (long privateSignatureKeyHandle : privateSignatureKeys) {
      byte[] id = session.getByteArrayAttrValue(privateSignatureKeyHandle, CKA_ID);
      ByteArrayAttribute idAttr = (ByteArrayAttribute) Attribute.getInstance(CKA_ID, id);
      AttributeVector certificateSearchTemplate = new AttributeVector(idAttr);
      session.findObjectsInit(certificateSearchTemplate);

      long[] foundCertificateObjects;
      if ((foundCertificateObjects = session.findObjects(1)).length > 0) {
        privateKeyToCertificateTable.put(privateSignatureKeyHandle, foundCertificateObjects[0]);
        LOG.info("The certificate for private signature key {} is (handle={}, label={})",
            privateSignatureKeyHandle, foundCertificateObjects[0], getLabel(session, foundCertificateObjects[0]));
      } else {
        LOG.info("There is no certificate for private signature key {}", privateSignatureKeyHandle);
      }

      session.findObjectsFinal();
    }

    LOG.info("found {} objects on this token", counter);
  }

  private static String getLabel(Session session, long hObject) throws PKCS11Exception {
    return session.getStringAttrValue(hObject, CKA_LABEL);
  }

}
