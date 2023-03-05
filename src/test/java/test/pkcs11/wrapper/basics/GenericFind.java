// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.
//
// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.wrapper.basics;

import test.pkcs11.wrapper.TestBase;
import org.junit.Test;
import org.xipki.pkcs11.wrapper.AttributeVector;
import org.xipki.pkcs11.wrapper.PKCS11Exception;
import org.xipki.pkcs11.wrapper.Session;
import org.xipki.pkcs11.wrapper.Token;
import org.xipki.pkcs11.wrapper.attrs.Attribute;
import org.xipki.pkcs11.wrapper.attrs.ByteArrayAttribute;

import java.util.*;

import static org.xipki.pkcs11.wrapper.PKCS11Constants.*;

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
    LOG.info("##################################################");
    LOG.info("Find all signature private keys.");
    AttributeVector signatureKeyTemplate = AttributeVector.newPrivateKey().attr(CKA_SIGN, true);

    // this find operation will find all objects that possess a CKA_SIGN
    // attribute with value true
    long[] signatureKeys = session.findObjectsSingle(signatureKeyTemplate, 99999);

    if (signatureKeys.length == 0) {
      LOG.info("There is no object with a CKA_SIGN attribute set to true.");
      return;
    }

    for (long object : signatureKeys) {
      LOG.info("handle={}, label={}", object, getLabel(session, object));
    }


    LOG.info("##################################################\n{}",
        "Find corresponding certificates for private signature keys.");

    // for each private signature key try to find a public key certificate with the same ID
    for (long privateSignatureKeyHandle : signatureKeys) {
      byte[] id = session.getByteArrayAttrValue(privateSignatureKeyHandle, CKA_ID);
      AttributeVector certificateSearchTemplate = AttributeVector.newX509Certificate().id(id);

      long[] foundCertificateObjects = session.findObjectsSingle(certificateSearchTemplate, 1);
      if (foundCertificateObjects.length > 0) {
        LOG.info("The certificate for private signature key {} is (handle={}, label={})",
            privateSignatureKeyHandle, foundCertificateObjects[0], getLabel(session, foundCertificateObjects[0]));
      } else {
        LOG.info("There is no certificate for private signature key {}", privateSignatureKeyHandle);
      }
    }

    LOG.info("found {} objects on this token", signatureKeys.length);
  }

  private static String getLabel(Session session, long hObject) throws PKCS11Exception {
    return session.getStringAttrValue(hObject, CKA_LABEL);
  }

}
