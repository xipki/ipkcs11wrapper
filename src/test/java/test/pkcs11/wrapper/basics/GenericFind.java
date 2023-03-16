// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.
//
// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.wrapper.basics;

import org.junit.Test;
import org.xipki.pkcs11.wrapper.AttributeVector;
import org.xipki.pkcs11.wrapper.PKCS11Token;
import org.xipki.pkcs11.wrapper.TokenException;
import test.pkcs11.wrapper.TestBase;

import static org.xipki.pkcs11.wrapper.PKCS11Constants.*;

/**
 * This class demonstrates how to use the GenericSearchTemplate class.
 */
public class GenericFind extends TestBase {

  @Test
  public void main() throws TokenException {
    LOG.info("##################################################");
    LOG.info("Find all signature private keys.");
    AttributeVector signatureKeyTemplate = AttributeVector.newPrivateKey().attr(CKA_SIGN, true);

    PKCS11Token token = getToken();
    // this find operation will find all objects that possess a CKA_SIGN
    // attribute with value true
    long[] signatureKeys = token.findObjects(signatureKeyTemplate, 99999);

    if (signatureKeys.length == 0) {
      LOG.info("There is no object with a CKA_SIGN attribute set to true.");
      return;
    }

    for (long object : signatureKeys) {
      LOG.info("handle={}, label={}", object, getLabel(object));
    }

    LOG.info("##################################################\n{}",
        "Find corresponding certificates for private signature keys.");

    // for each private signature key try to find a public key certificate with the same ID
    for (long privateSignatureKeyHandle : signatureKeys) {
      byte[] id = token.getAttrValues(privateSignatureKeyHandle, CKA_ID).id();
      AttributeVector certificateSearchTemplate = AttributeVector.newX509Certificate().id(id);

      long[] foundCertificateObjects = token.findObjects(certificateSearchTemplate, 1);
      if (foundCertificateObjects.length > 0) {
        LOG.info("The certificate for private signature key {} is (handle={}, label={})",
            privateSignatureKeyHandle, foundCertificateObjects[0], getLabel(foundCertificateObjects[0]));
      } else {
        LOG.info("There is no certificate for private signature key {}", privateSignatureKeyHandle);
      }
    }

    LOG.info("found {} objects on this token", signatureKeys.length);
  }

  private static String getLabel(long hObject) throws TokenException {
    return getToken().getAttrValues(hObject, CKA_LABEL).label();
  }

}
