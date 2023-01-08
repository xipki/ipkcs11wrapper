// Copyright (c) 2002 Graz University of Technology. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// 3. The end-user documentation included with the redistribution, if any, must
//    include the following acknowledgment:
//
//    "This product includes software developed by IAIK of Graz University of
//     Technology."
//
//    Alternately, this acknowledgment may appear in the software itself, if and
//    wherever such third-party acknowledgments normally appear.
//
// 4. The names "Graz University of Technology" and "IAIK of Graz University of
//    Technology" must not be used to endorse or promote products derived from
//    this software without prior written permission.
//
// 5. Products derived from this software may not be called "IAIK PKCS Wrapper",
//    nor may "IAIK" appear in their name, without prior written permission of
//    Graz University of Technology.
//
// THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESSED OR IMPLIED
// WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE LICENSOR BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
// OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
// OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
// ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

package demo.pkcs.pkcs11.wrapper.basics;

import demo.pkcs.pkcs11.wrapper.TestBase;
import org.junit.Test;
import org.xipki.pkcs11.AttributeVector;
import org.xipki.pkcs11.PKCS11Exception;
import org.xipki.pkcs11.Session;
import org.xipki.pkcs11.Token;
import org.xipki.pkcs11.objects.Attribute;
import org.xipki.pkcs11.objects.ByteArrayAttribute;

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
    AttributeVector signatureKeyTemplate = new AttributeVector()
        .attr(CKA_CLASS, CKO_PRIVATE_KEY)
        .attr(CKA_SIGN, true);

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
        LOG.info("The certificate for this private signature key {} is (handle={}, label={})",
            privateSignatureKeyHandle, foundCertificateObjects[0], getLabel(session, foundCertificateObjects[0]));
      } else {
        LOG.info("There is no certificate for this private signature key {}", privateSignatureKeyHandle);
      }

      session.findObjectsFinal();
    }

    LOG.info("found {} objects on this token", counter);
  }

  private static String getLabel(Session session, long hObject) throws PKCS11Exception {
    return session.getStringAttrValue(hObject, CKA_LABEL);
  }

}
