/*
 *
 * Copyright (c) 2019 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package demo.pkcs.pkcs11.wrapper.signatures;

import demo.pkcs.pkcs11.wrapper.util.Util;
import org.junit.Test;
import org.xipki.pkcs11.*;

import java.security.MessageDigest;

import static org.xipki.pkcs11.PKCS11Constants.*;

/**
 * Signs some raw data on the token using CKM_RSA_PKCS.
 *
 * @author Lijun Liao
 */
public class DSASignRawData extends SignatureTestBase {

  @Test
  public void main() throws Exception {
    Token token = getNonNullToken();
    Session session = openReadOnlySession(token);
    try {
      main0(token, session);
    } finally {
      session.closeSession();
    }
  }

  private void main0(Token token, Session session) throws Exception {
    LOG.info("##################################################");
    LOG.info("generate signature key pair");

    final long mechCode = CKM_DSA;
    if (!Util.supports(token, mechCode)) {
      System.out.println("Unsupported mechanism " + ckmCodeToName(mechCode));
      return;
    }
    // be sure that your token can process the specified mechanism
    Mechanism signatureMechanism = getSupportedMechanism(token, mechCode);

    final boolean inToken = false;

    PKCS11KeyPair generatedKeyPair = generateDSAKeypair(token, session, inToken);

    LOG.info("##################################################");
    LOG.info("signing data");
    byte[] dataToBeSigned = randomBytes(1057); // hash value
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    byte[] hashValue = md.digest(dataToBeSigned);

    // initialize for signing
    session.signInit(signatureMechanism, generatedKeyPair.getPrivateKey());

    // This signing operation is implemented in most of the drivers
    byte[] signatureValue = session.sign(hashValue);
    LOG.info("The signature value is : (len={}) {}", signatureValue.length, Functions.toHex(signatureValue));

    // verify with JCE
    jceVerifySignature("SHA256withDSA", session, generatedKeyPair.getPublicKey(), CKK_DSA,
        dataToBeSigned, Util.dsaSigPlainToX962(signatureValue));

    // verify with PKCS#11
    session.verifyInit(signatureMechanism, generatedKeyPair.getPublicKey());
    // error will be thrown if signature is invalid
    session.verify(hashValue, signatureValue);

    LOG.info("##################################################");
  }

}
