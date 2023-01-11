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
public class ECDSASignRawData extends SignatureTestBase {

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

    final long mechCode = CKM_ECDSA;
    if (!Util.supports(token, mechCode)) {
      System.out.println("Unsupported mechanism " + ckmCodeToName(mechCode));
      return;
    }
    // be sure that your token can process the specified mechanism
    Mechanism signatureMechanism = getSupportedMechanism(token, mechCode);

    final boolean inToken = false;
    // OID: 1.2.840.10045.3.1.7 (secp256r1, alias NIST P-256)
    final byte[] ecParams = new byte[] {0x06, 0x08, 0x2a, (byte) 0x86, 0x48, (byte) 0xce, 0x3d, 0x03, 0x01, 0x07};

    PKCS11KeyPair generatedKeyPair = generateECKeypair(token, session, ecParams, inToken);
    long generatedPrivateKey = generatedKeyPair.getPrivateKey();

    LOG.info("##################################################");
    LOG.info("signing data");
    byte[] dataToBeSigned = randomBytes(1057); // hash value
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    byte[] hashValue = md.digest(dataToBeSigned);

    // initialize for signing
    session.signInit(signatureMechanism, generatedPrivateKey);

    // This signing operation is implemented in most of the drivers
    byte[] signatureValue = session.sign(hashValue);

    LOG.info("The signature value is: {}", Functions.toHex(signatureValue));

    // verify
    long generatedPublicKey = generatedKeyPair.getPublicKey();
    session.verifyInit(signatureMechanism, generatedPublicKey);
    // error will be thrown if signature is invalid
    session.verify(hashValue, signatureValue);

    // verify with JCE
    jceVerifySignature("SHA256WithECDSA", session, generatedPublicKey, CKK_EC, dataToBeSigned,
        Util.dsaSigPlainToX962(signatureValue));

    LOG.info("##################################################");
  }

}
