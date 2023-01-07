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

import demo.pkcs.pkcs11.wrapper.TestBase;
import org.junit.Test;
import org.xipki.pkcs11.*;

import static org.xipki.pkcs11.PKCS11Constants.CKM_RSA_PKCS;

/**
 * This demo program generates a 1024-bit RSA key-pair on the token and signs
 * some data with it.
 *
 * @author Lijun Liao
 */
public class GenerateKeyAndSign extends TestBase {

  @Test
  public void main() throws PKCS11Exception {
    Token token = getNonNullToken();
    Session session = openReadWriteSession(token);
    try {
      main0(token, session);
    } finally {
      session.closeSession();
    }
  }

  private void main0(Token token, Session session) throws PKCS11Exception {
    LOG.info("##################################################");
    int keySize = 1024;
    LOG.info("Generating new {} bit RSA key-pair...", keySize);

    final boolean inToken = false;
    PKCS11KeyPair generatedKeyPair = generateRSAKeypair(token, session, keySize, inToken);
    long generatedRSAPublicKey = generatedKeyPair.getPublicKey();
    long generatedRSAPrivateKey = generatedKeyPair.getPrivateKey();
    // no we may work with the keys...

    LOG.info("Success");
    LOG.info("The  public key is {}", generatedRSAPublicKey);
    LOG.info("The private key is {}", generatedRSAPrivateKey);

    LOG.info("##################################################");
    LOG.info("Signing Data... ");

    Mechanism signatureMechanism = Mechanism.get(CKM_RSA_PKCS);
    session.signInit(signatureMechanism, generatedRSAPrivateKey);
    byte[] dataToBeSigned = "12345678901234567890123456789012345".getBytes();
    byte[] signatureValue = session.sign(dataToBeSigned);
    LOG.info("Finished");
    LOG.info("Signature Value: {}", Functions.toHex(signatureValue));
    LOG.info("##################################################");
  }

}
