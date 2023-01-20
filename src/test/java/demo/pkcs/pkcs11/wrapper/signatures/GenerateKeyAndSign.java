// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package demo.pkcs.pkcs11.wrapper.signatures;

import demo.pkcs.pkcs11.wrapper.TestBase;
import org.junit.Test;
import org.xipki.pkcs11.*;

import static org.xipki.pkcs11.PKCS11Constants.CKM_RSA_PKCS;

/**
 * This demo program generates a 1024-bit RSA key-pair on the token and signs
 * some data with it.
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

    Mechanism signatureMechanism = new Mechanism(CKM_RSA_PKCS);
    session.signInit(signatureMechanism, generatedRSAPrivateKey);
    byte[] dataToBeSigned = "12345678901234567890123456789012345".getBytes();
    byte[] signatureValue = session.sign(dataToBeSigned);
    LOG.info("Finished");
    LOG.info("Signature Value: {}", Functions.toHex(signatureValue));
    LOG.info("##################################################");
  }

}
