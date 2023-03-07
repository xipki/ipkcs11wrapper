// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.wrapper.encryption;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.pkcs11.wrapper.*;
import test.pkcs11.wrapper.TestBase;

import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKF_DECRYPT;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKM_RSA_PKCS;

/**
 * This demo shows how to use a PKCS#11 token to decrypt a session key
 * encrypted by RSA.
 */
public class RSADecrypt extends TestBase {

  @Test
  public void main() throws TokenException {
    Token token = getNonNullToken();

    Session session = openReadWriteSession(token);
    try {
      main0(token, session);
    } finally {
      session.closeSession();
    }
  }

  private void main0(Token token, Session session) throws TokenException {
    // check, if this token can do RSA decryption
    Mechanism encMech = getSupportedMechanism(token, CKM_RSA_PKCS);
    if (!token.getMechanismInfo(encMech.getMechanismCode()).hasFlagBit(CKF_DECRYPT)) {
      LOG.info("This token does not support RSA decryption according to PKCS!");
      throw new TokenException("RSA decryption not supported!");
    }

    final boolean inToken = false;
    final int keysize = 2048;
    PKCS11KeyPair keypair = generateRSAKeypair(token, session, keysize, inToken);
    long privKey = keypair.getPrivateKey();
    long pubKey = keypair.getPublicKey();

    byte[] sessionKey = new byte[16];
    byte[] encryptedSessionKey = session.encryptSingle(encMech, pubKey, sessionKey);

    // decrypt
    byte[] decryptedSessionKey = session.decryptSingle(encMech, privKey, encryptedSessionKey);

    Assert.assertArrayEquals(sessionKey, decryptedSessionKey);
    LOG.info("finished");
  }

}
