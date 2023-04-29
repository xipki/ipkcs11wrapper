// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.wrapper.encryption;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.pkcs11.wrapper.Mechanism;
import org.xipki.pkcs11.wrapper.PKCS11KeyPair;
import org.xipki.pkcs11.wrapper.PKCS11Token;
import org.xipki.pkcs11.wrapper.TokenException;
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
    // check, if this token can do RSA decryption
    Mechanism encMech = getSupportedMechanism(CKM_RSA_PKCS, CKF_DECRYPT);

    final boolean inToken = false;
    final int keySize = 2048;
    PKCS11KeyPair keypair = generateRSAKeypair(keySize, inToken);
    long privKey = keypair.getPrivateKey();
    long pubKey = keypair.getPublicKey();

    PKCS11Token token = getToken();
    byte[] sessionKey = new byte[16];
    byte[] encryptedSessionKey = token.encrypt(encMech, pubKey, sessionKey);

    // decrypt
    byte[] decryptedSessionKey = token.decrypt(encMech, privKey, encryptedSessionKey);

    Assert.assertArrayEquals(sessionKey, decryptedSessionKey);
    LOG.info("finished");
  }

}
