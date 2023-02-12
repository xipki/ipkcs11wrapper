// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.wrapper.encryption;

import test.pkcs11.wrapper.TestBase;
import org.junit.Assert;
import org.junit.Test;
import org.xipki.pkcs11.wrapper.*;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;

import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKA_TOKEN;

/**
 * This demo program uses a PKCS#11 module to encrypt a given file and test if
 * the data can be decrypted.
 */
public abstract class MultipleStepsSymmEncryptDecrypt extends TestBase {

  protected abstract Mechanism getKeyGenMech(Token token) throws PKCS11Exception;

  protected abstract AttributeVector getKeyTemplate();

  protected abstract Mechanism getEncryptionMech(Token token) throws PKCS11Exception;

  @Test
  public void main() throws PKCS11Exception, IOException {
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
    LOG.info("generate secret encryption/decryption key");
    Mechanism keyMechanism = getKeyGenMech(token);

    AttributeVector keyTemplate = getKeyTemplate().attr(CKA_TOKEN, false);

    long encryptionKey = session.generateKey(keyMechanism, keyTemplate);
    LOG.info("##################################################");
    LOG.info("encrypting data");

    byte[] rawData = randomBytes(1024);

    // be sure that your token can process the specified mechanism
    Mechanism encryptionMechanism = getEncryptionMech(token);

    // initialize for encryption
    session.encryptInit(encryptionMechanism, encryptionKey);

    ByteArrayOutputStream bout = new ByteArrayOutputStream(rawData.length);

    // update
    for (int i = 0; i < rawData.length; i += 64) {
      int inLen = Math.min(rawData.length - i, 64);

      byte[] res = session.encryptUpdate(Arrays.copyOfRange(rawData, i, i + inLen));
      bout.write(res, 0, res.length);
    }

    // final
    byte[] res = session.encryptFinal();
    bout.write(res, 0, res.length);

    byte[] encryptedData = bout.toByteArray();

    LOG.info("##################################################");
    LOG.info("trying to decrypt");

    Mechanism decryptionMechanism = getEncryptionMech(token);

    // initialize for decryption
    session.decryptInit(decryptionMechanism, encryptionKey);

    bout.reset();

    // update
    for (int i = 0; i < encryptedData.length; i += 64) {
      int inLen = Math.min(encryptedData.length - i, 64);

      res = session.decryptUpdate(Arrays.copyOfRange(encryptedData, i, i + inLen));
      bout.write(res, 0, res.length);
    }

    // final
    res = session.decryptFinal();
    bout.write(res, 0, res.length);

    byte[] decryptedData = bout.toByteArray();
    Assert.assertArrayEquals(rawData, decryptedData);
  }

}
