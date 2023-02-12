// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.wrapper.encryption;

import test.pkcs11.wrapper.TestBase;
import org.junit.Assert;
import org.junit.Test;
import org.xipki.pkcs11.wrapper.*;
import org.xipki.pkcs11.wrapper.params.CCM_PARAMS;
import org.xipki.pkcs11.wrapper.params.CkParams;

import java.util.Arrays;

/**
 * This demo program uses a PKCS#11 module to encrypt a given file and test if
 * the data can be decrypted.
 */
public abstract class SymmEncryptDecrypt extends TestBase {

  protected abstract Mechanism getKeyGenMech(Token token) throws PKCS11Exception;

  protected abstract AttributeVector getKeyTemplate();

  protected abstract Mechanism getEncryptionMech(Token token) throws PKCS11Exception;

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
    LOG.info("generate secret encryption/decryption key");

    Mechanism keyMechanism;
    try {
      keyMechanism = getKeyGenMech(token);
    } catch (PKCS11Exception e) {
      LOG.info("unsupported by the HSM, skipping test");
      System.out.println("unsupported by the HSM, skipping test");
      return;
    }

    AttributeVector keyTemplate = getKeyTemplate().token(false);

    long encryptionKey = session.generateKey(keyMechanism, keyTemplate);
    LOG.info("##################################################");
    LOG.info("encrypting data");

    byte[] rawData = randomBytes(1024);

    // be sure that your token can process the specified mechanism
    Mechanism encryptionMechanism = getEncryptionMech(token);
    CkParams params = encryptionMechanism.getParameters();
    if (params instanceof CCM_PARAMS) {
      ((CCM_PARAMS) params).setDataLen(rawData.length);
    }

    // initialize for encryption
    session.encryptInit(encryptionMechanism, encryptionKey);

    byte[] encryptedData = session.encrypt(rawData);

    LOG.info("##################################################");
    LOG.info("trying to decrypt");

    Mechanism decryptionMechanism = getEncryptionMech(token);
    params = encryptionMechanism.getParameters();
    if (params instanceof CCM_PARAMS) {
      ((CCM_PARAMS) params).setDataLen(encryptedData.length - 16);
    }

    // initialize for decryption
    session.decryptInit(decryptionMechanism, encryptionKey);

    byte[] decryptedData = session.decrypt(encryptedData);
    Assert.assertArrayEquals(rawData, decryptedData);
  }

}
