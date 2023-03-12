// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.wrapper.encryption;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.pkcs11.wrapper.*;
import test.pkcs11.wrapper.TestBase;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKA_TOKEN;

/**
 * This demo program uses a PKCS#11 module to encrypt a given file and test if
 * the data can be decrypted.
 */
public abstract class MultipleStepsSymmEncryptDecrypt extends TestBase {

  protected abstract Mechanism getKeyGenMech() throws PKCS11Exception;

  protected abstract AttributeVector getKeyTemplate();

  protected abstract Mechanism getEncryptionMech() throws PKCS11Exception;

  @Test
  public void main() throws TokenException, IOException {
    PKCS11Token token = getToken();
    LOG.info("##################################################");
    LOG.info("generate secret encryption/decryption key");
    Mechanism keyMechanism = getKeyGenMech();

    AttributeVector keyTemplate = getKeyTemplate().attr(CKA_TOKEN, false);

    long encryptionKey = token.generateKey(keyMechanism, keyTemplate);
    LOG.info("##################################################");
    LOG.info("encrypting data");

    byte[] rawData = randomBytes(10240);

    // be sure that your token can process the specified mechanism
    Mechanism encryptionMechanism = getEncryptionMech();

    // encrypt
    byte[] encryptedData;
    {
      ByteArrayInputStream plaintext = new ByteArrayInputStream(rawData);
      ByteArrayOutputStream out = new ByteArrayOutputStream(rawData.length);

      int outLen = token.encrypt(out, encryptionMechanism, encryptionKey, plaintext);

      encryptedData = out.toByteArray();

      if (encryptedData.length != outLen) {
        throw new TokenException("encryptedData.length != outLen");
      }
    }

    // decrypt
    LOG.info("##################################################");
    LOG.info("trying to decrypt");

    byte[] decryptedData;
    {
      Mechanism decryptionMechanism = getEncryptionMech();
      ByteArrayInputStream ciphertextIn = new ByteArrayInputStream(encryptedData);
      ByteArrayOutputStream out = new ByteArrayOutputStream();

      int outLen = token.decrypt(out, decryptionMechanism, encryptionKey, ciphertextIn);
      decryptedData = out.toByteArray();
      if (decryptedData.length != outLen) {
        throw new TokenException("decryptedData.length != outLen");
      }
    }

    // final
    Assert.assertArrayEquals(rawData, decryptedData);
  }

}
