// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.wrapper.encryption;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.pkcs11.wrapper.*;
import org.xipki.pkcs11.wrapper.params.CCM_PARAMS;
import org.xipki.pkcs11.wrapper.params.CkParams;
import test.pkcs11.wrapper.TestBase;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * This demo program uses a PKCS#11 module to encrypt a given file and test if
 * the data can be decrypted.
 */
public abstract class SymmEncryptDecrypt extends TestBase {

  protected abstract Mechanism getKeyGenMech() throws PKCS11Exception;

  protected abstract AttributeVector getKeyTemplate();

  protected abstract Mechanism getEncryptionMech() throws PKCS11Exception;

  @Test
  public void main() throws TokenException, IOException {
    LOG.info("##################################################");
    LOG.info("generate secret encryption/decryption key");

    Mechanism keyMechanism;
    try {
      keyMechanism = getKeyGenMech();
    } catch (PKCS11Exception e) {
      LOG.info("unsupported by the HSM, skipping test");
      System.out.println("unsupported by the HSM, skipping test");
      return;
    }

    PKCS11Token token = getToken();
    AttributeVector keyTemplate = getKeyTemplate().token(false);

    long encryptionKey = token.generateKey(keyMechanism, keyTemplate);
    LOG.info("##################################################");
    LOG.info("encrypting data");

    int[] dataLens = {1057, 10570, 105700};
    boolean[] asStreamModes = {false, true};

    for (int dataLen : dataLens) {
      for (boolean asStream : asStreamModes) {
        byte[] rawData = randomBytes(dataLen);

        // be sure that your token can process the specified mechanism
        Mechanism encryptionMechanism = getEncryptionMech();
        CkParams params = encryptionMechanism.getParameters();
        if (params instanceof CCM_PARAMS) {
          ((CCM_PARAMS) params).setDataLen(rawData.length);
        }

        // initialize for encryption
        byte[] encryptedData;
        if (asStream) {
          ByteArrayOutputStream bout = new ByteArrayOutputStream();
          token.encrypt(bout, encryptionMechanism, encryptionKey, new ByteArrayInputStream(rawData));
          encryptedData = bout.toByteArray();
        } else {
          encryptedData = token.encrypt(encryptionMechanism, encryptionKey, rawData);
        }

        LOG.info("##################################################");
        LOG.info("trying to decrypt");

        Mechanism decryptionMechanism = getEncryptionMech();
        params = encryptionMechanism.getParameters();
        if (params instanceof CCM_PARAMS) {
          ((CCM_PARAMS) params).setDataLen(encryptedData.length - 16);
        }

        // initialize for decryption
        byte[] decryptedData;
        if (asStream) {
          ByteArrayOutputStream bout = new ByteArrayOutputStream();
          token.decrypt(bout, decryptionMechanism, encryptionKey, new ByteArrayInputStream(encryptedData));
          decryptedData = bout.toByteArray();
        } else {
          decryptedData = token.decrypt(decryptionMechanism, encryptionKey, encryptedData);
        }
        Assert.assertArrayEquals(rawData, decryptedData);
      }
    }
  }

}
