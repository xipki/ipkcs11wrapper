// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.
//
// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package demo.pkcs.pkcs11.wrapper.encryption;

import demo.pkcs.pkcs11.wrapper.TestBase;
import org.junit.Assert;
import org.junit.Test;
import org.xipki.pkcs11.*;
import org.xipki.pkcs11.params.ByteArrayParams;

import java.util.Arrays;

import static org.xipki.pkcs11.PKCS11Constants.*;

/**
 * This demo program uses a PKCS#11 module to wrap and unwrap a secret key.
 * The key to be wrapped must be extractable otherwise it can't be wrapped.
 */
public class WrapUnwrapEncrKey extends TestBase {

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
    Mechanism keyMechanism = getSupportedMechanism(token, CKM_AES_KEY_GEN);

    AttributeVector secretEncryptionKeyTemplate = newSecretKey(CKK_AES).token(false).valueLen(16)
        .encrypt(true).decrypt(true).private_(true).sensitive(true).extractable(true);

    long encryptionKey = session.generateKey(keyMechanism, secretEncryptionKeyTemplate);

    byte[] rawData = randomBytes(1517);

    // be sure that your token can process the specified mechanism
    Mechanism wrapMechanism = getSupportedMechanism(token, CKM_AES_KEY_WRAP);

    byte[] encryptIV = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    Mechanism encryptionMechanism = getSupportedMechanism(token, CKM_AES_CBC_PAD, new ByteArrayParams(encryptIV));

    // initialize for encryption
    session.encryptInit(encryptionMechanism, encryptionKey);

    byte[] buffer = new byte[rawData.length + 64];
    int cipherLen = session.encrypt(rawData, 0, rawData.length, buffer, 0, buffer.length);
    byte[] encryptedData = Arrays.copyOf(buffer, cipherLen);

    LOG.info("##################################################");
    LOG.info("generate secret wrapping key");

    Mechanism wrapKeyMechanism = getSupportedMechanism(token, CKM_AES_KEY_GEN);
    AttributeVector wrapKeyTemplate = newSecretKey(CKK_AES).token(false).valueLen(16)
        .encrypt(true).decrypt(true).private_(true).sensitive(true).extractable(true).wrap(true).unwrap(true);

    long wrappingKey = session.generateKey(wrapKeyMechanism, wrapKeyTemplate);

    LOG.info("wrapping key");

    byte[] wrappedKey = session.wrapKey(wrapMechanism, wrappingKey, encryptionKey);
    AttributeVector keyTemplate = newSecretKey(CKK_AES).decrypt(true).token(false);

    LOG.info("unwrapping key");

    long unwrappedKey = session.unwrapKey(wrapMechanism, wrappingKey, wrappedKey, keyTemplate);

    LOG.info("##################################################");
    LOG.info("trying to decrypt");

    byte[] decryptIV = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    Mechanism decryptionMechanism = getSupportedMechanism(token, CKM_AES_CBC_PAD, new ByteArrayParams(decryptIV));

    // initialize for decryption
    session.decryptInit(decryptionMechanism, unwrappedKey);

    int decryptLen = session.decrypt(encryptedData, 0, encryptedData.length, buffer, 0, buffer.length);
    byte[] decryptedData = Arrays.copyOf(buffer, decryptLen);
    Arrays.fill(buffer, (byte) 0);

    Assert.assertArrayEquals(rawData, decryptedData);

    LOG.info("##################################################");
  }

}
