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

package demo.pkcs.pkcs11.wrapper.encryption;

import demo.pkcs.pkcs11.wrapper.TestBase;
import org.junit.Assert;
import org.junit.Test;
import org.xipki.pkcs11.*;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;

import static org.xipki.pkcs11.PKCS11Constants.CKA_TOKEN;

/**
 * This demo program uses a PKCS#11 module to encrypt a given file and test if
 * the data can be decrypted.
 *
 * @author Lijun Liao
 */
public abstract class MultipleStepsSymmEncryptDecrypt extends TestBase {

  protected abstract Mechanism getKeyGenMech(Token token) throws PKCS11Exception;

  protected abstract AttributesTemplate getKeyTemplate();

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

    AttributesTemplate keyTemplate = getKeyTemplate().attr(CKA_TOKEN, false);

    long encryptionKey = session.generateKey(keyMechanism, keyTemplate);
    LOG.info("##################################################");
    LOG.info("encrypting data");

    byte[] rawData = randomBytes(1024);

    // be sure that your token can process the specified mechanism
    Mechanism encryptionMechanism = getEncryptionMech(token);

    // initialize for encryption
    session.encryptInit(encryptionMechanism, encryptionKey);

    ByteArrayOutputStream bout = new ByteArrayOutputStream(rawData.length);
    byte[] buffer = new byte[128];

    int len;

    // update
    for (int i = 0; i < rawData.length; i += 64) {
      int inLen = Math.min(rawData.length - i, 64);

      len = session.encryptUpdate(rawData, i, inLen, buffer, 0, buffer.length);
      if (len > 0) {
        bout.write(buffer, 0, len);
      }
    }

    // final
    len = session.encryptFinal(buffer, 0, buffer.length);
    if (len > 0) {
      bout.write(buffer, 0, len);
    }
    Arrays.fill(buffer, (byte) 0);

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

      len = session.decryptUpdate(encryptedData, i, inLen, buffer, 0, buffer.length);
      if (len > 0) {
        bout.write(buffer, 0, len);
      }
    }

    // final
    len = session.decryptFinal(buffer, 0, buffer.length);
    if (len > 0) {
      bout.write(buffer, 0, len);
    }
    Arrays.fill(buffer, (byte) 0);

    byte[] decryptedData = bout.toByteArray();
    Assert.assertArrayEquals(rawData, decryptedData);
  }

}
