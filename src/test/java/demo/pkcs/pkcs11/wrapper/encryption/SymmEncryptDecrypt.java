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
import org.xipki.pkcs11.parameters.CcmParameters;
import org.xipki.pkcs11.parameters.Parameters;

import java.util.Arrays;

/**
 * This demo program uses a PKCS#11 module to encrypt a given file and test if
 * the data can be decrypted.
 *
 * @author Lijun Liao
 */
public abstract class SymmEncryptDecrypt extends TestBase {

  protected abstract Mechanism getKeyGenMech(Token token) throws PKCS11Exception;

  protected abstract AttributesTemplate getKeyTemplate();

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
    Mechanism keyMechanism = getKeyGenMech(token);

    AttributesTemplate keyTemplate = getKeyTemplate().token(false);

    long encryptionKey = session.generateKey(keyMechanism, keyTemplate);
    LOG.info("##################################################");
    LOG.info("encrypting data");

    byte[] rawData = randomBytes(1024);

    // be sure that your token can process the specified mechanism
    Mechanism encryptionMechanism = getEncryptionMech(token);
    Parameters params = encryptionMechanism.getParameters();
    if (params instanceof CcmParameters) {
      ((CcmParameters) params).setDataLen(rawData.length);
    }

    // initialize for encryption
    session.encryptInit(encryptionMechanism, encryptionKey);

    byte[] buffer = new byte[rawData.length + 32];
    int len = session.encrypt(rawData, 0, rawData.length, buffer, 0, buffer.length);
    byte[] encryptedData = Arrays.copyOf(buffer, len);

    LOG.info("##################################################");
    LOG.info("trying to decrypt");

    Mechanism decryptionMechanism = getEncryptionMech(token);
    params = encryptionMechanism.getParameters();
    if (params instanceof CcmParameters) {
      ((CcmParameters) params).setDataLen(encryptedData.length - 16);
    }

    // initialize for decryption
    session.decryptInit(decryptionMechanism, encryptionKey);

    len = session.decrypt(encryptedData, 0, encryptedData.length, buffer, 0, buffer.length);
    byte[] decryptedData = Arrays.copyOf(buffer, len);
    Arrays.fill(buffer, (byte) 0);
    Assert.assertArrayEquals(rawData, decryptedData);
  }

}
