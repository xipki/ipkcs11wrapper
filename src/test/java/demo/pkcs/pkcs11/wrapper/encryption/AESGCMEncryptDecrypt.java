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

import org.junit.Test;
import org.xipki.pkcs11.AttributeVector;
import org.xipki.pkcs11.Mechanism;
import org.xipki.pkcs11.PKCS11Exception;
import org.xipki.pkcs11.Token;
import org.xipki.pkcs11.params.GcmParameters;

import static org.xipki.pkcs11.PKCS11Constants.*;

/**
 * This demo program uses a PKCS#11 module to encrypt and decrypt via
 * CKM_AES_GCM.
 *
 * @author Lijun Liao
 */
public class AESGCMEncryptDecrypt extends SymmEncryptDecrypt {

  private final byte[] iv;

  private final byte[] aad;

  public AESGCMEncryptDecrypt() {
    iv = randomBytes(12);
    aad = new byte[20];
    // aad = "hello".getBytes();
  }

  @Test
  @Override
  public void main() throws PKCS11Exception {
    super.main();
  }

  @Override
  protected Mechanism getKeyGenMech(Token token) throws PKCS11Exception {
    return getSupportedMechanism(token, CKM_AES_KEY_GEN);
  }

  @Override
  protected Mechanism getEncryptionMech(Token token) throws PKCS11Exception {
    return getSupportedMechanism(token, CKM_AES_GCM, new GcmParameters(iv, aad, 128));
  }

  @Override
  protected AttributeVector getKeyTemplate() {
    return newSecretKey(CKK_AES).encrypt(true).decrypt(true).valueLen(16);
  }

}
