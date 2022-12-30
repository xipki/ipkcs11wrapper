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

import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.AttributeVector;
import iaik.pkcs.pkcs11.parameters.AesCtrParameters;

import static iaik.pkcs.pkcs11.wrapper.PKCS11Constants.*;

/**
 * This demo program uses a PKCS#11 module to encrypt and decrypt via
 * CKM_AES_CTR. The encryption are processed in multiple C_EncryptUpdate
 * and finally C_EncryptFinal.
 * And the decryption are processed in multiple C_EdcryptUpdate
 * and finally C_DecryptFinal.
 *
 * @author Lijun Liao
 */
public class MultipleStepsAESCTREncryptDecrypt
extends MultipleStepsSymmEncryptDecrypt {

  private final byte[] iv;

  public MultipleStepsAESCTREncryptDecrypt() {
    iv = randomBytes(16);
  }

  @Override
  protected Mechanism getKeyGenMech(Token token) throws TokenException {
    return getSupportedMechanism(token, CKM_AES_KEY_GEN);
  }

  @Override
  protected Mechanism getEncryptionMech(Token token) throws TokenException {
    Mechanism mech = getSupportedMechanism(token, CKM_AES_CTR);
    AesCtrParameters params = new AesCtrParameters(iv);
    mech.setParameters(params);
    return mech;
  }

  @Override
  protected AttributeVector getKeyTemplate() {
    return newSecretKey(CKK_AES)
        .attr(CKA_ENCRYPT, true)
        .attr(CKA_DECRYPT, true)
        .attr(CKA_VALUE_LEN, 16);
  }

}
