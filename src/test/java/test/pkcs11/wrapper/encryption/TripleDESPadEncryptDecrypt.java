// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.wrapper.encryption;

import org.xipki.pkcs11.wrapper.AttributeVector;
import org.xipki.pkcs11.wrapper.Mechanism;
import org.xipki.pkcs11.wrapper.PKCS11Exception;
import org.xipki.pkcs11.wrapper.params.ByteArrayParams;
import test.pkcs11.wrapper.TestBase;

import static org.xipki.pkcs11.wrapper.PKCS11Constants.*;

/**
 * This demo program uses a PKCS#11 module to encrypt and decrypt via AES.
 */
public class TripleDESPadEncryptDecrypt extends SymmEncryptDecrypt {

  private final byte[] iv;

  public TripleDESPadEncryptDecrypt() {
    iv = TestBase.randomBytes(8);
  }

  @Override
  protected Mechanism getKeyGenMech() throws PKCS11Exception {
    return getSupportedMechanism(CKM_DES3_KEY_GEN, CKF_GENERATE);
  }

  @Override
  protected Mechanism getEncryptionMech() throws PKCS11Exception {
    return getSupportedMechanism(CKM_DES3_CBC_PAD, CKF_ENCRYPT, new ByteArrayParams(iv));
  }

  @Override
  protected AttributeVector getKeyTemplate() {
    return newSecretKey(CKK_DES3).encrypt(true).decrypt(true);
  }

}
