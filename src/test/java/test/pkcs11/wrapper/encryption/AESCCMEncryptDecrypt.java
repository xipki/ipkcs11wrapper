// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.wrapper.encryption;

import org.junit.Test;
import org.xipki.pkcs11.wrapper.*;
import org.xipki.pkcs11.wrapper.params.CCM_PARAMS;
import test.pkcs11.wrapper.TestBase;

import java.io.IOException;

import static org.xipki.pkcs11.wrapper.PKCS11Constants.*;

/**
 * This demo program uses a PKCS#11 module to encrypt and decrypt via
 * CKM_AES_GCM.
 */
public class AESCCMEncryptDecrypt extends SymmEncryptDecrypt {

  private final byte[] iv;

  private final byte[] aad;

  public AESCCMEncryptDecrypt() {
    iv = TestBase.randomBytes(12);
    aad = new byte[20];
    // aad = "hello".getBytes();
  }

  @Test
  @Override
  public void main() throws TokenException, IOException {
    if (!getToken().supportsMechanism(CKM_AES_CCM, CKF_ENCRYPT)) {
      System.err.println("AES-CCM unsupported in the HSM, skip");
      return;
    }

    super.main();
  }

  @Override
  protected Mechanism getKeyGenMech() throws PKCS11Exception {
    return getSupportedMechanism(CKM_AES_KEY_GEN, CKF_GENERATE);
  }

  @Override
  protected Mechanism getEncryptionMech() throws PKCS11Exception {
    return getSupportedMechanism(CKM_AES_CCM, CKF_ENCRYPT, new CCM_PARAMS(0, iv, aad, 128));
  }

  @Override
  protected AttributeVector getKeyTemplate() {
    return newSecretKey(CKK_AES).encrypt(true).decrypt(true).valueLen(16);
  }

}
