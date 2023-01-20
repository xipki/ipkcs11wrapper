// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package demo.pkcs.pkcs11.wrapper.encryption;

import demo.pkcs.pkcs11.wrapper.util.Util;
import org.junit.Test;
import org.xipki.pkcs11.AttributeVector;
import org.xipki.pkcs11.Mechanism;
import org.xipki.pkcs11.PKCS11Exception;
import org.xipki.pkcs11.Token;
import org.xipki.pkcs11.params.CCM_PARAMS;

import static org.xipki.pkcs11.PKCS11Constants.*;

/**
 * This demo program uses a PKCS#11 module to encrypt and decrypt via
 * CKM_AES_GCM.
 */
public class AESCCMEncryptDecrypt extends SymmEncryptDecrypt {

  private final byte[] iv;

  private final byte[] aad;

  public AESCCMEncryptDecrypt() {
    iv = randomBytes(12);
    aad = new byte[20];
    // aad = "hello".getBytes();
  }

  @Test
  @Override
  public void main() throws PKCS11Exception {
    if (!Util.supports(getNonNullToken(), CKM_AES_CCM)) {
      System.err.println("AES-CCM unsupported in the HSM, skip");
      return;
    }

    super.main();
  }

  @Override
  protected Mechanism getKeyGenMech(Token token) throws PKCS11Exception {
    return getSupportedMechanism(token, CKM_AES_KEY_GEN);
  }

  @Override
  protected Mechanism getEncryptionMech(Token token) throws PKCS11Exception {
    return getSupportedMechanism(token, CKM_AES_CCM, new CCM_PARAMS(0, iv, aad, 128));
  }

  @Override
  protected AttributeVector getKeyTemplate() {
    return newSecretKey(CKK_AES).encrypt(true).decrypt(true).valueLen(16);
  }

}
