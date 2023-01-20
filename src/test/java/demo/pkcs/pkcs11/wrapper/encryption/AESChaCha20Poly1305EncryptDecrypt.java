// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package demo.pkcs.pkcs11.wrapper.encryption;

import org.junit.Test;
import org.xipki.pkcs11.AttributeVector;
import org.xipki.pkcs11.Mechanism;
import org.xipki.pkcs11.PKCS11Exception;
import org.xipki.pkcs11.Token;
import org.xipki.pkcs11.params.SALSA20_CHACHA20_POLY1305_PARAMS;

import static org.xipki.pkcs11.PKCS11Constants.*;

/**
 * This demo program uses a PKCS#11 module to encrypt and decrypt via
 * CKM_CHACHA20_POLY1305.
 */
public class AESChaCha20Poly1305EncryptDecrypt extends SymmEncryptDecrypt {

  private final byte[] iv;

  private final byte[] aad;

  public AESChaCha20Poly1305EncryptDecrypt() {
    iv = randomBytes(12);
    aad = new byte[20];
    // aad = "hello".getBytes();
  }

  @Test
  @Override
  public void main() throws PKCS11Exception {
    // check whether supported in current JDK
    try {
      new SALSA20_CHACHA20_POLY1305_PARAMS(new byte[12], null);
    } catch (IllegalStateException ex) {
      System.err.println("AES-GCM unsupported in current JDK, skip");
      return;
    }

    super.main();
  }

  @Override
  protected Mechanism getKeyGenMech(Token token) throws PKCS11Exception {
    return getSupportedMechanism(token, CKM_CHACHA20_KEY_GEN);
  }

  @Override
  protected Mechanism getEncryptionMech(Token token) throws PKCS11Exception {
    return getSupportedMechanism(token, CKM_CHACHA20_POLY1305, new SALSA20_CHACHA20_POLY1305_PARAMS(iv, aad));
  }

  @Override
  protected AttributeVector getKeyTemplate() {
    return newSecretKey(CKK_CHACHA20).encrypt(true).decrypt(true).valueLen(32);
  }

}
