// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package demo.pkcs.pkcs11.wrapper.encryption;

import org.xipki.pkcs11.AttributeVector;
import org.xipki.pkcs11.Mechanism;
import org.xipki.pkcs11.PKCS11Exception;
import org.xipki.pkcs11.Token;
import org.xipki.pkcs11.params.ByteArrayParams;

import static org.xipki.pkcs11.PKCS11Constants.*;

/**
 * This demo program uses a PKCS#11 module to encrypt and decrypt via AES.
 */
public class TripleDESPadEncryptDecrypt extends SymmEncryptDecrypt {

  private final byte[] iv;

  public TripleDESPadEncryptDecrypt() {
    iv = randomBytes(8);
  }

  @Override
  protected Mechanism getKeyGenMech(Token token) throws PKCS11Exception {
    return getSupportedMechanism(token, CKM_DES3_KEY_GEN);
  }

  @Override
  protected Mechanism getEncryptionMech(Token token) throws PKCS11Exception {
    return getSupportedMechanism(token, CKM_DES3_CBC_PAD, new ByteArrayParams(iv));
  }

  @Override
  protected AttributeVector getKeyTemplate() {
    return newSecretKey(CKK_DES3).encrypt(true).decrypt(true);
  }

}
