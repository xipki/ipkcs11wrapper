// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.wrapper.speed.encryption;

import org.junit.Assert;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.pkcs11.wrapper.*;
import test.pkcs11.wrapper.TestBase;
import test.pkcs11.wrapper.speed.Pkcs11Executor;

import java.util.Random;

/**
 * Decryption executor base class.
 */
public abstract class DecryptExecutor extends Pkcs11Executor {

  private static final Logger LOG = LoggerFactory.getLogger(DecryptExecutor.class);

  public class MyRunnable implements Runnable {

    public MyRunnable() {
    }

    @Override
    public void run() {
      PKCS11Token token;
      try {
        token = TestBase.getToken();
      } catch (PKCS11Exception e) {
        account(1, 1);
        return;
      }

      while (!stop()) {
        try {
          byte[] decryptedData = token.decrypt(encryptMechanism, key, dataToDecrypt);
          Assert.assertArrayEquals(plainData, decryptedData);

          account(1, 0);
        } catch (Throwable th) {
          System.err.println(th.getMessage());
          LOG.error("error", th);
          account(1, 1);
        }
      }
    }

  }

  private final Mechanism encryptMechanism;

  private final byte[] dataToDecrypt;

  private final byte[] plainData;

  private final long key;

  protected abstract AttributeVector getMinimalKeyTemplate();

  public DecryptExecutor(String description, Mechanism keyGenMechanism,
                         Mechanism encryptMechanism, int inputLen) throws TokenException {
    super(description);
    this.encryptMechanism = encryptMechanism;
    this.plainData = TestBase.randomBytes(inputLen);

    byte[] id = new byte[20];
    new Random().nextBytes(id);
    // generate keypair on token
    AttributeVector keyTemplate = getMinimalKeyTemplate().sensitive(true).token(true)
        .id(id).encrypt(true).decrypt(true);

    PKCS11Token token = TestBase.getToken();
    key = token.generateKey(keyGenMechanism, keyTemplate);

    this.dataToDecrypt = token.encrypt(encryptMechanism, key, plainData);

  }

  @Override
  protected Runnable getTester() throws Exception {
    return new MyRunnable();
  }

  @Override
  public void close() {
    if (key != 0) {
      try {
        TestBase.getToken().destroyObject(key);
      } catch (Throwable th) {
        LOG.error("could not destroy generated objects", th);
      }
    }

    super.close();
  }

}
