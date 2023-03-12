// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.wrapper.speed.encryption;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.pkcs11.wrapper.*;
import test.pkcs11.wrapper.TestBase;
import test.pkcs11.wrapper.speed.Pkcs11Executor;

import java.util.Random;

/**
 * Encrypt executor base.
 */
public abstract class EncryptExecutor extends Pkcs11Executor {

  private static final Logger LOG = LoggerFactory.getLogger(EncryptExecutor.class);

  protected final PKCS11Token token;

  public class MyRunnable implements Runnable {

    public MyRunnable() {
    }

    private final byte[] out = new byte[inputLen + 64];

    @Override
    public void run() {
      while (!stop()) {
        try {
          byte[] data = TestBase.randomBytes(inputLen);
          token.encrypt(encryptMechanism, key, data);
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

  private final int inputLen;

  private final long key;

  protected abstract AttributeVector getMinimalKeyTemplate();

  public EncryptExecutor(String description, Mechanism keyGenMechanism,
                         Mechanism encryptMechanism, int inputLen)
          throws TokenException {
    super(description);
    this.encryptMechanism = encryptMechanism;
    this.inputLen = inputLen;

    byte[] id = new byte[20];
    new Random().nextBytes(id);

    // generate keypair on token
    AttributeVector keyTemplate = getMinimalKeyTemplate()
        .sensitive(true).token(true).id(id).encrypt(true).decrypt(true);

    token = TestBase.getToken();
    key = token.generateKey(keyGenMechanism, keyTemplate);
  }

  @Override
  protected Runnable getTestor() {
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
