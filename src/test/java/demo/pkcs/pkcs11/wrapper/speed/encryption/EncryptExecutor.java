// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package demo.pkcs.pkcs11.wrapper.speed.encryption;

import demo.pkcs.pkcs11.wrapper.TestBase;
import demo.pkcs.pkcs11.wrapper.speed.ConcurrentSessionBagEntry;
import demo.pkcs.pkcs11.wrapper.speed.Pkcs11Executor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.pkcs11.*;

import java.util.Random;

/**
 * Encrypt executor base.
 */
public abstract class EncryptExecutor extends Pkcs11Executor {

  private static final Logger LOG = LoggerFactory.getLogger(EncryptExecutor.class);

  public class MyRunnable implements Runnable {

    public MyRunnable() {
    }

    private final byte[] out = new byte[inputLen + 64];

    @Override
    public void run() {
      while (!stop()) {
        try {
          byte[] data = TestBase.randomBytes(inputLen);

          ConcurrentSessionBagEntry sessionBag = borrowSession();
          try {
            Session session = sessionBag.value();
            // initialize for signing
            session.encryptInit(encryptMechanism, key);
            // This signing operation is implemented in most of the drivers
            session.encrypt(data, 0, inputLen, out, 0, out.length);
          } finally {
            requiteSession(sessionBag);
          }

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
      Token token, char[] pin, Mechanism encryptMechanism, int inputLen)
          throws PKCS11Exception {
    super(description, token, pin);
    this.encryptMechanism = encryptMechanism;
    this.inputLen = inputLen;

    byte[] id = new byte[20];
    new Random().nextBytes(id);

    // generate keypair on token
    AttributeVector keyTemplate = getMinimalKeyTemplate()
        .sensitive(true).token(true).id(id).encrypt(true).decrypt(true);

    ConcurrentSessionBagEntry sessionBag = borrowSession();
    try {
      Session session = sessionBag.value();
      key = session.generateKey(keyGenMechanism, keyTemplate);
    } finally {
      requiteSession(sessionBag);
    }

  }

  @Override
  protected Runnable getTestor() {
    return new MyRunnable();
  }

  @Override
  public void close() {
    if (key != 0) {
      ConcurrentSessionBagEntry sessionBag = borrowSession();
      try {
        Session session = sessionBag.value();
        session.destroyObject(key);
      } catch (Throwable th) {
        LOG.error("could not destroy generated objects", th);
      } finally {
        requiteSession(sessionBag);
      }
    }

    super.close();
  }

}
