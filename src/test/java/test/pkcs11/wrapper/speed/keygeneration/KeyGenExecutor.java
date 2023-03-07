// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.wrapper.speed.keygeneration;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.pkcs11.wrapper.*;
import test.pkcs11.wrapper.speed.ConcurrentSessionBagEntry;
import test.pkcs11.wrapper.speed.Pkcs11Executor;

import java.util.Random;

import static org.xipki.pkcs11.wrapper.PKCS11Constants.ckmCodeToName;

/**
 * Secret key generation executor base class.
 */
public abstract class KeyGenExecutor extends Pkcs11Executor {

  private static final Logger LOG = LoggerFactory.getLogger(KeyGenExecutor.class);

  public class MyRunnable implements Runnable {

    public MyRunnable() {
    }

    @Override
    public void run() {
      while (!stop()) {
        try {
          // generate key on token
          AttributeVector secretKeyTemplate = getMinimalKeyTemplate()
              .token(inToken).sensitive(true).encrypt(true).decrypt(true);
          if (inToken) {
            byte[] id = new byte[20];
            new Random().nextBytes(id);
            secretKeyTemplate.id(id);
          }

          ConcurrentSessionBagEntry sessionBag = borrowSession();
          long key;
          try {
            Session session = sessionBag.value();
            key = session.generateKey(mechanism, secretKeyTemplate);
            destroyObject(LOG, session, key);
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

  private final Mechanism mechanism;

  private final boolean inToken;

  public KeyGenExecutor(long mechanism, int keyLen, Token token, char[] pin, boolean inToken) throws PKCS11Exception {
    super(describe(mechanism, keyLen, inToken), token, pin);
    this.mechanism = new Mechanism(mechanism);
    this.inToken = inToken;
  }

  protected abstract AttributeVector getMinimalKeyTemplate();

  @Override
  protected Runnable getTestor() {
    return new MyRunnable();
  }

  private static String describe(long mechanism, int keyLen, boolean inToken) {
    StringBuilder sb = new StringBuilder(100)
      .append(ckmCodeToName(mechanism)).append(" (");
    if (keyLen > 0) {
      sb.append(keyLen * 8).append(" bits, ");
    }

    sb.append("inToken: ").append(inToken).append(") Speed");
    return sb.toString();
  }

}
