// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.wrapper.speed.encryption;

import test.pkcs11.wrapper.TestBase;
import test.pkcs11.wrapper.speed.ConcurrentSessionBagEntry;
import test.pkcs11.wrapper.speed.Pkcs11Executor;
import org.junit.Assert;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.pkcs11.wrapper.*;

import java.util.Arrays;
import java.util.Random;

/**
 * Decryptor executor base class.
 */
public abstract class DecryptExecutor extends Pkcs11Executor {

  private static final Logger LOG = LoggerFactory.getLogger(DecryptExecutor.class);

  public class MyRunnable implements Runnable {

    public MyRunnable() {
    }

    private final byte[] out = new byte[plainData.length + 64];

    @Override
    public void run() {
      while (!stop()) {
        try {
          ConcurrentSessionBagEntry sessionBag = borrowSession();
          try {
            Session session = sessionBag.value();
            // initialize for signing
            session.decryptInit(encryptMechanism, key);
            // This signing operation is implemented in most of the drivers
            int len = session.decrypt(dataToDecrypt, 0, dataToDecrypt.length, out, 0, out.length);
            byte[] decryptedData = Arrays.copyOf(out, len);
            Assert.assertArrayEquals(plainData, decryptedData);
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

  private final byte[] dataToDecrypt;

  private final byte[] plainData;

  private final long key;

  protected abstract AttributeVector getMinimalKeyTemplate();

  public DecryptExecutor(String description, Mechanism keyGenMechanism,
                         Token token, char[] pin, Mechanism encryptMechanism, int inputLen) throws PKCS11Exception {
    super(description, token, pin);
    this.encryptMechanism = encryptMechanism;
    this.plainData = TestBase.randomBytes(inputLen);

    byte[] id = new byte[20];
    new Random().nextBytes(id);
    // generate keypair on token
    AttributeVector keyTemplate = getMinimalKeyTemplate().sensitive(true).token(true)
        .id(id).encrypt(true).decrypt(true);

    ConcurrentSessionBagEntry sessionBag = borrowSession();
    try {
      Session session = sessionBag.value();
      key = session.generateKey(keyGenMechanism, keyTemplate);

      session.encryptInit(encryptMechanism, key);
      byte[] buffer = new byte[inputLen + 64];
      int len = session.encrypt(plainData, 0, inputLen, buffer, 0, buffer.length);
      this.dataToDecrypt = Arrays.copyOf(buffer, len);
    } finally {
      requiteSession(sessionBag);
    }

  }

  @Override
  protected Runnable getTestor() throws Exception {
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
