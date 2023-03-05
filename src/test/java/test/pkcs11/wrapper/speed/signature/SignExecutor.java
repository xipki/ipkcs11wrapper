// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.wrapper.speed.signature;

import test.pkcs11.wrapper.TestBase;
import test.pkcs11.wrapper.speed.ConcurrentSessionBagEntry;
import test.pkcs11.wrapper.speed.Pkcs11Executor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.pkcs11.wrapper.*;

import java.util.Random;

/**
 * Sign executor base class.
 */
public abstract class SignExecutor extends Pkcs11Executor {

  private static final Logger LOG = LoggerFactory.getLogger(SignExecutor.class);

  public class MyRunnable implements Runnable {

    public MyRunnable() {
    }

    @Override
    public void run() {
      while (!stop()) {
        try {
          byte[] data = TestBase.randomBytes(inputLen);

          ConcurrentSessionBagEntry sessionBag = borrowSession();
          try {
            sessionBag.value().signSingle(signMechanism, keypair.getPrivateKey(), data);
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

  private final Mechanism signMechanism;

  private final int inputLen;

  private final PKCS11KeyPair keypair;

  public SignExecutor(String description, Mechanism keypairGenMechanism,
                      Token token, char[] pin, Mechanism signMechanism, int inputLen)
          throws PKCS11Exception {
    super(description, token, pin);
    this.signMechanism = signMechanism;
    this.inputLen = inputLen;

    byte[] id = new byte[20];
    new Random().nextBytes(id);

    KeyPairTemplate template = new KeyPairTemplate(getMinimalPrivateKeyTemplate(), getMinimalPublicKeyTemplate());
    template.token(true).id(id).signVerify(true);
    template.privateKey().sensitive(true).private_(true);

    // generate keypair on token
    ConcurrentSessionBagEntry sessionBag = borrowSession();
    try {
      Session session = sessionBag.value();
      keypair = session.generateKeyPair(keypairGenMechanism, template);
    } finally {
      requiteSession(sessionBag);
    }

  }

  protected abstract AttributeVector getMinimalPrivateKeyTemplate();

  protected abstract AttributeVector getMinimalPublicKeyTemplate();

  @Override
  protected Runnable getTestor() {
    return new MyRunnable();
  }

  @Override
  public void close() {
    if (keypair != null) {
      ConcurrentSessionBagEntry sessionBag = borrowSession();
      try {
        Session session = sessionBag.value();
        session.destroyObject(keypair.getPrivateKey());
        session.destroyObject(keypair.getPublicKey());
      } catch (Throwable th) {
        LOG.error("could not destroy generated objects", th);
      } finally {
        requiteSession(sessionBag);
      }
    }

    super.close();
  }

}
