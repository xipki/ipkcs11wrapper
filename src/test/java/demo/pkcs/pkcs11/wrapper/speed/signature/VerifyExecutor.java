// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package demo.pkcs.pkcs11.wrapper.speed.signature;

import demo.pkcs.pkcs11.wrapper.TestBase;
import demo.pkcs.pkcs11.wrapper.speed.ConcurrentSessionBagEntry;
import demo.pkcs.pkcs11.wrapper.speed.Pkcs11Executor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.pkcs11.*;

import java.util.Random;

/**
 * Verify executor base class.
 */

public abstract class VerifyExecutor extends Pkcs11Executor {

  private static final Logger LOG = LoggerFactory.getLogger(VerifyExecutor.class);

  public class MyRunnable implements Runnable {

    public MyRunnable() {
    }

    @Override
    public void run() {
      while (!stop()) {
        try {
          ConcurrentSessionBagEntry sessionBag = borrowSession();
          try {
            Session session = sessionBag.value();
            // initialize for signing
            session.verifyInit(signMechanism, keypair.getPublicKey());
            // This signing operation is implemented in most of the drivers
            session.verify(dataToVerify, signatureToVerify);
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

  private final PKCS11KeyPair keypair;

  private final byte[] dataToVerify;

  private final byte[] signatureToVerify;

  public VerifyExecutor(String description, Mechanism keypairGenMechanism,
      Token token, char[] pin, Mechanism signMechanism, int inputLen) throws PKCS11Exception {
    super(description, token, pin);
    this.signMechanism = signMechanism;

    // generate keypair on token

    byte[] id = new byte[20];
    new Random().nextBytes(id);

    KeyPairTemplate template = new KeyPairTemplate(getMinimalPrivateKeyTemplate(), getMinimalPublicKeyTemplate());
    template.token(true).id(id).signVerify(true);
    template.privateKey().sensitive(true).private_(true);

    ConcurrentSessionBagEntry sessionBag = borrowSession();
    try {
      Session session = sessionBag.value();
      keypair = session.generateKeyPair(keypairGenMechanism, template);

      dataToVerify = TestBase.randomBytes(inputLen);
      // initialize for signing
      session.signInit(signMechanism, keypair.getPrivateKey());
      // This signing operation is implemented in most of the drivers
      signatureToVerify = session.sign(dataToVerify);
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
