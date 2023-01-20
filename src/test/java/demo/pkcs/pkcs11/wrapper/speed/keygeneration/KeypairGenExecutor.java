// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package demo.pkcs.pkcs11.wrapper.speed.keygeneration;

import demo.pkcs.pkcs11.wrapper.speed.ConcurrentSessionBagEntry;
import demo.pkcs.pkcs11.wrapper.speed.Pkcs11Executor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.pkcs11.*;

import java.util.Random;

import static org.xipki.pkcs11.PKCS11Constants.CKA_ID;

/**
 * Keypair generation executor base class.
 */
public abstract class KeypairGenExecutor extends Pkcs11Executor {

  private static final Logger LOG = LoggerFactory.getLogger(KeypairGenExecutor.class);

  public class MyRunnable implements Runnable {

    public MyRunnable() {
    }

    @Override
    public void run() {
      while (!stop()) {
        try {
          // generate keypair on token
          AttributeVector publicKeyTemplate = getMinimalPublicKeyTemplate().token(inToken).verify(true);

          AttributeVector privateKeyTemplate = getMinimalPrivateKeyTemplate().sensitive(true)
                  .private_(true).token(inToken).sign(true);

          if (inToken) {
            byte[] id = new byte[20];
            new Random().nextBytes(id);
            publicKeyTemplate.attr(CKA_ID, id);
            privateKeyTemplate.attr(CKA_ID, id);
          }

          ConcurrentSessionBagEntry sessionBag = borrowSession();
          PKCS11KeyPair keypair;
          try {
            Session session = sessionBag.value();
            keypair = session.generateKeyPair(mechanism, publicKeyTemplate, privateKeyTemplate);
            destroyObject(LOG, session, keypair.getPrivateKey());
            destroyObject(LOG, session, keypair.getPublicKey());
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

  public KeypairGenExecutor(String description, long mechnism, Token token, char[] pin, boolean inToken)
      throws PKCS11Exception {
    super(description, token, pin);
    this.mechanism = new Mechanism(mechnism);
    this.inToken = inToken;
  }

  protected abstract AttributeVector getMinimalPrivateKeyTemplate();

  protected abstract AttributeVector getMinimalPublicKeyTemplate();

  @Override
  protected Runnable getTestor() {
    return new MyRunnable();
  }

}
