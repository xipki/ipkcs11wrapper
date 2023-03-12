// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.wrapper.speed.keygeneration;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.pkcs11.wrapper.*;
import test.pkcs11.wrapper.TestBase;
import test.pkcs11.wrapper.speed.Pkcs11Executor;

import java.util.Random;

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
          KeyPairTemplate template = new KeyPairTemplate(getMinimalPrivateKeyTemplate(), getMinimalPublicKeyTemplate());
          template.token(inToken).signVerify(true);
          template.privateKey().sensitive(true).private_(true);

          if (inToken) {
            byte[] id = new byte[20];
            new Random().nextBytes(id);
            template.id(id);
          }

          PKCS11KeyPair keypair = TestBase.getToken().generateKeyPair(mechanism, template);
          destroyObject(LOG, keypair.getPrivateKey());
          destroyObject(LOG, keypair.getPublicKey());

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

  public KeypairGenExecutor(String description, long mechnism, boolean inToken)
      throws PKCS11Exception {
    super(description);
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
