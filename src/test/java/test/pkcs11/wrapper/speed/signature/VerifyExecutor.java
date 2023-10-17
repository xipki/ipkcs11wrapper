// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.wrapper.speed.signature;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.pkcs11.wrapper.*;
import test.pkcs11.wrapper.TestBase;
import test.pkcs11.wrapper.speed.Pkcs11Executor;

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
          TestBase.getToken().verify(signMechanism, keypair.getPublicKey(), dataToVerify, signatureToVerify);
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
                        Mechanism signMechanism, int inputLen) throws TokenException {
    super(description);
    this.signMechanism = signMechanism;

    // generate keypair on token

    byte[] id = new byte[20];
    new Random().nextBytes(id);

    KeyPairTemplate template = new KeyPairTemplate(getMinimalPrivateKeyTemplate(), getMinimalPublicKeyTemplate());
    template.token(true).id(id).signVerify(true);
    template.privateKey().sensitive(true).private_(true);

    PKCS11Token token = TestBase.getToken();
    keypair = token.generateKeyPair(keypairGenMechanism, template);

    dataToVerify = TestBase.randomBytes(inputLen);
    signatureToVerify = token.sign(signMechanism, keypair.getPrivateKey(), dataToVerify);
  }

  protected abstract AttributeVector getMinimalPrivateKeyTemplate();

  protected abstract AttributeVector getMinimalPublicKeyTemplate();

  @Override
  protected Runnable getTester() {
    return new MyRunnable();
  }

  @Override
  public void close() {
    if (keypair != null) {
      try {
        PKCS11Token token = TestBase.getToken();
        token.destroyObject(keypair.getPrivateKey());
        token.destroyObject(keypair.getPublicKey());
      } catch (Throwable th) {
        LOG.error("could not destroy generated objects", th);
      }
    }

    super.close();
  }

}
