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
          TestBase.getToken().sign(signMechanism, keypair.getPrivateKey(), data);
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
                      Mechanism signMechanism, int inputLen)
          throws TokenException {
    super(description);
    this.signMechanism = signMechanism;
    this.inputLen = inputLen;

    byte[] id = new byte[20];
    new Random().nextBytes(id);

    KeyPairTemplate template = new KeyPairTemplate(getMinimalPrivateKeyTemplate(), getMinimalPublicKeyTemplate());
    template.token(true).id(id).signVerify(true);
    template.privateKey().sensitive(true).private_(true);

    // generate keypair on token
    keypair = TestBase.getToken().generateKeyPair(keypairGenMechanism, template);
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
