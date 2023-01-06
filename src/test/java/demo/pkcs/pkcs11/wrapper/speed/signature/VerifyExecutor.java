/*
 *
 * Copyright (c) 2019 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package demo.pkcs.pkcs11.wrapper.speed.signature;

import demo.pkcs.pkcs11.wrapper.TestBase;
import demo.pkcs.pkcs11.wrapper.speed.ConcurrentSessionBagEntry;
import demo.pkcs.pkcs11.wrapper.speed.Pkcs11Executor;
import org.xipki.pkcs11.Mechanism;
import org.xipki.pkcs11.Session;
import org.xipki.pkcs11.Token;
import org.xipki.pkcs11.PKCS11Exception;
import org.xipki.pkcs11.objects.AttributeVector;
import org.xipki.pkcs11.objects.KeyPair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Random;

/**
 * Verify executor base class.
 *
 * @author Lijun Liao
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

  private final KeyPair keypair;

  private final byte[] dataToVerify;

  private final byte[] signatureToVerify;

  public VerifyExecutor(String description, Mechanism keypairGenMechanism,
      Token token, char[] pin, Mechanism signMechanism, int inputLen) throws PKCS11Exception {
    super(description, token, pin);
    this.signMechanism = signMechanism;

    // generate keypair on token

    byte[] id = new byte[20];
    new Random().nextBytes(id);

    AttributeVector publicKeyTemplate = getMinimalPublicKeyTemplate().token(true).id(id).verify(true);

    AttributeVector privateKeyTemplate = getMinimalPrivateKeyTemplate()
        .sensitive(true).private_(true).token(true).id(id).sign(true);

    ConcurrentSessionBagEntry sessionBag = borrowSession();
    try {
      Session session = sessionBag.value();
      keypair = session.generateKeyPair(keypairGenMechanism, publicKeyTemplate, privateKeyTemplate);

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
