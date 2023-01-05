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

package demo.pkcs.pkcs11.wrapper.speed.keygeneration;

import demo.pkcs.pkcs11.wrapper.speed.ConcurrentSessionBagEntry;
import demo.pkcs.pkcs11.wrapper.speed.Pkcs11Executor;
import org.xipki.pkcs11.Mechanism;
import org.xipki.pkcs11.Session;
import org.xipki.pkcs11.Token;
import org.xipki.pkcs11.TokenException;
import org.xipki.pkcs11.objects.AttributeVector;
import org.xipki.pkcs11.objects.KeyPair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Random;

import static org.xipki.pkcs11.PKCS11Constants.*;

/**
 * Keypair generation executor base class.
 *
 * @author Lijun Liao
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
          KeyPair keypair;
          try {
            Session session = sessionBag.value();
            keypair = session.generateKeyPair(mechanism, publicKeyTemplate, privateKeyTemplate);
            session.destroyObject(keypair.getPrivateKey());
            session.destroyObject(keypair.getPublicKey());
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
      throws TokenException {
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
