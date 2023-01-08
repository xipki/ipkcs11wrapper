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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.pkcs11.*;

import java.util.Random;

/**
 * Secret key generation executor base class.
 *
 * @author Lijun Liao
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
      .append(Functions.ckmCodeToName(mechanism)).append(" (");
    if (keyLen > 0) {
      sb.append(keyLen * 8).append(" bits, ");
    }

    sb.append("inToken: ").append(inToken).append(") Speed");
    return sb.toString();
  }

}
