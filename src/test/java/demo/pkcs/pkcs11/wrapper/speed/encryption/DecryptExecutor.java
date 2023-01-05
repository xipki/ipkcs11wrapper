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

package demo.pkcs.pkcs11.wrapper.speed.encryption;

import demo.pkcs.pkcs11.wrapper.TestBase;
import demo.pkcs.pkcs11.wrapper.speed.ConcurrentSessionBagEntry;
import demo.pkcs.pkcs11.wrapper.speed.Pkcs11Executor;
import org.xipki.pkcs11.Mechanism;
import org.xipki.pkcs11.Session;
import org.xipki.pkcs11.Token;
import org.xipki.pkcs11.TokenException;
import org.xipki.pkcs11.objects.AttributeVector;
import org.junit.Assert;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Random;

/**
 * Decryptor executor base class.
 *
 * @author Lijun Liao
 */
public abstract class DecryptExecutor extends Pkcs11Executor {

  private static final Logger LOG = LoggerFactory.getLogger(DecryptExecutor.class);

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
            session.decryptInit(encryptMechanism, key);
            // This signing operation is implemented in most of the drivers
            byte[] decryptedData = session.decrypt(dataToDecrypt);
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
      Token token, char[] pin, Mechanism encryptMechanism, int inputLen) throws TokenException {
    super(description, token, pin);
    this.encryptMechanism = encryptMechanism;
    this.plainData = TestBase.randomBytes(inputLen);

    byte[] id = new byte[20];
    new Random().nextBytes(id);
    // generate keypair on token
    AttributeVector keyTemplate = getMinimalKeyTemplate()
        .sensitive(true).token(true).id(id).encrypt(true).decrypt(true);

    ConcurrentSessionBagEntry sessionBag = borrowSession();
    try {
      Session session = sessionBag.value();
      key = session.generateKey(keyGenMechanism, keyTemplate);

      session.encryptInit(encryptMechanism, key);
      this.dataToDecrypt = session.encrypt(plainData);
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
