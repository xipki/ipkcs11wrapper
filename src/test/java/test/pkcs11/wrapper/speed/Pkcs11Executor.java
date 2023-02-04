// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.wrapper.speed;

import test.pkcs11.wrapper.util.Util;
import org.slf4j.Logger;
import org.xipki.pkcs11.wrapper.PKCS11Exception;
import org.xipki.pkcs11.wrapper.Session;
import org.xipki.pkcs11.wrapper.Token;
import org.xipki.util.BenchmarkExecutor;
import org.xipki.util.concurrent.ConcurrentBag;

import java.util.concurrent.TimeUnit;

/**
 * Benchmark executor base class.
 */
public abstract class Pkcs11Executor extends BenchmarkExecutor {

  private final ConcurrentBag<ConcurrentSessionBagEntry> sessions = new ConcurrentBag<>();

  protected Pkcs11Executor(String description, Token token, char[] pin) throws PKCS11Exception {
    super(description);

    for (int i = 0; i < 5; i++) {
      Session session = Util.openAuthorizedSession(token, true, pin);
      sessions.add(new ConcurrentSessionBagEntry(session));
    }
  }

  protected ConcurrentSessionBagEntry borrowSession() {
    ConcurrentSessionBagEntry signer = null;
    try {
      signer = sessions.borrow(1000, TimeUnit.MILLISECONDS);
    } catch (InterruptedException ex) {
    }

    if (signer == null) {
      throw new IllegalStateException("no idle session available");
    }

    return signer;
  }

  protected void requiteSession(ConcurrentSessionBagEntry session) {
    sessions.requite(session);
  }

  @Override
  protected Runnable getTestor() throws Exception {
    return null;
  }

  @Override
  public void close() {
    ConcurrentSessionBagEntry session;
    try {
      session = sessions.borrow(10, TimeUnit.MILLISECONDS);
      session.value().closeSession();
    } catch (InterruptedException | PKCS11Exception ex) {
    } finally {
      super.close();
    }
  }

  protected static void destroyObject(Logger logger, Session session, long objectHandle) {
    try {
      session.destroyObject(objectHandle);
    } catch (PKCS11Exception ex) {
      logger.error("could not destroy key " + objectHandle);
    }
  }

}
