// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.wrapper.speed;

import org.slf4j.Logger;
import org.xipki.pkcs11.wrapper.PKCS11Exception;
import org.xipki.pkcs11.wrapper.TokenException;
import org.xipki.util.BenchmarkExecutor;
import test.pkcs11.wrapper.TestBase;

/**
 * Benchmark executor base class.
 */
public abstract class Pkcs11Executor extends BenchmarkExecutor {

  protected Pkcs11Executor(String description) throws PKCS11Exception {
    super(description);
  }

  protected static void destroyObject(Logger logger, long objectHandle) {
    try {
      TestBase.getToken().destroyObject(objectHandle);
    } catch (TokenException ex) {
      logger.error("could not destroy key " + objectHandle);
    }
  }

}
