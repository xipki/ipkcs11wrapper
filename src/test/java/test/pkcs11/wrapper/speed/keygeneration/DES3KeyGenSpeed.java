// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.wrapper.speed.keygeneration;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.pkcs11.wrapper.AttributeVector;
import org.xipki.pkcs11.wrapper.PKCS11Exception;
import org.xipki.pkcs11.wrapper.PKCS11Token;
import test.pkcs11.wrapper.TestBase;

import static org.xipki.pkcs11.wrapper.PKCS11Constants.*;

/**
 * TripleDES speed test.
 */
public class DES3KeyGenSpeed extends TestBase {

  private class MyExecutor extends KeyGenExecutor {

    public MyExecutor(boolean inToken) throws PKCS11Exception {
      super(mechanism, 0, inToken);
    }

    @Override
    protected AttributeVector getMinimalKeyTemplate() {
      return newSecretKey(CKK_DES3);
    }

  }

  private static final long mechanism = CKM_DES3_KEY_GEN;

  @Test
  public void main() throws PKCS11Exception {
    PKCS11Token token = getToken();
    if (!token.supportsMechanism(mechanism, CKF_GENERATE)) {
      System.out.println(ckmCodeToName(mechanism) + " is not supported, skip test");
      return;
    }

    boolean[] inTokens = new boolean[] {false, true};
    for (boolean inToken : inTokens) {
      MyExecutor executor = new MyExecutor(inToken);
      executor.setThreads(getSpeedTestThreads());
      executor.setDuration(getSpeedTestDuration());
      executor.execute();
      Assert.assertEquals("no error", 0, executor.getErrorAccount());
    }
  }

}
