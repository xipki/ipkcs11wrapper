// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.wrapper.speed.keygeneration;

import test.pkcs11.wrapper.TestBase;
import test.pkcs11.wrapper.util.Util;
import junit.framework.Assert;
import org.junit.Test;
import org.xipki.pkcs11.wrapper.AttributeVector;
import org.xipki.pkcs11.wrapper.PKCS11Exception;
import org.xipki.pkcs11.wrapper.Token;

import static org.xipki.pkcs11.wrapper.PKCS11Constants.*;

/**
 * TripleDES speed test.
 */
public class DES3KeyGenSpeed extends TestBase {

  private class MyExecutor extends KeyGenExecutor {

    public MyExecutor(Token token, char[] pin, boolean inToken) throws PKCS11Exception {
      super(mechanism, 0, token, pin, inToken);
    }

    @Override
    protected AttributeVector getMinimalKeyTemplate() {
      return newSecretKey(CKK_DES3);
    }

  }

  private static final long mechanism = CKM_DES3_KEY_GEN;

  @Test
  public void main() throws PKCS11Exception {
    Token token = getNonNullToken();
    if (!Util.supports(token, mechanism)) {
      System.out.println(ckmCodeToName(mechanism) + " is not supported, skip test");
      return;
    }

    boolean[] inTokens = new boolean[] {false, true};
    for (boolean inToken : inTokens) {
      MyExecutor executor = new MyExecutor(token, getModulePin(), inToken);
      executor.setThreads(getSpeedTestThreads());
      executor.setDuration(getSpeedTestDuration());
      executor.execute();
      Assert.assertEquals("no error", 0, executor.getErrorAccout());
    }
  }

}
