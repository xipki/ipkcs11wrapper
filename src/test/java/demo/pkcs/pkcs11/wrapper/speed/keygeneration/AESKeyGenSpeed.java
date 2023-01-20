// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package demo.pkcs.pkcs11.wrapper.speed.keygeneration;

import demo.pkcs.pkcs11.wrapper.TestBase;
import demo.pkcs.pkcs11.wrapper.util.Util;
import junit.framework.Assert;
import org.junit.Test;
import org.xipki.pkcs11.AttributeVector;
import org.xipki.pkcs11.PKCS11Exception;
import org.xipki.pkcs11.Token;

import static org.xipki.pkcs11.PKCS11Constants.*;

/**
 * AES speed test base class.
 */
public abstract class AESKeyGenSpeed extends TestBase {

  private class MyExecutor extends KeyGenExecutor {

    public MyExecutor(Token token, char[] pin, boolean inToken) throws PKCS11Exception {
      super(mechanism, getKeyByteLen(), token, pin, inToken);
    }

    @Override
    protected AttributeVector getMinimalKeyTemplate() {
      return newSecretKey(CKK_AES).valueLen(getKeyByteLen());
    }

  }

  private static final long mechanism = CKM_AES_KEY_GEN;

  protected abstract int getKeyByteLen();

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
