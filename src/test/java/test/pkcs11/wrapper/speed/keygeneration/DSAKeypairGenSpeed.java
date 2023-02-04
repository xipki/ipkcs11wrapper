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
 * EDDSA Keypair Generation Speed Test
 */
public class DSAKeypairGenSpeed extends TestBase {

  private class MyExecutor extends KeypairGenExecutor {

    public MyExecutor(Token token, char[] pin, boolean inToken) throws PKCS11Exception {
      super(ckmCodeToName(mechanism) + " (P:2048, Q:256, inToken: " + inToken + ") Speed",
          mechanism, token, pin, inToken);
    }

    @Override
    protected AttributeVector getMinimalPrivateKeyTemplate() {
      return newPrivateKey(CKK_DSA);
    }

    @Override
    protected AttributeVector getMinimalPublicKeyTemplate() {
      return newPublicKey(CKK_DSA).prime(DSA_P).subprime(DSA_Q).base(DSA_G).token(false);
    }

  }

  private static final long mechanism = CKM_DSA_KEY_PAIR_GEN;

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
