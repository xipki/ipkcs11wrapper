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
 * EDDSA Keypair Generation Speed Test
 */
public class RSAKeypairGenSpeed extends TestBase {

  private class MyExecutor extends KeypairGenExecutor {

    public MyExecutor(boolean inToken) throws PKCS11Exception {
      super(ckmCodeToName(mechanism) + " (2048, inToken: " + inToken + ") Speed",
          mechanism, inToken);
    }

    @Override
    protected AttributeVector getMinimalPrivateKeyTemplate() {
      return newPrivateKey(CKK_RSA);
    }

    @Override
    protected AttributeVector getMinimalPublicKeyTemplate() {
      return newPublicKey(CKK_RSA).attr(CKA_MODULUS_BITS, 2048);
    }

  }

  private static final long mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;

  @Test
  public void main() throws PKCS11Exception {
    PKCS11Token token = getToken();
    if (!token.supportsMechanism(mechanism, CKF_GENERATE_KEY_PAIR)) {
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
