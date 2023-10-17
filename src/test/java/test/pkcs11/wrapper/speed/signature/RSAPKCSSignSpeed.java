// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.wrapper.speed.signature;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.pkcs11.wrapper.AttributeVector;
import org.xipki.pkcs11.wrapper.Mechanism;
import org.xipki.pkcs11.wrapper.PKCS11Token;
import org.xipki.pkcs11.wrapper.TokenException;
import org.xipki.util.BenchmarkExecutor;
import test.pkcs11.wrapper.TestBase;

import static org.xipki.pkcs11.wrapper.PKCS11Constants.*;

/**
 * RSA/PKCS1v1.5 sign / verify speed test.
 */
public class RSAPKCSSignSpeed extends TestBase {

  private class MySignExecutor extends SignExecutor {

    public MySignExecutor() throws TokenException {
      super(ckmCodeToName(signMechanism) + " (2048) Sign Speed",
          new Mechanism(keypairGenMechanism), new Mechanism(signMechanism), 32);
    }

    @Override
    protected AttributeVector getMinimalPrivateKeyTemplate() {
      return getMinimalPrivateKeyTemplate0();
    }

    @Override
    protected AttributeVector getMinimalPublicKeyTemplate() {
      return getMinimalPublicKeyTemplate0();
    }

  }

  private class MyVerifyExecutor extends VerifyExecutor {

    public MyVerifyExecutor() throws TokenException {
      super(ckmCodeToName(signMechanism) + " (2048) Verify Speed",
          new Mechanism(keypairGenMechanism), new Mechanism(signMechanism), 32);
    }

    @Override
    protected AttributeVector getMinimalPrivateKeyTemplate() {
      return getMinimalPrivateKeyTemplate0();
    }

    @Override
    protected AttributeVector getMinimalPublicKeyTemplate() {
      return getMinimalPublicKeyTemplate0();
    }

  }

  private static final long keypairGenMechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;

  private static final long signMechanism = CKM_RSA_PKCS;

  private AttributeVector getMinimalPrivateKeyTemplate0() {
    return newPrivateKey(CKK_RSA);
  }

  private AttributeVector getMinimalPublicKeyTemplate0() {
    return newPublicKey(CKK_RSA).attr(CKA_MODULUS_BITS, 2048);
  }

  @Test
  public void main() throws TokenException {
    PKCS11Token token = getToken();
    if (!token.supportsMechanism(keypairGenMechanism, CKF_GENERATE_KEY_PAIR)) {
      System.out.println(ckmCodeToName(keypairGenMechanism) + " is not supported, skip test");
      return;
    }

    if (!token.supportsMechanism(signMechanism, CKF_SIGN)) {
      System.out.println(ckmCodeToName(signMechanism) + " is not supported, skip test");
      return;
    }

    BenchmarkExecutor executor = new MySignExecutor();
    executor.setThreads(getSpeedTestThreads());
    executor.setDuration(getSpeedTestDuration());
    executor.execute();
    Assert.assertEquals("Sign speed", 0, executor.getErrorAccount());

    executor = new MyVerifyExecutor();
    executor.setThreads(getSpeedTestThreads());
    executor.setDuration(getSpeedTestDuration());
    executor.execute();
    Assert.assertEquals("Verify speed", 0, executor.getErrorAccount());
  }

}
