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
 * EDDSA sign / verify speed test.
 */
public class EDDSASignVerifySpeed extends TestBase {

  private class MySignExecutor extends SignExecutor {

    public MySignExecutor() throws TokenException {
      super(ckmCodeToName(signMechanism) + " (Ed25519) Sign Speed",
          new Mechanism(keypairGenMechanism), new Mechanism(signMechanism), 107);
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
      super(ckmCodeToName(signMechanism) + " (Ed25519) Verify Speed",
          new Mechanism(keypairGenMechanism), new Mechanism(signMechanism), 107);
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

  private static final long keypairGenMechanism = CKM_EC_EDWARDS_KEY_PAIR_GEN;

  private static final long signMechanism = CKM_EDDSA;

  private AttributeVector getMinimalPrivateKeyTemplate0() {
    return newPrivateKey(CKK_EC_EDWARDS);
  }

  private AttributeVector getMinimalPublicKeyTemplate0() {
    // set the general attributes for the public key
    // OID: 1.3.101.112 (Ed25519)
    byte[] encodedCurveOid = new byte[] {0x06, 0x03, 0x2b, 0x65, 0x70};
    return newPublicKey(CKK_EC_EDWARDS).ecParams(encodedCurveOid);
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
