// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.wrapper.speed.signature;

import junit.framework.Assert;
import org.junit.Test;
import org.xipki.pkcs11.wrapper.*;
import org.xipki.util.BenchmarkExecutor;
import test.pkcs11.wrapper.TestBase;

import static org.xipki.pkcs11.wrapper.PKCS11Constants.*;

/**
 * ECDSA sign / verify speed test.
 */
public class ECDSASignVerifySpeed extends TestBase {

  private class MySignExecutor extends SignExecutor {

    public MySignExecutor() throws TokenException {
      super(ckmCodeToName(signMechanism) + " (NIST P-256) Sign Speed",
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
      super(ckmCodeToName(signMechanism) + " (NIST P-256) Verify Speed",
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

  private static final long keypairGenMechanism = CKM_EC_KEY_PAIR_GEN;

  private static final long signMechanism = CKM_ECDSA;

  private AttributeVector getMinimalPrivateKeyTemplate0() {
    return newPrivateKey(CKK_EC);
  }

  private AttributeVector getMinimalPublicKeyTemplate0() {
    // set the general attributes for the public key
    // OID: 1.2.840.10045.3.1.7 (secp256r1, alias NIST P-256)
    byte[] encodedCurveOid = new byte[] {0x06, 0x08, 0x2a, (byte) 0x86, 0x48, (byte) 0xce, 0x3d, 0x03, 0x01, 0x07};
    return newPublicKey(CKK_EC).ecParams(encodedCurveOid);
  }

  @Test
  public void main() throws TokenException {
    PKCS11Token token = getToken();
    if (!token.supportsMechanism(keypairGenMechanism, CKF_GENERATE_KEY_PAIR)) {
      System.out.println(ckmCodeToName(keypairGenMechanism) + " is not supported, skip test");
      return;
    }

    if (!token.supportsMechanism(signMechanism, CKF_ENCRYPT)) {
      System.out.println(ckmCodeToName(signMechanism) + " is not supported, skip test");
      return;
    }

    BenchmarkExecutor executor = new MySignExecutor();
    executor.setThreads(getSpeedTestThreads());
    executor.setDuration(getSpeedTestDuration());
    executor.execute();
    Assert.assertEquals("Sign speed", 0, executor.getErrorAccout());

    executor = new MyVerifyExecutor();
    executor.setThreads(getSpeedTestThreads());
    executor.setDuration(getSpeedTestDuration());
    executor.execute();
    Assert.assertEquals("Verify speed", 0, executor.getErrorAccout());
  }

}
