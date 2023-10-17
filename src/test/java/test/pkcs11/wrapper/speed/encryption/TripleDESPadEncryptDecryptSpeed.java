// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.
//
// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.wrapper.speed.encryption;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.pkcs11.wrapper.*;
import org.xipki.pkcs11.wrapper.params.ByteArrayParams;
import org.xipki.util.BenchmarkExecutor;
import test.pkcs11.wrapper.TestBase;

import static org.xipki.pkcs11.wrapper.PKCS11Constants.*;

/**
 * This demo program uses a PKCS#11 module to encrypt and decrypt via
 * CKM_AES_CBC_PAD.
 */
public class TripleDESPadEncryptDecryptSpeed extends TestBase {

  private class MyEncryptExecutor extends EncryptExecutor {

    public MyEncryptExecutor() throws TokenException {
      super(ckmCodeToName(encryptMechanism) + " Encrypt Speed",
          getKeyGenMech(), getEncryptionMech(), inputLen);
    }

    @Override
    protected AttributeVector getMinimalKeyTemplate() {
      return getMinimalKeyTemplate0();
    }

  }

  private class MyDecryptExecutor extends DecryptExecutor {

    public MyDecryptExecutor() throws TokenException {
      super(ckmCodeToName(encryptMechanism) + " Decrypt Speed",
          getKeyGenMech(), getEncryptionMech(), inputLen);
    }

    @Override
    protected AttributeVector getMinimalKeyTemplate() {
      return getMinimalKeyTemplate0();
    }

  }

  private static final long keyGenMechanism = CKM_DES3_KEY_GEN;

  private static final long encryptMechanism = CKM_DES3_CBC_PAD;

  private static final int inputLen = 1024;

  private static final String inputUnit = "KiB";

  private final byte[] iv;

  public TripleDESPadEncryptDecryptSpeed() {
    iv = randomBytes(8);
  }

  private Mechanism getKeyGenMech() throws PKCS11Exception {
    return getSupportedMechanism(keyGenMechanism, CKF_GENERATE);
  }

  private Mechanism getEncryptionMech() throws PKCS11Exception {
    return getSupportedMechanism(encryptMechanism, CKF_ENCRYPT, new ByteArrayParams(iv));
  }

  private AttributeVector getMinimalKeyTemplate0() {
    return newSecretKey(CKK_DES3);
  }

  @Test
  public void main() throws TokenException {
    PKCS11Token token = getToken();
    if (!token.supportsMechanism(keyGenMechanism, CKF_GENERATE)) {
      System.out.println(ckmCodeToName(keyGenMechanism) + " is not supported, skip test");
      return;
    }

    if (!token.supportsMechanism(encryptMechanism, CKF_ENCRYPT)) {
      System.out.println(ckmCodeToName(encryptMechanism) + " is not supported, skip test");
      return;
    }

    BenchmarkExecutor executor = new MyEncryptExecutor();
    executor.setThreads(getSpeedTestThreads());
    executor.setDuration(getSpeedTestDuration());
    executor.setUnit(inputUnit);
    executor.execute();
    Assert.assertEquals("Encrypt speed", 0, executor.getErrorAccount());

    executor = new MyDecryptExecutor();
    executor.setThreads(getSpeedTestThreads());
    executor.setDuration(getSpeedTestDuration());
    executor.setUnit(inputUnit);
    executor.execute();
    Assert.assertEquals("Decrypt speed", 0, executor.getErrorAccount());
  }

}
