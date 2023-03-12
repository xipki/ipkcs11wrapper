// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.wrapper.speed.encryption;

import junit.framework.Assert;
import org.junit.Test;
import org.xipki.pkcs11.wrapper.*;
import org.xipki.pkcs11.wrapper.params.GCM_PARAMS;
import org.xipki.util.BenchmarkExecutor;
import test.pkcs11.wrapper.TestBase;

import static org.xipki.pkcs11.wrapper.PKCS11Constants.*;

/**
 * This demo program uses a PKCS#11 module to encrypt and decrypt via
 * CKM_AES_CBC_PAD.
 */
public class AESGCMPadEncryptDecryptSpeed extends TestBase {

  private class MyEncryptExecutor extends EncryptExecutor {

    public MyEncryptExecutor() throws TokenException {
      super(ckmCodeToName(encryptMechanism) + " (" + keyLen + ") Encrypt Speed",
          getKeyGenMech(), getEncryptionMech(), inputLen);
    }

    @Override
    protected AttributeVector getMinimalKeyTemplate() {
      return getMinimalKeyTemplate0();
    }

  }

  private class MyDecryptExecutor extends DecryptExecutor {

    public MyDecryptExecutor() throws TokenException {
      super(ckmCodeToName(encryptMechanism) + " (" + keyLen + ") Decrypt Speed",
          getKeyGenMech(), getEncryptionMech(), inputLen);
    }

    @Override
    protected AttributeVector getMinimalKeyTemplate() {
      return getMinimalKeyTemplate0();
    }

  }

  private static final long keyGenMechanism = CKM_AES_KEY_GEN;

  private static final long encryptMechanism = CKM_AES_GCM;

  private static final int inputLen = 1024;

  private static final String inputUnit = "KiB";

  private static final int keyLen = 256;

  private final byte[] iv;

  private final byte[] aad;

  public AESGCMPadEncryptDecryptSpeed() {
    iv = randomBytes(12);
    aad = "hello".getBytes();
  }

  private Mechanism getKeyGenMech() throws PKCS11Exception {
    return getSupportedMechanism(keyGenMechanism, CKF_GENERATE);
  }

  private Mechanism getEncryptionMech() throws PKCS11Exception {
    return getSupportedMechanism(encryptMechanism, CKF_ENCRYPT, new GCM_PARAMS(iv, aad, 128));
  }

  private AttributeVector getMinimalKeyTemplate0() {
    return newSecretKey(CKK_AES).valueLen(keyLen / 8);
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
    Assert.assertEquals("Encrypt speed", 0, executor.getErrorAccout());

    executor = new MyDecryptExecutor();
    executor.setThreads(getSpeedTestThreads());
    executor.setDuration(getSpeedTestDuration());
    executor.setUnit(inputUnit);
    executor.execute();
    Assert.assertEquals("Decrypt speed", 0, executor.getErrorAccout());
  }

}
