// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.wrapper.speed.encryption;

import junit.framework.Assert;
import org.junit.Test;
import org.xipki.pkcs11.wrapper.AttributeVector;
import org.xipki.pkcs11.wrapper.Mechanism;
import org.xipki.pkcs11.wrapper.PKCS11Exception;
import org.xipki.pkcs11.wrapper.Token;
import org.xipki.pkcs11.wrapper.params.ByteArrayParams;
import org.xipki.util.BenchmarkExecutor;
import test.pkcs11.wrapper.TestBase;
import test.pkcs11.wrapper.util.Util;

import static org.xipki.pkcs11.wrapper.PKCS11Constants.*;

/**
 * This demo program uses a PKCS#11 module to encrypt and decrypt via
 * CKM_AES_CBC_PAD.
 */
public class AESCBCPadEncryptDecryptSpeed extends TestBase {

  private class MyEncryptExecutor extends EncryptExecutor {

    public MyEncryptExecutor(Token token, char[] pin) throws PKCS11Exception {
      super(ckmCodeToName(encryptMechanism) + " (" + keyLen + ") Encrypt Speed",
          getKeyGenMech(token), token, pin,
          getEncryptionMech(token), inputLen);
    }

    @Override
    protected AttributeVector getMinimalKeyTemplate() {
      return getMinimalKeyTemplate0();
    }

  }

  private class MyDecryptExecutor extends DecryptExecutor {

    public MyDecryptExecutor(Token token, char[] pin) throws PKCS11Exception {
      super(ckmCodeToName(encryptMechanism) + " (" + keyLen + ") Decrypt Speed",
          getKeyGenMech(token), token, pin,
          getEncryptionMech(token), inputLen);
    }

    @Override
    protected AttributeVector getMinimalKeyTemplate() {
      return getMinimalKeyTemplate0();
    }

  }

  private static final long keyGenMechanism = CKM_AES_KEY_GEN;

  private static final long encryptMechanism = CKM_AES_CBC_PAD;

  private static final int inputLen = 1024;

  private static final String inputUnit = "KiB";

  private static final int keyLen = 256;

  private final byte[] iv;

  public AESCBCPadEncryptDecryptSpeed() {
    iv = randomBytes(16);
  }

  private Mechanism getKeyGenMech(Token token) throws PKCS11Exception {
    return getSupportedMechanism(token, keyGenMechanism);
  }

  private Mechanism getEncryptionMech(Token token) throws PKCS11Exception {
    return getSupportedMechanism(token, encryptMechanism, new ByteArrayParams(iv));
  }

  private AttributeVector getMinimalKeyTemplate0() {
    return newSecretKey(CKK_AES).valueLen(keyLen / 8);
  }

  @Test
  public void main() throws PKCS11Exception {
    Token token = getNonNullToken();
    if (!Util.supports(token, keyGenMechanism)) {
      System.out.println(ckmCodeToName(keyGenMechanism) + " is not supported, skip test");
      return;
    }

    if (!Util.supports(token, encryptMechanism)) {
      System.out.println(ckmCodeToName(encryptMechanism) + " is not supported, skip test");
      return;
    }

    BenchmarkExecutor executor = new MyEncryptExecutor(token, getModulePin());
    executor.setThreads(getSpeedTestThreads());
    executor.setDuration(getSpeedTestDuration());
    executor.setUnit(inputUnit);
    executor.execute();
    Assert.assertEquals("Encrypt speed", 0, executor.getErrorAccout());

    executor = new MyDecryptExecutor(token, getModulePin());
    executor.setThreads(getSpeedTestThreads());
    executor.setDuration(getSpeedTestDuration());
    executor.setUnit(inputUnit);
    executor.execute();
    Assert.assertEquals("Decrypt speed", 0, executor.getErrorAccout());
  }

}
