/*
 *
 * Copyright (c) 2019 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package demo.pkcs.pkcs11.wrapper.speed.encryption;

import demo.pkcs.pkcs11.wrapper.TestBase;
import demo.pkcs.pkcs11.wrapper.util.Util;
import junit.framework.Assert;
import org.junit.Test;
import org.xipki.pkcs11.AttributeVector;
import org.xipki.pkcs11.Mechanism;
import org.xipki.pkcs11.PKCS11Exception;
import org.xipki.pkcs11.Token;
import org.xipki.pkcs11.params.InitializationVectorParameters;
import org.xipki.util.BenchmarkExecutor;

import static org.xipki.pkcs11.PKCS11Constants.*;

/**
 * This demo program uses a PKCS#11 module to encrypt and decrypt via
 * CKM_AES_CBC_PAD.
 *
 * @author Lijun Liao
 */
public class AESCBCPadEncryptDecryptSpeed extends TestBase {

  private class MyEncryptExecutor extends EncryptExecutor {

    public MyEncryptExecutor(Token token, char[] pin) throws PKCS11Exception {
      super(codeToName(Category.CKM, encryptMechanism) + " (" + keyLen + ") Encrypt Speed",
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
      super(codeToName(Category.CKM, encryptMechanism) + " (" + keyLen + ") Decrypt Speed",
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
    return getSupportedMechanism(token, encryptMechanism, new InitializationVectorParameters(iv));
  }

  private AttributeVector getMinimalKeyTemplate0() {
    return newSecretKey(CKK_AES).valueLen(keyLen / 8);
  }

  @Test
  public void main() throws PKCS11Exception {
    Token token = getNonNullToken();
    if (!Util.supports(token, keyGenMechanism)) {
      System.out.println(codeToName(Category.CKM, keyGenMechanism) + " is not supported, skip test");
      return;
    }

    if (!Util.supports(token, encryptMechanism)) {
      System.out.println(codeToName(Category.CKM, encryptMechanism) + " is not supported, skip test");
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
