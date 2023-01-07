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

package demo.pkcs.pkcs11.wrapper.speed.keygeneration;

import demo.pkcs.pkcs11.wrapper.TestBase;
import demo.pkcs.pkcs11.wrapper.util.Util;
import junit.framework.Assert;
import org.junit.Test;
import org.xipki.pkcs11.AttributesTemplate;
import org.xipki.pkcs11.Functions;
import org.xipki.pkcs11.PKCS11Exception;
import org.xipki.pkcs11.Token;

import static org.xipki.pkcs11.PKCS11Constants.CKK_AES;
import static org.xipki.pkcs11.PKCS11Constants.CKM_AES_KEY_GEN;

/**
 * AES speed test base class.
 *
 * @author Lijun Liao
 */
public abstract class AESKeyGenSpeed extends TestBase {

  private class MyExecutor extends KeyGenExecutor {

    public MyExecutor(Token token, char[] pin, boolean inToken) throws PKCS11Exception {
      super(mechanism, getKeyByteLen(), token, pin, inToken);
    }

    @Override
    protected AttributesTemplate getMinimalKeyTemplate() {
      return newSecretKey(CKK_AES).valueLen(getKeyByteLen());
    }

  }

  private static final long mechanism = CKM_AES_KEY_GEN;

  protected abstract int getKeyByteLen();

  @Test
  public void main() throws PKCS11Exception {
    Token token = getNonNullToken();
    if (!Util.supports(token, mechanism)) {
      System.out.println(Functions.ckmCodeToName(mechanism) + " is not supported, skip test");
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
