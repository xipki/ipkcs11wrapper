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

import static org.xipki.pkcs11.PKCS11Constants.CKK_EC;
import static org.xipki.pkcs11.PKCS11Constants.CKM_EC_KEY_PAIR_GEN;

/**
 * EDDSA Keypair Generation Speed Test
 *
 * @author Lijun Liao
 */
public class ECKeypairGenSpeed extends TestBase {

  private class MyExecutor extends KeypairGenExecutor {

    public MyExecutor(Token token, char[] pin, boolean inToken) throws PKCS11Exception {
      super(Functions.ckmCodeToName(mechanism) + " (NIST P-256, inToken: " + inToken + ") Speed",
          mechanism, token, pin, inToken);
    }

    @Override
    protected AttributesTemplate getMinimalPrivateKeyTemplate() {
      return newPrivateKey(CKK_EC);
    }

    @Override
    protected AttributesTemplate getMinimalPublicKeyTemplate() {
      // set the general attributes for the public key
      // OID: 1.2.840.10045.3.1.7 (secp256r1, alias NIST P-256)
      byte[] encodedCurveOid = new byte[] {0x06, 0x08, 0x2a, (byte) 0x86, 0x48, (byte) 0xce, 0x3d, 0x03, 0x01, 0x07};
      return newPublicKey(CKK_EC).ecParams(encodedCurveOid);
    }

  }

  private static final long mechanism = CKM_EC_KEY_PAIR_GEN;

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
