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

import static org.xipki.pkcs11.PKCS11Constants.CKK_EC_EDWARDS;
import static org.xipki.pkcs11.PKCS11Constants.CKM_EC_EDWARDS_KEY_PAIR_GEN;

/**
 * EDDSA Keypair Generation Speed Test
 *
 * @author Lijun Liao
 */
public class EdDSAKeypairGenSpeed extends TestBase {

  private class MyExecutor extends KeypairGenExecutor {

    public MyExecutor(Token token, char[] pin, boolean inToken) throws PKCS11Exception {
      super(Functions.ckmCodeToName(mechanism) + " (Ed25519, inToken: " + inToken + ") Speed",
          mechanism, token, pin, inToken);
    }

    @Override
    protected AttributesTemplate getMinimalPrivateKeyTemplate() {
      return newPrivateKey(CKK_EC_EDWARDS);
    }

    @Override
    protected AttributesTemplate getMinimalPublicKeyTemplate() {
      // set the general attributes for the public key
      // OID: 1.3.101.112 (Ed25519)
      byte[] encodedCurveOid = new byte[] {0x06, 0x03, 0x2b, 0x65, 0x70};
      return newPublicKey(CKK_EC_EDWARDS).ecParams(encodedCurveOid);
    }

  }

  private static final long mechanism = CKM_EC_EDWARDS_KEY_PAIR_GEN;

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
