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

package demo.pkcs.pkcs11.wrapper.speed.signature;

import demo.pkcs.pkcs11.wrapper.TestBase;
import demo.pkcs.pkcs11.wrapper.util.Util;
import junit.framework.Assert;
import org.junit.Test;
import org.xipki.pkcs11.*;
import org.xipki.util.BenchmarkExecutor;

import static org.xipki.pkcs11.PKCS11Constants.*;

/**
 * EDDSA sign / verify speed test.
 *
 * @author Lijun Liao
 */
public class EDDSASignVerifySpeed extends TestBase {

  private class MySignExecutor extends SignExecutor {

    public MySignExecutor(Token token, char[] pin) throws PKCS11Exception {
      super(Functions.ckmCodeToName(signMechanism) + " (Ed25519) Sign Speed",
          new Mechanism(keypairGenMechanism), token, pin, new Mechanism(signMechanism), 107);
    }

    @Override
    protected AttributesTemplate getMinimalPrivateKeyTemplate() {
      return getMinimalPrivateKeyTemplate0();
    }

    @Override
    protected AttributesTemplate getMinimalPublicKeyTemplate() {
      return getMinimalPublicKeyTemplate0();
    }

  }

  private class MyVerifyExecutor extends VerifyExecutor {

    public MyVerifyExecutor(Token token, char[] pin) throws PKCS11Exception {
      super(Functions.ckmCodeToName(signMechanism) + " (Ed25519) Verify Speed",
          new Mechanism(keypairGenMechanism), token, pin, new Mechanism(signMechanism), 107);
    }

    @Override
    protected AttributesTemplate getMinimalPrivateKeyTemplate() {
      return getMinimalPrivateKeyTemplate0();
    }

    @Override
    protected AttributesTemplate getMinimalPublicKeyTemplate() {
      return getMinimalPublicKeyTemplate0();
    }

  }

  private static final long keypairGenMechanism = CKM_EC_EDWARDS_KEY_PAIR_GEN;

  private static final long signMechanism = CKM_EDDSA;

  private AttributesTemplate getMinimalPrivateKeyTemplate0() {
    return newPrivateKey(CKK_EC_EDWARDS);
  }

  private AttributesTemplate getMinimalPublicKeyTemplate0() {
    // set the general attributes for the public key
    // OID: 1.3.101.112 (Ed25519)
    byte[] encodedCurveOid = new byte[] {0x06, 0x03, 0x2b, 0x65, 0x70};
    return newPublicKey(CKK_EC_EDWARDS).ecParams(encodedCurveOid);
  }

  @Test
  public void main() throws PKCS11Exception {
    Token token = getNonNullToken();
    if (!Util.supports(token, keypairGenMechanism)) {
      System.out.println(Functions.ckmCodeToName(keypairGenMechanism) + " is not supported, skip test");
      return;
    }

    if (!Util.supports(token, signMechanism)) {
      System.out.println(Functions.ckmCodeToName(signMechanism) + " is not supported, skip test");
      return;
    }

    BenchmarkExecutor executor = new MySignExecutor(token, getModulePin());
    executor.setThreads(getSpeedTestThreads());
    executor.setDuration(getSpeedTestDuration());
    executor.execute();
    Assert.assertEquals("Sign speed", 0, executor.getErrorAccout());

    executor = new MyVerifyExecutor(token, getModulePin());
    executor.setThreads(getSpeedTestThreads());
    executor.setDuration(getSpeedTestDuration());
    executor.execute();
    Assert.assertEquals("Verify speed", 0, executor.getErrorAccout());
  }

}
