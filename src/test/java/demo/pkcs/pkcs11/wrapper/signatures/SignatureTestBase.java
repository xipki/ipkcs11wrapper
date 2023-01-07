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

package demo.pkcs.pkcs11.wrapper.signatures;

import demo.pkcs.pkcs11.wrapper.TestBase;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.xipki.pkcs11.Session;

import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;

/**
 * Signature test base
 *
 * @author Lijun Liao
 */
public class SignatureTestBase extends TestBase {

  @BeforeClass
  public static void addProvider() {
    if (Security.getProvider("BC") == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  protected void jceVerifySignature(String algorithm, Session session, long publicKeyHandle, long keyType,
                                    byte[] data, byte[] signatureValue) throws Exception {
    // verify with JCE
    PublicKey jcePublicKey = generateJCEPublicKey(session, publicKeyHandle, keyType);
    Signature signature = Signature.getInstance(algorithm, "BC");
    signature.initVerify(jcePublicKey);
    signature.update(data);
    boolean valid = signature.verify(signatureValue);
    if (!valid) {
      throw new SignatureException("signature is invalid");
    }
  }

}
