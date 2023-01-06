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

package demo.pkcs.pkcs11.wrapper.keygeneration;

import demo.pkcs.pkcs11.wrapper.TestBase;
import org.xipki.pkcs11.Mechanism;
import org.xipki.pkcs11.Session;
import org.xipki.pkcs11.Token;
import org.xipki.pkcs11.PKCS11Exception;
import org.xipki.pkcs11.objects.AttributeVector;
import org.junit.Test;

import static org.xipki.pkcs11.PKCS11Constants.*;

/**
 * This demo program shows how to generate secret keys.
 *
 * @author Lijun Liao
 */
public class GenerateKey extends TestBase {

  @Test
  public void main() throws PKCS11Exception {
    Token token = getNonNullToken();
    Session session = openReadWriteSession(token);
    try {
      main0(token, session);
    } finally {
      session.closeSession();
    }
  }

  private void main0(Token token, Session session) throws PKCS11Exception {
    Mechanism mech = getSupportedMechanism(token, CKM_GENERIC_SECRET_KEY_GEN);
    LOG.info("##################################################");
    LOG.info("Generating generic secret key");

    AttributeVector secretKeyTemplate = newSecretKey(CKK_GENERIC_SECRET).token(false).valueLen(16);
    long secretKey = session.generateKey(mech, secretKeyTemplate);

    LOG.info("the secret key is {}", secretKey);
    LOG.info("##################################################");
  }

}
