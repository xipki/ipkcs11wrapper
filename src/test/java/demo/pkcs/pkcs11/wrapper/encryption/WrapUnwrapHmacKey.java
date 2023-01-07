// Copyright (c) 2002 Graz University of Technology. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// 3. The end-user documentation included with the redistribution, if any, must
//    include the following acknowledgment:
//
//    "This product includes software developed by IAIK of Graz University of
//     Technology."
//
//    Alternately, this acknowledgment may appear in the software itself, if and
//    wherever such third-party acknowledgments normally appear.
//
// 4. The names "Graz University of Technology" and "IAIK of Graz University of
//    Technology" must not be used to endorse or promote products derived from
//    this software without prior written permission.
//
// 5. Products derived from this software may not be called "IAIK PKCS Wrapper",
//    nor may "IAIK" appear in their name, without prior written permission of
//    Graz University of Technology.
//
// THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESSED OR IMPLIED
// WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE LICENSOR BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
// OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
// OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
// ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

package demo.pkcs.pkcs11.wrapper.encryption;

import demo.pkcs.pkcs11.wrapper.TestBase;
import demo.pkcs.pkcs11.wrapper.util.Util;
import org.xipki.pkcs11.Mechanism;
import org.xipki.pkcs11.Session;
import org.xipki.pkcs11.Token;
import org.xipki.pkcs11.PKCS11Exception;
import org.xipki.pkcs11.AttributesTemplate;
import org.junit.Test;

import java.math.BigInteger;
import java.security.SecureRandom;

import static org.xipki.pkcs11.PKCS11Constants.*;

/**
 * This demo program uses a PKCS#11 module to wrap and unwrap a MAC secret key.
 * The key to be wrapped must be extractable otherwise it can't be wrapped.
 */
public class WrapUnwrapHmacKey extends TestBase {

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
    LOG.info("##################################################");
    AttributesTemplate secretMACKeyTemplate = newSecretKey(CKK_GENERIC_SECRET).token(false)
        .sign(true).verify(true).private_(true).sensitive(true).extractable(true);

    long hmacKey;
    int keyBytesLen = 32;
    Mechanism keyMechanism = Mechanism.get(CKM_GENERIC_SECRET_KEY_GEN);
    if (Util.supports(token, keyMechanism.getMechanismCode())) {
      LOG.info("generate secret MAC key");
      secretMACKeyTemplate.valueLen(keyBytesLen);
      hmacKey = session.generateKey(keyMechanism, secretMACKeyTemplate);
    } else {
      LOG.info("import secret MAC key (generation not supported)");
      byte[] keyValue = new byte[keyBytesLen];
      new SecureRandom().nextBytes(keyValue);
      secretMACKeyTemplate.value(keyValue);

      hmacKey = session.createObject(secretMACKeyTemplate);
    }

    LOG.info("##################################################");

    // be sure that your token can process the specified mechanism
    Mechanism signatureMechanism = getSupportedMechanism(token, CKM_SHA256_HMAC);
    // initialize for signing
    session.signInit(signatureMechanism, hmacKey);

    byte[] rawData = randomBytes(1057);

    byte[] macValue = session.sign(rawData);

    LOG.info("The MAC value is: " + new BigInteger(1, macValue).toString(16));
    LOG.info("##################################################");
    LOG.info("generate secret wrapping key");
    Mechanism wrapKeyMechanism = Mechanism.get(CKM_AES_KEY_GEN);
    AttributesTemplate wrapKeyTemplate = newSecretKey(CKK_AES).valueLen(16)
        .encrypt(true).decrypt(true).private_(true).sensitive(true).extractable(true).wrap(true).token(false);

    long wrappingKey = session.generateKey(wrapKeyMechanism, wrapKeyTemplate);

    LOG.info("wrapping key");

    Mechanism wrapMechanism = Mechanism.get(CKM_AES_KEY_WRAP);
    byte[] wrappedKey = session.wrapKey(wrapMechanism, wrappingKey, hmacKey);
    LOG.info("unwrapping key");

    AttributesTemplate keyTemplate = newSecretKey(CKK_GENERIC_SECRET).verify(true).token(false);

    long unwrappedKey = session.unwrapKey(wrapMechanism, wrappingKey, wrappedKey, keyTemplate);

    LOG.info("##################################################");
    LOG.info("verification of the MAC... ");

    // initialize for verification
    session.verifyInit(signatureMechanism, unwrappedKey);

    session.verify(rawData, macValue); // throws an exception upon
    // unsuccessful verification

    LOG.info("##################################################");
  }

}
