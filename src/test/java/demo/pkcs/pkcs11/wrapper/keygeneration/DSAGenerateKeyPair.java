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
import demo.pkcs.pkcs11.wrapper.util.Util;
import org.xipki.pkcs11.*;
import org.xipki.pkcs11.objects.AttributeVector;
import org.xipki.pkcs11.objects.KeyPair;
import org.xipki.pkcs11.Functions;
import org.junit.Test;

import java.util.List;
import java.util.Random;

import static org.xipki.pkcs11.PKCS11Constants.*;

/**
 * This demo program generates a 2048 bit DSA key-pair on the token.
 *
 * @author Lijun Liao
 */
public class DSAGenerateKeyPair extends TestBase {

  @Test
  public void main() throws TokenException {
    Token token = getNonNullToken();
    Session session = openReadWriteSession(token);
    try {
      main0(token, session);
    } finally {
      session.closeSession();
    }
  }

  private void main0(Token token, Session session) throws TokenException {
    LOG.info("##################################################");
    LOG.info("Generating new DSA key-pair... ");

    // first check out what attributes of the keys we may set
    List<Long> supportedMechanisms = token.getMechanismList2();

    MechanismInfo signatureMechanismInfo;
    if (supportedMechanisms.contains(CKM_DSA)) {
      signatureMechanismInfo = token.getMechanismInfo(CKM_DSA);
    } else {
      signatureMechanismInfo = null;
    }

    final long mechCode = CKM_DSA_KEY_PAIR_GEN;
    if (!Util.supports(token, mechCode)) {
      System.out.println("Unsupported mechanism " + Functions.ckmCodeToName(mechCode));
      return;
    }

    byte[] id = new byte[20];
    new Random().nextBytes(id);

    Mechanism keyPairGenerationMechanism = getSupportedMechanism(token, mechCode);

    AttributeVector publicKeyTemplate = newPublicKey(CKK_DSA).token(true).id(id)
        .prime(DSA_P).subprime(DSA_Q).base(DSA_G);

    AttributeVector privateKeyTemplate = newPrivateKey(CKK_DSA).id(id).sensitive(true).token(true).private_(true);

    // set the attributes in a way netscape does, this should work with most tokens
    if (signatureMechanismInfo != null) {
      publicKeyTemplate.verify(signatureMechanismInfo.hasFlagBit(CKF_VERIFY))
          .verifyRecover(signatureMechanismInfo.hasFlagBit(CKF_VERIFY_RECOVER))
          .encrypt(signatureMechanismInfo.hasFlagBit(CKF_ENCRYPT))
          .derive(signatureMechanismInfo.hasFlagBit(CKF_DERIVE))
          .wrap(signatureMechanismInfo.hasFlagBit(CKF_WRAP));

      privateKeyTemplate
          .sign(signatureMechanismInfo.hasFlagBit(CKF_SIGN))
          .signRecover(signatureMechanismInfo.hasFlagBit(CKF_SIGN_RECOVER))
          .decrypt(signatureMechanismInfo.hasFlagBit(CKF_DECRYPT))
          .derive(signatureMechanismInfo.hasFlagBit(CKF_DERIVE))
          .unwrap(signatureMechanismInfo.hasFlagBit(CKF_UNWRAP));
    } else {
      // if we have no information we assume these attributes
      privateKeyTemplate.sign(true).decrypt(true);
      publicKeyTemplate.verify(true).encrypt(true);
    }

    KeyPair generatedKeyPair = session.generateKeyPair(
        keyPairGenerationMechanism, publicKeyTemplate, privateKeyTemplate);
    long generatedPublicKey = generatedKeyPair.getPublicKey();
    long generatedPrivateKey = generatedKeyPair.getPrivateKey();
    // no we may work with the keys...

    try {
      LOG.info("Success");
      LOG.info("The public key is {}", generatedPublicKey);
      LOG.info("The private key is {}", generatedPrivateKey);

      LOG.info("##################################################");
      byte[] value = session.getByteArrayAttributeValue(generatedPublicKey, CKA_VALUE);

      LOG.info("Public Key (Value): {}", Functions.toHex(value));

      // now we try to search for the generated keys
      LOG.info("##################################################");
      LOG.info("Trying to search for the public key of the generated key-pair" + " by ID: {}",
          Functions.toHex(id));
      // set the search template for the public key
      AttributeVector exportPublicKeyTemplate = newPublicKey(CKK_DSA).attr(CKA_ID, id);

      session.findObjectsInit(exportPublicKeyTemplate);
      long[] foundPublicKeys = session.findObjects(1);
      session.findObjectsFinal();

      if (foundPublicKeys.length != 1) {
        LOG.error("Error: Cannot find the public key under the given ID!");
      } else {
        LOG.info("Found public key {}", foundPublicKeys[0]);
      }

      LOG.info("##################################################");
    } finally {
      session.destroyObject(generatedPrivateKey);
      session.destroyObject(generatedPublicKey);
    }

  }

}
