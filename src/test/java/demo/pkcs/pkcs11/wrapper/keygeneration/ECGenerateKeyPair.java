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
 * This demo program generates an EC key-pair on the token.
 *
 * @author Lijun Liao
 */
public class ECGenerateKeyPair extends TestBase {

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
    LOG.info("Generating new EC (curve secp256r1) key-pair... ");

    // first check out what attributes of the keys we may set
    List<Long> supportedMechanisms = token.getMechanismList2();

    MechanismInfo signatureMechanismInfo;
    if (supportedMechanisms.contains(CKM_ECDSA)) {
      signatureMechanismInfo = token.getMechanismInfo(CKM_ECDSA);
    } else {
      signatureMechanismInfo = null;
    }

    final long mechCode = CKM_EC_KEY_PAIR_GEN;
    if (!Util.supports(token, mechCode)) {
      System.out.println("Unsupported mechanism " + Functions.ckmCodeToName(mechCode));
      return;
    }

    Mechanism keyPairGenerationMechanism = getSupportedMechanism(token, mechCode);
    AttributeVector publicKeyTemplate = newPublicKey(CKK_EC);
    AttributeVector privateKeyTemplate = newPrivateKey(CKK_EC);

    byte[] id = new byte[20];
    new Random().nextBytes(id);

    // set the general attributes for the public key
    // OID: 1.2.840.10045.3.1.7 (secp256r1, alias NIST P-256)
    byte[] encodedCurveOid = new byte[] {0x06, 0x08, 0x2a, (byte) 0x86,
        0x48, (byte) 0xce, 0x3d, 0x03, 0x01, 0x07};
    publicKeyTemplate.ecParams(encodedCurveOid).token(true).id(id);
    privateKeyTemplate.sensitive(true).token(true).private_(true).id(id);

    // set the attributes in a way netscape does, this should work with most
    // tokens
    if (signatureMechanismInfo != null) {
      publicKeyTemplate
          .verify(signatureMechanismInfo.hasFlagBit(CKF_VERIFY))
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
      publicKeyTemplate.verify(true).encrypt(true);

      privateKeyTemplate.sign(true).decrypt(true);
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
      byte[] encodedPoint = session.getByteArrayAttrValue(generatedPublicKey, CKA_EC_POINT);
      byte[] curveOid = session.getByteArrayAttrValue(generatedPublicKey, CKA_EC_PARAMS);

      LOG.info("Public Key (Point): {}", Functions.toHex(encodedPoint));
      LOG.info("Public Key (Curve OID): {}", Functions.toHex(curveOid));

      // now we try to search for the generated keys
      LOG.info("##################################################");
      LOG.info("Trying to search for the public key of the generated key-pair"
          + " by ID: {}", Functions.toHex(id));
      // set the search template for the public key
      AttributeVector exportPublicKeyTemplate = newPublicKey(CKK_EC).attr(CKA_ID, id);

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
