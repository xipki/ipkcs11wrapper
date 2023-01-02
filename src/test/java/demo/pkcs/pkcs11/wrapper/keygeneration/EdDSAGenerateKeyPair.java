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
import iaik.pkcs.pkcs11.*;
import iaik.pkcs.pkcs11.objects.AttributeVector;
import iaik.pkcs.pkcs11.objects.KeyPair;
import iaik.pkcs.pkcs11.wrapper.Functions;
import org.junit.Test;

import java.util.List;
import java.util.Random;

import static iaik.pkcs.pkcs11.wrapper.PKCS11Constants.*;

/**
 * This demo program generates an Ed25519 key-pair on the token.
 *
 * @author Lijun Liao
 */
public class EdDSAGenerateKeyPair extends TestBase {

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
    LOG.info("Generating new EdDSA (curve Ed25519) key-pair... ");

    // first check out what attributes of the keys we may set
    List<Long> supportedMechanisms = token.getMechanismList2();

    MechanismInfo signatureMechanismInfo;
    if (supportedMechanisms.contains(CKM_EDDSA)) {
      signatureMechanismInfo = token.getMechanismInfo(CKM_EDDSA);
    } else {
      signatureMechanismInfo = null;
    }

    final long mechCode = CKM_EC_EDWARDS_KEY_PAIR_GEN;
    if (!Util.supports(token, mechCode)) {
      System.out.println("Unsupported mechanism " + Functions.ckmCodeToName(mechCode));
      return;
    }

    Mechanism keyPairGenerationMechanism = getSupportedMechanism(token, mechCode);

    AttributeVector publicKeyTemplate = newPublicKey(CKK_EC_EDWARDS);
    AttributeVector privateKeyTemplate = newPrivateKey(CKK_EC_EDWARDS);

    // set the general attributes for the public key
    // OID: 1.3.101.112 (Ed25519)
    byte[] encodedCurveOid = new byte[] {0x06, 0x03, 0x2b, 0x65, 0x70};
    byte[] id = new byte[20];
    new Random().nextBytes(id);
    publicKeyTemplate.attr(CKA_EC_PARAMS, encodedCurveOid)
        .attr(CKA_TOKEN, true).attr(CKA_ID, id);

    privateKeyTemplate.attr(CKA_SENSITIVE, true).attr(CKA_TOKEN, true)
        .attr(CKA_PRIVATE, true).attr(CKA_ID, id);

    // set the attributes in a way netscape does, this should work with most
    // tokens
    if (signatureMechanismInfo != null) {
      publicKeyTemplate.attr(CKA_VERIFY, signatureMechanismInfo.isVerify())
          .attr(CKA_VERIFY_RECOVER, signatureMechanismInfo.isVerifyRecover())
          .attr(CKA_ENCRYPT, signatureMechanismInfo.isEncrypt())
          .attr(CKA_DERIVE, signatureMechanismInfo.isDerive())
          .attr(CKA_WRAP, signatureMechanismInfo.isWrap());

      privateKeyTemplate.attr(CKA_SIGN, signatureMechanismInfo.isSign())
          .attr(CKA_SIGN_RECOVER, signatureMechanismInfo.isSignRecover())
          .attr(CKA_DECRYPT, signatureMechanismInfo.isDecrypt())
          .attr(CKA_DERIVE, signatureMechanismInfo.isDerive())
          .attr(CKA_UNWRAP, signatureMechanismInfo.isUnwrap());
    } else {
      // if we have no information we assume these attributes
      privateKeyTemplate.attr(CKA_SIGN, true).attr(CKA_DECRYPT, true);
      publicKeyTemplate.attr(CKA_VERIFY, true).attr(CKA_ENCRYPT, true);
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
      byte[] encodedPoint = session.getByteArrayAttributeValue(generatedPublicKey, CKA_EC_POINT);
      byte[] curveOid = session.getByteArrayAttributeValue(generatedPublicKey, CKA_EC_PARAMS);

      LOG.info("Public Key (Point): {}", Functions.toHexString(encodedPoint));
      LOG.info("Public Key (Curve OID): {}", Functions.toHexString(curveOid));

      // now we try to search for the generated keys
      LOG.info("##################################################");
      LOG.info("Trying to search for the public key of the generated key-pair" + " by ID: {}",
          Functions.toHexString(id));
      // set the search template for the public key
      AttributeVector exportPublicKeyTemplate = newPublicKey(CKK_EC_EDWARDS).attr(CKA_ID, id);

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
