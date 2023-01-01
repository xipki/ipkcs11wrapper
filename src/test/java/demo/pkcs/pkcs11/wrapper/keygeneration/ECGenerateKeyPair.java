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

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Random;

import static iaik.pkcs.pkcs11.wrapper.PKCS11Constants.*;

/**
 * This demo program generates an EC key-pair on the token.
 *
 * @author Lijun Liao
 */
public class ECGenerateKeyPair extends TestBase {

  @Test
  public void main() throws TokenException, NoSuchAlgorithmException, InvalidKeySpecException {
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
    LOG.info("Generating new EC (curve secp256r1) key-pair... ");

    // first check out what attributes of the keys we may set
    HashSet<Mechanism> supportedMechanisms = new HashSet<>(Arrays.asList(token.getMechanismList()));

    MechanismInfo signatureMechanismInfo;
    if (supportedMechanisms.contains(Mechanism.get(CKM_ECDSA))) {
      signatureMechanismInfo = token.getMechanismInfo(Mechanism.get(CKM_ECDSA));
    } else {
      signatureMechanismInfo = null;
    }

    final long mechCode = CKM_EC_KEY_PAIR_GEN;
    if (!Util.supports(token, mechCode)) {
      System.out.println("Unsupported mechanism " + Functions.ckmCodeToName(mechCode));
      return;
    }

    Mechanism keyPairGenerationMechanism = getSupportedMechanism(
            token, mechCode);
    AttributeVector publicKeyTemplate = newPublicKey(CKK_EC);
    AttributeVector privateKeyTemplate = newPrivateKey(CKK_EC);

    byte[] id = new byte[20];
    new Random().nextBytes(id);

    // set the general attributes for the public key
    // OID: 1.2.840.10045.3.1.7 (secp256r1, alias NIST P-256)
    byte[] encodedCurveOid = new byte[] {0x06, 0x08, 0x2a, (byte) 0x86,
        0x48, (byte) 0xce, 0x3d, 0x03, 0x01, 0x07};
    publicKeyTemplate.attr(CKA_EC_PARAMS, encodedCurveOid).attr(CKA_TOKEN, true).attr(CKA_ID, id);

    privateKeyTemplate.attr(CKA_SENSITIVE, true)
        .attr(CKA_TOKEN, true).attr(CKA_PRIVATE, true).attr(CKA_ID, id);

    // set the attributes in a way netscape does, this should work with most
    // tokens
    if (signatureMechanismInfo != null) {
      publicKeyTemplate
          .attr(CKA_VERIFY, signatureMechanismInfo.isVerify())
          .attr(CKA_VERIFY_RECOVER, signatureMechanismInfo.isVerifyRecover())
          .attr(CKA_ENCRYPT, signatureMechanismInfo.isEncrypt())
          .attr(CKA_DERIVE, signatureMechanismInfo.isDerive())
          .attr(CKA_WRAP, signatureMechanismInfo.isWrap());

      privateKeyTemplate
          .attr(CKA_SIGN, signatureMechanismInfo.isSign())
          .attr(CKA_SIGN_RECOVER, signatureMechanismInfo.isSignRecover())
          .attr(CKA_DECRYPT, signatureMechanismInfo.isDecrypt())
          .attr(CKA_UNWRAP, signatureMechanismInfo.isUnwrap());
    } else {
      // if we have no information we assume these attributes
      publicKeyTemplate
          .attr(CKA_VERIFY, true).attr(CKA_ENCRYPT, true);

      privateKeyTemplate.attr(CKA_SIGN, true)
          .attr(CKA_DECRYPT, true);
    }

    KeyPair generatedKeyPair = session.generateKeyPair(
        keyPairGenerationMechanism, publicKeyTemplate, privateKeyTemplate);
    long generatedPublicKey = generatedKeyPair.getPublicKey();
    long generatedPrivateKey = generatedKeyPair.getPrivateKey();
    // no we may work with the keys...

    try {
      LOG.info("Success");
      LOG.info("The public key is");
      LOG.info("__________________________________________________");
      LOG.info("{}", generatedPublicKey);
      LOG.info("__________________________________________________");
      LOG.info("The private key is");
      LOG.info("__________________________________________________");
      LOG.info("{}", generatedPrivateKey);
      LOG.info("__________________________________________________");

      LOG.info("##################################################");
      long exportablePublicKey = generatedPublicKey;
      byte[] encodedPoint = session.getByteArrayAttributeValue(exportablePublicKey, CKA_EC_POINT);
      byte[] curveOid = session.getByteArrayAttributeValue(exportablePublicKey, CKA_EC_PARAMS);

      LOG.info("Public Key (Point): {}", Functions.toHexString(encodedPoint));
      LOG.info("Public Key (Curve OID): {}", Functions.toHexString(curveOid));

      // now we try to search for the generated keys
      LOG.info("##################################################");
      LOG.info("Trying to search for the public key of the generated key-pair"
          + " by ID: {}", Functions.toHexString(id));
      // set the search template for the public key
      AttributeVector exportPublicKeyTemplate = newPublicKey(CKK_EC).attr(CKA_ID, id);

      session.findObjectsInit(exportPublicKeyTemplate);
      long[] foundPublicKeys = session.findObjects(1);
      session.findObjectsFinal();

      if (foundPublicKeys.length != 1) {
        LOG.error("Error: Cannot find the public key under the given ID!");
      } else {
        LOG.info("Found public key!");
        LOG.info("__________________________________________________");
        LOG.info("{}", foundPublicKeys[0]);
        LOG.info("__________________________________________________");
      }

      LOG.info("##################################################");
    } finally {
      session.destroyObject(generatedPrivateKey);
      session.destroyObject(generatedPublicKey);
    }

  }

}
