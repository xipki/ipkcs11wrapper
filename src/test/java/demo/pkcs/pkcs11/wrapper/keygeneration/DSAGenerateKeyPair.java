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
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import org.junit.Test;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Random;

import static iaik.pkcs.pkcs11.wrapper.PKCS11Constants.*;

/**
 * This demo program generates a 2048 bit DSA key-pair on the token.
 *
 * @author Lijun Liao
 */
public class DSAGenerateKeyPair extends TestBase {

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
    LOG.info("Generating new DSA key-pair... ");

    // first check out what attributes of the keys we may set
    HashSet<Mechanism> supportedMechanisms = new HashSet<>(Arrays.asList(token.getMechanismList()));

    MechanismInfo signatureMechanismInfo;
    if (supportedMechanisms.contains(Mechanism.get(PKCS11Constants.CKM_DSA))) {
      signatureMechanismInfo = token.getMechanismInfo(Mechanism.get(PKCS11Constants.CKM_DSA));
    } else {
      signatureMechanismInfo = null;
    }

    final long mechCode = PKCS11Constants.CKM_DSA_KEY_PAIR_GEN;
    if (!Util.supports(token, mechCode)) {
      System.out.println("Unsupported mechanism " + Functions.ckmCodeToName(mechCode));
      return;
    }

    byte[] id = new byte[20];
    new Random().nextBytes(id);

    Mechanism keyPairGenerationMechanism = getSupportedMechanism(token, mechCode);

    AttributeVector publicKeyTemplate = newPublicKey(CKK_DSA)
        .attr(CKA_PRIME, Functions.decodeHex(DSA_P))
        .attr(CKA_SUBPRIME, Functions.decodeHex(DSA_Q))
        .attr(CKA_BASE, Functions.decodeHex(DSA_G))
        .attr(CKA_TOKEN, true)
        .attr(CKA_ID, id);

    AttributeVector privateKeyTemplate = newPrivateKey(CKK_DSA)
        .attr(CKA_SENSITIVE, true)
        .attr(CKA_TOKEN, true)
        .attr(CKA_PRIVATE, true)
        .attr(CKA_ID, id);

    // set the attributes in a way netscape does, this should work with most tokens
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
      privateKeyTemplate.attr(CKA_SIGN, true)
          .attr(CKA_DECRYPT, true);

      publicKeyTemplate.attr(CKA_VERIFY, true)
          .attr(CKA_ENCRYPT, true);
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
      byte[] value = session.getByteArrayAttributeValue(exportablePublicKey, CKA_VALUE);

      LOG.info("Public Key (Value): {}", Functions.toHexString(value));

      // now we try to search for the generated keys
      LOG.info("##################################################");
      LOG.info("Trying to search for the public key of the generated key-pair" + " by ID: {}",
          Functions.toHexString(id));
      // set the search template for the public key
      AttributeVector exportPublicKeyTemplate = newPublicKey(CKK_DSA).attr(CKA_ID, id);

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
