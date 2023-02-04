// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.wrapper.keygeneration;

import test.pkcs11.wrapper.TestBase;
import test.pkcs11.wrapper.util.Util;
import org.junit.Test;
import org.xipki.pkcs11.wrapper.*;

import java.util.List;
import java.util.Random;

import static org.xipki.pkcs11.wrapper.PKCS11Constants.*;

/**
 * This demo program generates a 2048 bit DSA key-pair on the token.
 */
public class DSAGenerateKeyPair extends TestBase {

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
    LOG.info("Generating new DSA key-pair... ");

    // first check out what attributes of the keys we may set
    List<Long> supportedMechanisms = getMechanismList(token);

    MechanismInfo signatureMechanismInfo;
    if (supportedMechanisms.contains(CKM_DSA)) {
      signatureMechanismInfo = token.getMechanismInfo(CKM_DSA);
    } else {
      signatureMechanismInfo = null;
    }

    final long mechCode = CKM_DSA_KEY_PAIR_GEN;
    if (!Util.supports(token, mechCode)) {
      System.out.println("Unsupported mechanism " + ckmCodeToName(mechCode));
      return;
    }

    byte[] id = new byte[20];
    new Random().nextBytes(id);

    Mechanism keyPairGenerationMechanism = getSupportedMechanism(token, mechCode);
    KeyPairTemplate template = new KeyPairTemplate(CKK_DSA).token(true).id(id);

    template.publicKey().prime(DSA_P).subprime(DSA_Q).base(DSA_G);
    template.privateKey().sensitive(true).private_(true);

    // set the attributes in a way netscape does, this should work with most tokens
    if (signatureMechanismInfo != null) {
      template.publicKey().verify(signatureMechanismInfo.hasFlagBit(CKF_VERIFY))
          .verifyRecover(signatureMechanismInfo.hasFlagBit(CKF_VERIFY_RECOVER))
          .encrypt(signatureMechanismInfo.hasFlagBit(CKF_ENCRYPT))
          .derive(signatureMechanismInfo.hasFlagBit(CKF_DERIVE))
          .wrap(signatureMechanismInfo.hasFlagBit(CKF_WRAP));

      template.privateKey()
          .sign(signatureMechanismInfo.hasFlagBit(CKF_SIGN))
          .signRecover(signatureMechanismInfo.hasFlagBit(CKF_SIGN_RECOVER))
          .decrypt(signatureMechanismInfo.hasFlagBit(CKF_DECRYPT))
          .derive(signatureMechanismInfo.hasFlagBit(CKF_DERIVE))
          .unwrap(signatureMechanismInfo.hasFlagBit(CKF_UNWRAP));
    } else {
      // if we have no information we assume these attributes
      template.signVerify(true).decryptEncrypt(true);
    }

    PKCS11KeyPair generatedKeyPair = session.generateKeyPair(keyPairGenerationMechanism, template);
    long generatedPublicKey = generatedKeyPair.getPublicKey();
    long generatedPrivateKey = generatedKeyPair.getPrivateKey();
    // no we may work with the keys...

    try {
      LOG.info("Success");
      LOG.info("The public key is {}", generatedPublicKey);
      LOG.info("The private key is {}", generatedPrivateKey);

      LOG.info("##################################################");
      byte[] value = session.getByteArrayAttrValue(generatedPublicKey, CKA_VALUE);

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
