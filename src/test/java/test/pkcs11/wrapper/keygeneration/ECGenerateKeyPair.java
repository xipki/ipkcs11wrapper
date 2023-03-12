// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.wrapper.keygeneration;

import org.junit.Test;
import org.xipki.pkcs11.wrapper.*;
import test.pkcs11.wrapper.TestBase;

import java.util.Random;

import static org.xipki.pkcs11.wrapper.PKCS11Constants.*;

/**
 * This demo program generates an EC key-pair on the token.
 */
public class ECGenerateKeyPair extends TestBase {

  @Test
  public void main() throws TokenException {
    LOG.info("##################################################");
    LOG.info("Generating new EC (curve secp256r1) key-pair... ");

    PKCS11Token token = getToken();
    // first check out what attributes of the keys we may set
    MechanismInfo signatureMechanismInfo;
    if (token.supportsMechanism(CKM_ECDSA, CKF_SIGN)) {
      signatureMechanismInfo = token.getMechanismInfo(CKM_ECDSA);
    } else {
      signatureMechanismInfo = null;
    }

    final long mechCode = CKM_EC_KEY_PAIR_GEN;
    if (!token.supportsMechanism(mechCode, CKF_GENERATE_KEY_PAIR)) {
      System.out.println("Unsupported mechanism " + ckmCodeToName(mechCode));
      return;
    }

    Mechanism keyPairGenerationMechanism = getSupportedMechanism(mechCode, CKF_GENERATE_KEY_PAIR);

    byte[] id = new byte[20];
    new Random().nextBytes(id);

    KeyPairTemplate template = new KeyPairTemplate(CKK_EC).id(id).token(true);

    // set the general attributes for the public key
    // OID: 1.2.840.10045.3.1.7 (secp256r1, alias NIST P-256)
    byte[] encodedCurveOid = new byte[] {0x06, 0x08, 0x2a, (byte) 0x86,
        0x48, (byte) 0xce, 0x3d, 0x03, 0x01, 0x07};
    template.publicKey().ecParams(encodedCurveOid);
    template.privateKey().sensitive(true).private_(true);

    // set the attributes in a way netscape does, this should work with most
    // tokens
    if (signatureMechanismInfo != null) {
      template.publicKey()
          .verify(signatureMechanismInfo.hasFlagBit(CKF_VERIFY))
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

    PKCS11KeyPair generatedKeyPair = token.generateKeyPair(keyPairGenerationMechanism, template);
    long generatedPublicKey = generatedKeyPair.getPublicKey();
    long generatedPrivateKey = generatedKeyPair.getPrivateKey();
    // no we may work with the keys...

    try {
      LOG.info("Success");
      LOG.info("The public key is {}", generatedPublicKey);
      LOG.info("The private key is {}", generatedPrivateKey);

      LOG.info("##################################################");
      AttributeVector attrs = token.getAttrValues(generatedPublicKey, CKA_EC_POINT, CKA_EC_PARAMS);
      byte[] encodedPoint = attrs.ecPoint();
      byte[] curveOid = attrs.ecParams();

      LOG.info("Public Key (Point): {}", Functions.toHex(encodedPoint));
      LOG.info("Public Key (Curve OID): {}", Functions.toHex(curveOid));

      // now we try to search for the generated keys
      LOG.info("##################################################");
      LOG.info("Trying to search for the public key of the generated key-pair"
          + " by ID: {}", Functions.toHex(id));
      // set the search template for the public key
      AttributeVector exportPublicKeyTemplate = newPublicKey(CKK_EC).attr(CKA_ID, id);

      long[] foundPublicKeys = token.findObjects(exportPublicKeyTemplate, 1);
      if (foundPublicKeys.length != 1) {
        LOG.error("Error: Cannot find the public key under the given ID!");
      } else {
        LOG.info("Found public key {}", foundPublicKeys[0]);
      }

      LOG.info("##################################################");
    } finally {
      token.destroyObject(generatedPrivateKey);
      token.destroyObject(generatedPublicKey);
    }

  }

}
