// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.
//
// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.wrapper.keygeneration;

import org.junit.Test;
import org.xipki.pkcs11.wrapper.*;
import test.pkcs11.wrapper.TestBase;
import test.pkcs11.wrapper.util.Util;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.List;
import java.util.Random;

import static org.xipki.pkcs11.wrapper.PKCS11Constants.*;

/**
 * This demo program generates a 2048-bit RSA key-pair on the token.
 */
public class RSAGenerateKeyPair extends TestBase {

  @Test
  public void main() throws PKCS11Exception, NoSuchAlgorithmException, InvalidKeySpecException {
    Token token = getNonNullToken();
    Session session = openReadWriteSession(token);
    try {
      main0(token, session);
    } finally {
      session.closeSession();
    }
  }

  private void main0(Token token, Session session)
      throws PKCS11Exception, NoSuchAlgorithmException, InvalidKeySpecException {
    LOG.info("##################################################");
    LOG.info("Generating new 2048 bit RSA key-pair... ");

    // first check out what attributes of the keys we may set
    List<Long> supportedMechanisms = getMechanismList(token);

    MechanismInfo signatureMechanismInfo =
          supportedMechanisms.contains(CKM_RSA_PKCS) ? token.getMechanismInfo(CKM_RSA_PKCS)
        : supportedMechanisms.contains(CKM_RSA_X_509) ? token.getMechanismInfo(CKM_RSA_X_509)
        : supportedMechanisms.contains(CKM_RSA_9796) ? token.getMechanismInfo(CKM_RSA_9796)
        : supportedMechanisms.contains(CKM_RSA_PKCS_OAEP) ? token.getMechanismInfo(CKM_RSA_PKCS_OAEP)
        : null;

    final long mechCode = CKM_RSA_PKCS_KEY_PAIR_GEN;
    if (!Util.supports(token, mechCode)) {
      System.out.println("Unsupported mechanism " + ckmCodeToName(mechCode));
      return;
    }

    Mechanism keyPairGenerationMechanism = getSupportedMechanism(token, mechCode);

    byte[] id = new byte[20];
    new Random().nextBytes(id);

    // set the general attributes for the public key
    KeyPairTemplate template = new KeyPairTemplate(CKK_RSA).token(true).id(id);
    template.publicKey().modulusBits(2048);
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

    PKCS11KeyPair generatedKeyPair = session.generateKeyPair(keyPairGenerationMechanism, template);
    long generatedPublicKey = generatedKeyPair.getPublicKey();
    long generatedPrivateKey = generatedKeyPair.getPrivateKey();
    // no we may work with the keys...

    try {
      LOG.info("Success");
      LOG.info("The public key is {}", generatedPublicKey);
      LOG.info("The private key is {}", generatedPrivateKey);
      LOG.info("__________________________________________________");

      LOG.info("##################################################");
      AttributeVector attrValues = session.getAttrValues(generatedPublicKey, CKA_MODULUS, CKA_PUBLIC_EXPONENT);
      RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(attrValues.modulus(), attrValues.publicExponent());

      KeyFactory keyFactory = KeyFactory.getInstance("RSA");
      RSAPublicKey javaRsaPublicKey = (RSAPublicKey) keyFactory.generatePublic(rsaPublicKeySpec);
      X509EncodedKeySpec x509EncodedPublicKey = keyFactory.getKeySpec(javaRsaPublicKey, X509EncodedKeySpec.class);
      x509EncodedPublicKey.getEncoded();

      // now we try to search for the generated keys
      LOG.info("##################################################");
      LOG.info("Trying to search for the public key of the generated key-pair" + " by ID: {}",
          Functions.toHex(id));
      // set the search template for the public key
      AttributeVector exportRsaPublicKeyTemplate = newPublicKey(CKK_RSA).id(id);

      long[] foundPublicKeys = session.findObjectsSingle(exportRsaPublicKeyTemplate, 1);
      if (foundPublicKeys.length != 1) {
        LOG.error("Error: Cannot find the public key under the given ID!");
      } else {
        LOG.info("Found public key: {}", foundPublicKeys[0]);
      }

      LOG.info("##################################################");
    } finally {
      session.destroyObject(generatedPrivateKey);
      session.destroyObject(generatedPublicKey);
    }

  }

}
