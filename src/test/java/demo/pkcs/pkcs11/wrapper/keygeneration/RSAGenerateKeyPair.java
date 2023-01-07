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

package demo.pkcs.pkcs11.wrapper.keygeneration;

import demo.pkcs.pkcs11.wrapper.TestBase;
import demo.pkcs.pkcs11.wrapper.util.Util;
import org.xipki.pkcs11.*;
import org.xipki.pkcs11.AttributesTemplate;
import org.xipki.pkcs11.PKCS11KeyPair;
import org.xipki.pkcs11.Functions;
import org.junit.Test;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.List;
import java.util.Random;

import static org.xipki.pkcs11.PKCS11Constants.*;

/**
 * This demo program generates a 2048-bit RSA key-pair on the token.
 *
 * @author Lijun Liao
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
    List<Long> supportedMechanisms = token.getMechanismList2();

    MechanismInfo signatureMechanismInfo;
    if (supportedMechanisms.contains(CKM_RSA_PKCS)) {
      signatureMechanismInfo = token.getMechanismInfo(CKM_RSA_PKCS);
    } else if (supportedMechanisms.contains(CKM_RSA_X_509)) {
      signatureMechanismInfo = token.getMechanismInfo(CKM_RSA_X_509);
    } else if (supportedMechanisms.contains(CKM_RSA_9796)) {
      signatureMechanismInfo = token.getMechanismInfo(CKM_RSA_9796);
    } else if (supportedMechanisms.contains(CKM_RSA_PKCS_OAEP)) {
      signatureMechanismInfo = token.getMechanismInfo(CKM_RSA_PKCS_OAEP);
    } else {
      signatureMechanismInfo = null;
    }

    final long mechCode = CKM_RSA_PKCS_KEY_PAIR_GEN;
    if (!Util.supports(token, mechCode)) {
      System.out.println("Unsupported mechanism " + Functions.ckmCodeToName(mechCode));
      return;
    }

    Mechanism keyPairGenerationMechanism = getSupportedMechanism(token, mechCode);

    byte[] id = new byte[20];
    new Random().nextBytes(id);

    // set the general attributes for the public key
    AttributesTemplate publicKeyTemplate = newPublicKey(CKK_RSA).modulusBits(2048).token(true).id(id);
    AttributesTemplate privateKeyTemplate = newPrivateKey(CKK_RSA).sensitive(true).token(true).private_(true).id(id);

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
      privateKeyTemplate.sign(true).decrypt(true);
      publicKeyTemplate.verify(true).encrypt(true);
    }

    PKCS11KeyPair generatedKeyPair = session.generateKeyPair(
        keyPairGenerationMechanism, publicKeyTemplate, privateKeyTemplate);
    long generatedPublicKey = generatedKeyPair.getPublicKey();
    long generatedPrivateKey = generatedKeyPair.getPrivateKey();
    // no we may work with the keys...

    try {
      LOG.info("Success");
      LOG.info("The public key is {}", generatedPublicKey);
      LOG.info("The private key is {}", generatedPrivateKey);
      LOG.info("__________________________________________________");

      LOG.info("##################################################");
      BigInteger[] attrValues = session.getBigIntAttrValues(generatedPublicKey,
          CKA_MODULUS, CKA_PUBLIC_EXPONENT);
      RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(attrValues[0], attrValues[1]);

      KeyFactory keyFactory = KeyFactory.getInstance("RSA");
      RSAPublicKey javaRsaPublicKey = (RSAPublicKey) keyFactory.generatePublic(rsaPublicKeySpec);
      X509EncodedKeySpec x509EncodedPublicKey = keyFactory.getKeySpec(javaRsaPublicKey, X509EncodedKeySpec.class);
      x509EncodedPublicKey.getEncoded();

      // now we try to search for the generated keys
      LOG.info("##################################################");
      LOG.info("Trying to search for the public key of the generated key-pair" + " by ID: {}",
          Functions.toHex(id));
      // set the search template for the public key
      AttributesTemplate exportRsaPublicKeyTemplate = newPublicKey(CKK_RSA).id(id);

      session.findObjectsInit(exportRsaPublicKeyTemplate);
      long[] foundPublicKeys = session.findObjects(1);
      session.findObjectsFinal();

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
