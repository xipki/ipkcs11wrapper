// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.wrapper.signatures;

import org.junit.Test;
import org.xipki.pkcs11.wrapper.*;
import test.pkcs11.wrapper.util.Util;

import java.security.MessageDigest;

import static org.xipki.pkcs11.wrapper.PKCS11Constants.*;

/**
 * Signs some raw data on the token using CKM_RSA_PKCS.
 */
public class DSASignRawData extends SignatureTestBase {

  @Test
  public void main() throws Exception {
    Token token = getNonNullToken();
    Session session = openReadOnlySession(token);
    try {
      main0(token, session);
    } finally {
      session.closeSession();
    }
  }

  private void main0(Token token, Session session) throws Exception {
    LOG.info("##################################################");
    LOG.info("generate signature key pair");

    final long mechCode = CKM_DSA;
    if (!Util.supports(token, mechCode)) {
      System.out.println("Unsupported mechanism " + ckmCodeToName(mechCode));
      return;
    }
    // be sure that your token can process the specified mechanism
    Mechanism signatureMechanism = getSupportedMechanism(token, mechCode);

    final boolean inToken = false;

    PKCS11KeyPair generatedKeyPair = generateDSAKeypair(token, session, inToken);

    LOG.info("##################################################");
    LOG.info("signing data");
    byte[] dataToBeSigned = randomBytes(1057); // hash value
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    byte[] hashValue = md.digest(dataToBeSigned);

    // This signing operation is implemented in most of the drivers
    byte[] signatureValue = session.signSingle(signatureMechanism, generatedKeyPair.getPrivateKey(), hashValue);
    LOG.info("The signature value is : (len={}) {}", signatureValue.length, Functions.toHex(signatureValue));

    // verify with JCE
    jceVerifySignature("SHA256withDSA", session, generatedKeyPair.getPublicKey(), CKK_DSA,
        dataToBeSigned, Util.dsaSigPlainToX962(signatureValue));

    // verify with PKCS#11
    // error will be thrown if signature is invalid
    session.verifySingle(signatureMechanism, generatedKeyPair.getPublicKey(), hashValue, signatureValue);

    LOG.info("##################################################");
  }

}
