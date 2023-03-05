// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.wrapper.signatures;

import test.pkcs11.wrapper.util.Util;
import org.junit.Test;
import org.xipki.pkcs11.wrapper.Mechanism;
import org.xipki.pkcs11.wrapper.PKCS11KeyPair;
import org.xipki.pkcs11.wrapper.Session;
import org.xipki.pkcs11.wrapper.Token;
import org.xipki.pkcs11.wrapper.params.RSA_PKCS_PSS_PARAMS;

import java.math.BigInteger;
import java.security.MessageDigest;

import static org.xipki.pkcs11.wrapper.PKCS11Constants.*;

/**
 * Signs some raw data on the token using CKM_RSA_PKCS_PSS.
 */
public class RSAPKCSPSSSignRawData extends SignatureTestBase {

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

    final long mechCode = CKM_RSA_PKCS_PSS;
    if (!Util.supports(token, mechCode)) {
      System.out.println("Unsupported mechanism " + ckmCodeToName(mechCode));
      return;
    }
    // be sure that your token can process the specified mechanism
    RSA_PKCS_PSS_PARAMS pssParams = new RSA_PKCS_PSS_PARAMS(CKM_SHA256, CKG_MGF1_SHA256, 32);
    Mechanism signatureMechanism = getSupportedMechanism(token, mechCode, pssParams);

    final boolean inToken = false;
    PKCS11KeyPair generatedKeyPair = generateRSAKeypair(token, session, 2048, inToken);
    long generatedPrivateKey = generatedKeyPair.getPrivateKey();

    LOG.info("##################################################");
    LOG.info("signing data");
    byte[] dataToBeSigned = randomBytes(1057); // hash value
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    byte[] hashValue = md.digest(dataToBeSigned);

    // This signing operation is implemented in most of the drivers
    byte[] signatureValue = session.signSingle(signatureMechanism, generatedPrivateKey, hashValue);

    LOG.info("The signature value is: {}", new BigInteger(1, signatureValue).toString(16));

    // verify
    long generatedPublicKey = generatedKeyPair.getPublicKey();
    // error will be thrown if signature is invalid
    session.verifySingle(signatureMechanism, generatedPublicKey, hashValue, signatureValue);

    // verify with JCE
    jceVerifySignature("SHA256withRSAandMGF1", session, generatedPublicKey, CKK_RSA,
        dataToBeSigned, signatureValue);

    LOG.info("##################################################");
  }

}
