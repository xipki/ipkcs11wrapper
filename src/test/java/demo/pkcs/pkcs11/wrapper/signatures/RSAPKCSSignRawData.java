// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package demo.pkcs.pkcs11.wrapper.signatures;

import demo.pkcs.pkcs11.wrapper.util.Util;
import org.junit.Test;
import org.xipki.pkcs11.Mechanism;
import org.xipki.pkcs11.PKCS11KeyPair;
import org.xipki.pkcs11.Session;
import org.xipki.pkcs11.Token;
import org.xipki.util.Hex;

import java.math.BigInteger;
import java.security.MessageDigest;

import static org.xipki.pkcs11.PKCS11Constants.*;

/**
 * Signs some raw data on the token using CKM_RSA_PKCS.
 */
public class RSAPKCSSignRawData extends SignatureTestBase {

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
    final long mechCode = CKM_RSA_PKCS;
    if (!Util.supports(token, mechCode)) {
      System.out.println("Unsupported mechanism " + ckmCodeToName(mechCode));
      return;
    }
    // be sure that your token can process the specified mechanism
    Mechanism signatureMechanism = getSupportedMechanism(token, mechCode);

    final boolean inToken = false;
    PKCS11KeyPair generatedKeyPair = generateRSAKeypair(token, session, 2048, inToken);
    long generatedPrivateKey = generatedKeyPair.getPrivateKey();

    LOG.info("##################################################");
    LOG.info("signing data");
    byte[] dataToBeSigned = randomBytes(1057); // hash value
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    byte[] hashValue = md.digest(dataToBeSigned);
    byte[] digestInfoPrefix = Hex.decode("3031300d060960864801650304020105000420");
    byte[] digestInfo = new byte[digestInfoPrefix.length + hashValue.length];
    System.arraycopy(digestInfoPrefix, 0, digestInfo, 0, digestInfoPrefix.length);
    System.arraycopy(hashValue, 0, digestInfo, digestInfoPrefix.length, hashValue.length);

    // initialize for signing
    session.signInit(signatureMechanism, generatedPrivateKey);

    // This signing operation is implemented in most of the drivers
    byte[] signatureValue = session.sign(digestInfo);

    LOG.info("The signature value is: {}", new BigInteger(1, signatureValue).toString(16));

    // verify
    long generatedPublicKey = generatedKeyPair.getPublicKey();
    session.verifyInit(signatureMechanism, generatedPublicKey);
    // error will be thrown if signature is invalid
    session.verify(digestInfo, signatureValue);

    // verify with JCE
    jceVerifySignature("SHA256withRSA", session, generatedPublicKey, CKK_RSA,
        dataToBeSigned, signatureValue);

    LOG.info("##################################################");
  }

}
