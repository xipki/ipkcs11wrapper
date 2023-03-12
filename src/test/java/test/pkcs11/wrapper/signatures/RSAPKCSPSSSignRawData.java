// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.wrapper.signatures;

import org.junit.Test;
import org.xipki.pkcs11.wrapper.*;
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
    LOG.info("##################################################");
    LOG.info("generate signature key pair");

    PKCS11Token token = getToken();

    final long mechCode = CKM_RSA_PKCS_PSS;
    if (!token.supportsMechanism(mechCode, CKF_SIGN)) {
      System.out.println("Unsupported mechanism " + ckmCodeToName(mechCode));
      return;
    }
    // be sure that your token can process the specified mechanism
    RSA_PKCS_PSS_PARAMS pssParams = new RSA_PKCS_PSS_PARAMS(CKM_SHA256, CKG_MGF1_SHA256, 32);
    Mechanism signatureMechanism = getSupportedMechanism(mechCode, CKF_SIGN, pssParams);

    final boolean inToken = false;
    PKCS11KeyPair generatedKeyPair = generateRSAKeypair(2048, inToken);
    long generatedPrivateKey = generatedKeyPair.getPrivateKey();

    LOG.info("##################################################");
    LOG.info("signing data");
    byte[] dataToBeSigned = randomBytes(1057); // hash value
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    byte[] hashValue = md.digest(dataToBeSigned);

    // This signing operation is implemented in most of the drivers
    byte[] signatureValue = token.sign(signatureMechanism, generatedPrivateKey, hashValue);

    LOG.info("The signature value is: {}", new BigInteger(1, signatureValue).toString(16));

    // verify
    long generatedPublicKey = generatedKeyPair.getPublicKey();
    // error will be thrown if signature is invalid
    token.verify(signatureMechanism, generatedPublicKey, hashValue, signatureValue);

    // verify with JCE
    jceVerifySignature("SHA256withRSAandMGF1", generatedPublicKey, CKK_RSA,
        dataToBeSigned, signatureValue);

    LOG.info("##################################################");
  }

}
