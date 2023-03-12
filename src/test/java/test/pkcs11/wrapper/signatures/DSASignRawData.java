// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.wrapper.signatures;

import org.junit.Test;
import org.xipki.pkcs11.wrapper.*;

import java.security.MessageDigest;

import static org.xipki.pkcs11.wrapper.PKCS11Constants.*;

/**
 * Signs some raw data on the token using CKM_RSA_PKCS.
 */
public class DSASignRawData extends SignatureTestBase {

  @Test
  public void main() throws Exception {
    LOG.info("##################################################");
    LOG.info("generate signature key pair");

    PKCS11Token token = getToken();
    final long mechCode = CKM_DSA;
    if (!token.supportsMechanism(mechCode, CKF_SIGN)) {
      System.out.println("Unsupported mechanism " + ckmCodeToName(mechCode));
      return;
    }
    // be sure that your token can process the specified mechanism
    Mechanism signatureMechanism = getSupportedMechanism(mechCode, CKF_SIGN);

    final boolean inToken = false;

    PKCS11KeyPair generatedKeyPair = generateDSAKeypair(inToken);

    LOG.info("##################################################");
    LOG.info("signing data");
    byte[] dataToBeSigned = randomBytes(1057); // hash value
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    byte[] hashValue = md.digest(dataToBeSigned);

    // This signing operation is implemented in most of the drivers
    byte[] signatureValue = token.sign(signatureMechanism, generatedKeyPair.getPrivateKey(), hashValue);
    LOG.info("The signature value is : (len={}) {}", signatureValue.length, Functions.toHex(signatureValue));

    // verify with JCE
    jceVerifySignature("SHA256withDSA", generatedKeyPair.getPublicKey(), CKK_DSA,
        dataToBeSigned, Functions.dsaSigPlainToX962(signatureValue));

    // verify with PKCS#11
    // error will be thrown if signature is invalid
    token.verify(signatureMechanism, generatedKeyPair.getPublicKey(), hashValue, signatureValue);

    LOG.info("##################################################");
  }

}
