// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.wrapper.signatures;

import org.junit.Test;
import org.xipki.pkcs11.wrapper.*;
import org.xipki.util.Hex;

import java.math.BigInteger;
import java.security.MessageDigest;

import static org.xipki.pkcs11.wrapper.PKCS11Constants.*;

/**
 * Signs some raw data on the token using CKM_RSA_PKCS.
 */
public class RSAPKCSSignRawData extends SignatureTestBase {

  @Test
  public void main() throws Exception {
    LOG.info("##################################################");
    LOG.info("generate signature key pair");
    final long mechCode = CKM_RSA_PKCS;

    PKCS11Token token = getToken();

    if (!token.supportsMechanism(mechCode, CKF_SIGN)) {
      System.out.println("Unsupported mechanism " + ckmCodeToName(mechCode));
      return;
    }
    // be sure that your token can process the specified mechanism
    Mechanism signatureMechanism = getSupportedMechanism(mechCode, CKF_SIGN);

    final boolean inToken = false;
    PKCS11KeyPair generatedKeyPair = generateRSAKeypair(2048, inToken);
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

    // This signing operation is implemented in most of the drivers
    byte[] signatureValue = token.sign(signatureMechanism, generatedPrivateKey, digestInfo);

    LOG.info("The signature value is: {}", new BigInteger(1, signatureValue).toString(16));

    // verify
    long generatedPublicKey = generatedKeyPair.getPublicKey();
    // error will be thrown if signature is invalid
    token.verify(signatureMechanism, generatedPublicKey, digestInfo, signatureValue);

    // verify with JCE
    jceVerifySignature("SHA256withRSA", generatedPublicKey, CKK_RSA,
        dataToBeSigned, signatureValue);

    LOG.info("##################################################");
  }

}
