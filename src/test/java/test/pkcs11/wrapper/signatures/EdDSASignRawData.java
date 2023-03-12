// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.wrapper.signatures;

import org.junit.Test;
import org.xipki.pkcs11.wrapper.*;
import test.pkcs11.wrapper.util.Util;

import static org.xipki.pkcs11.wrapper.PKCS11Constants.*;

/**
 * Signs some raw data on the token using CKM_RSA_PKCS.
 */
public class EdDSASignRawData extends SignatureTestBase {

  @Test
  public void main() throws Exception {
    LOG.info("##################################################");
    LOG.info("generate signature key pair");

    final long mechCode = CKM_EDDSA;
    PKCS11Token token = getToken();
    if (!token.supportsMechanism(mechCode, CKF_SIGN)) {
      System.out.println("Unsupported mechanism " + ckmCodeToName(mechCode));
      return;
    }
    // be sure that your token can process the specified mechanism
    Mechanism signatureMechanism = getSupportedMechanism(mechCode, CKF_SIGN);

    final boolean inToken = false;
    // OID: 1.3.101.112 (Ed25519)
    byte[] ecParams = new byte[] {0x06, 0x03, 0x2b, 0x65, 0x70};

    PKCS11KeyPair generatedKeyPair = generateEdDSAKeypair(ecParams, inToken);

    LOG.info("##################################################");
    LOG.info("signing data");
    byte[] dataToBeSigned = randomBytes(1057); // hash value

    // This signing operation is implemented in most of the drivers
    byte[] signatureValue = token.sign(signatureMechanism, generatedKeyPair.getPrivateKey(), dataToBeSigned);
    LOG.info("The signature value is: {}", Functions.toHex(signatureValue));

    // verify signature
    long generatedPublicKey = generatedKeyPair.getPublicKey();
    // error will be thrown if signature is invalid
    token.verify(signatureMechanism, generatedPublicKey, dataToBeSigned, signatureValue);

    // verify with JCE
    jceVerifySignature("Ed25519", generatedPublicKey, CKK_EC_EDWARDS, dataToBeSigned, signatureValue);

    LOG.info("##################################################");
  }

}
