// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.wrapper.signatures;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.pkcs11.wrapper.*;

import java.io.ByteArrayInputStream;
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
    final long mechCode = CKM_DSA_SHA1;
    if (!token.supportsMechanism(mechCode, CKF_SIGN)) {
      System.out.println("Unsupported mechanism " + ckmCodeToName(mechCode));
      return;
    }
    // be sure that your token can process the specified mechanism
    Mechanism signatureMechanism = getSupportedMechanism(mechCode, CKF_SIGN);

    final boolean inToken = false;

    PKCS11KeyPair generatedKeyPair = generateDSAKeypair(inToken);

    int[] dataLens = {1057, 10570, 105700};
    boolean[] asStreamModes = {false, true};

    for (int dataLen : dataLens) {
      for (boolean asStream : asStreamModes) {
        LOG.info("##################################################");
        LOG.info("signing data");
        byte[] dataToBeSigned = randomBytes(dataLen); // hash value

        // This signing operation is implemented in most of the drivers
        long generatedPrivateKey = generatedKeyPair.getPrivateKey();
        byte[] signatureValue;
        if (asStream) {
          signatureValue = token.sign(signatureMechanism, generatedPrivateKey,
              new ByteArrayInputStream(dataToBeSigned));
        } else{
          signatureValue = token.sign(signatureMechanism, generatedPrivateKey, dataToBeSigned);
        }

        LOG.info("The signature value is : (len={}) {}", signatureValue.length, Functions.toHex(signatureValue));

        // verify with JCE
        jceVerifySignature("SHA1withDSA", generatedKeyPair.getPublicKey(), CKK_DSA,
            dataToBeSigned, Functions.dsaSigPlainToX962(signatureValue));

        // verify with PKCS#11
        long generatedPublicKey = generatedKeyPair.getPublicKey();
        // error will be thrown if signature is invalid
        boolean sigValid;
        if (asStream) {
          sigValid = token.verify(signatureMechanism, generatedPublicKey, new ByteArrayInputStream(dataToBeSigned),
              signatureValue);
        } else {
          sigValid = token.verify(signatureMechanism, generatedPublicKey, dataToBeSigned, signatureValue);
        }
        Assert.assertTrue("signature verification result", sigValid);

        LOG.info("##################################################");
      }
    }
  }

}
