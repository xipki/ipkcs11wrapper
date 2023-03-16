// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.wrapper.signatures;

import org.junit.Test;
import org.xipki.pkcs11.wrapper.Functions;
import org.xipki.pkcs11.wrapper.Mechanism;
import org.xipki.pkcs11.wrapper.PKCS11KeyPair;
import org.xipki.pkcs11.wrapper.PKCS11Token;
import org.xipki.pkcs11.wrapper.params.CkParamsWithExtra;
import org.xipki.pkcs11.wrapper.params.ExtraParams;

import java.security.MessageDigest;

import static org.xipki.pkcs11.wrapper.PKCS11Constants.*;

/**
 * Signs some raw data on the token using CKM_RSA_PKCS.
 */
public class ECDSASignRawData extends SignatureTestBase {

  @Test
  public void main() throws Exception {
    LOG.info("##################################################");
    LOG.info("generate signature key pair");

    final long mechCode = CKM_ECDSA;
    PKCS11Token token = getToken();
    if (!token.supportsMechanism(mechCode, CKF_SIGN)) {
      System.out.println("Unsupported mechanism " + ckmCodeToName(mechCode));
      return;
    }

    final boolean inToken = false;
    // OID: 1.2.840.10045.3.1.7 (secp256r1, alias NIST P-256)
    final byte[] ecParams = new byte[] {0x06, 0x08, 0x2a, (byte) 0x86, 0x48, (byte) 0xce, 0x3d, 0x03, 0x01, 0x07};

    // be sure that your token can process the specified mechanism
    Mechanism signatureMechanism = getSupportedMechanism(mechCode, CKF_SIGN);
    // Some HSM vendors return the ECDSA signature in X.962 format, we need to provide the order bit
    // to covert it to R || S.
    signatureMechanism = new Mechanism(signatureMechanism.getMechanismCode(),
        new CkParamsWithExtra(signatureMechanism.getParameters(), new ExtraParams().ecOrderBitSize(256)));

    PKCS11KeyPair generatedKeyPair = generateECKeypair(ecParams, inToken);
    long generatedPrivateKey = generatedKeyPair.getPrivateKey();

    int[] dataLens = {1057, 10570, 105700};

    for (int dataLen : dataLens) {
      LOG.info("##################################################");
      LOG.info("signing data");
      byte[] dataToBeSigned = randomBytes(dataLen); // hash value
      MessageDigest md = MessageDigest.getInstance("SHA-256");
      byte[] hashValue = md.digest(dataToBeSigned);

      // This signing operation is implemented in most of the drivers
      byte[] signatureValue = token.sign(signatureMechanism, generatedPrivateKey, hashValue);

      LOG.info("The signature value is: {}", Functions.toHex(signatureValue));

      // verify
      long generatedPublicKey = generatedKeyPair.getPublicKey();
      // error will be thrown if signature is invalid
      token.verify(signatureMechanism, generatedPublicKey, hashValue, signatureValue);

      // verify with JCE
      jceVerifySignature("SHA256WithECDSA", generatedPublicKey, CKK_EC, dataToBeSigned,
          Functions.dsaSigPlainToX962(signatureValue));

      LOG.info("##################################################");
    }
  }

}
