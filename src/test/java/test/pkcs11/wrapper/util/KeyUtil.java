// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.wrapper.util;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.xipki.util.Args;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Key utility class.
 */

public class KeyUtil {

  private KeyUtil() {
  }

  public static DSAPublicKey generateDSAPublicKey(DSAPublicKeySpec keySpec) throws InvalidKeySpecException {
    Args.notNull(keySpec, "keySpec");
    return (DSAPublicKey) getKeyFactory("DSA").generatePublic(keySpec);
  }

  private static KeyFactory getKeyFactory(String algorithm) throws InvalidKeySpecException {
    String alg = algorithm.toUpperCase();
    if ("ECDSA".equals(alg)) {
      alg = "EC";
    }

    try {
      return KeyFactory.getInstance(alg, "BC");
    } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
      throw new InvalidKeySpecException("could not find KeyFactory for " + algorithm + ": " + ex.getMessage());
    }
  }

  public static PublicKey generatePublicKey(SubjectPublicKeyInfo pkInfo) throws InvalidKeySpecException {
    Args.notNull(pkInfo, "pkInfo");

    X509EncodedKeySpec keyspec;
    try {
      keyspec = new X509EncodedKeySpec(pkInfo.getEncoded());
    } catch (IOException ex) {
      throw new InvalidKeySpecException(ex.getMessage(), ex);
    }
    ASN1ObjectIdentifier aid = pkInfo.getAlgorithm().getAlgorithm();

    String algorithm;
    if (PKCSObjectIdentifiers.rsaEncryption.equals(aid)) {
      algorithm = "RSA";
    } else if (X9ObjectIdentifiers.id_dsa.equals(aid)) {
      algorithm = "DSA";
    } else if (X9ObjectIdentifiers.id_ecPublicKey.equals(aid)) {
      algorithm = "EC";
    } else {
      algorithm = EdECConstants.getName(pkInfo.getAlgorithm().getAlgorithm());
    }

    if (algorithm == null) {
      throw new InvalidKeySpecException("unsupported key algorithm: " + aid);
    }

    return getKeyFactory(algorithm).generatePublic(keyspec);
  }

  public static RSAPublicKey generateRSAPublicKey(RSAPublicKeySpec keySpec) throws InvalidKeySpecException {
    Args.notNull(keySpec, "keySpec");
    return (RSAPublicKey) getKeyFactory("RSA").generatePublic(keySpec);
  }

  public static ECPublicKey createECPublicKey(byte[] encodedAlgorithmIdParameters, byte[] encodedPoint)
          throws InvalidKeySpecException {
    Args.notNull(encodedAlgorithmIdParameters, "encodedAlgorithmIdParameters");
    Args.notNull(encodedPoint, "encodedPoint");

    ASN1Encodable algParams;
    if (encodedAlgorithmIdParameters[0] == 6) {
      algParams = ASN1ObjectIdentifier.getInstance(encodedAlgorithmIdParameters);
    } else {
      algParams = X962Parameters.getInstance(encodedAlgorithmIdParameters);
    }
    AlgorithmIdentifier algId = new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, algParams);

    SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo(algId, encodedPoint);
    X509EncodedKeySpec keySpec;
    try {
      keySpec = new X509EncodedKeySpec(spki.getEncoded());
    } catch (IOException ex) {
      throw new InvalidKeySpecException(ex.getMessage(), ex);
    }

    KeyFactory kf;
    try {
      kf = KeyFactory.getInstance("EC", "BC");
    } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
      throw new InvalidKeySpecException(ex.getMessage(), ex);
    }
    return (ECPublicKey) kf.generatePublic(keySpec);
  }

}
