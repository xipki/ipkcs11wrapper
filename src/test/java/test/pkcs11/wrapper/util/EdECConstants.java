// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.wrapper.util;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

/**
 * EdDSA constants class.
 */
public class EdECConstants {

  private static final ASN1ObjectIdentifier id_edwards_curve_algs = new ASN1ObjectIdentifier("1.3.101");

  public static final ASN1ObjectIdentifier id_X25519 = id_edwards_curve_algs.branch("110").intern();
  public static final ASN1ObjectIdentifier id_X448 = id_edwards_curve_algs.branch("111").intern();
  public static final ASN1ObjectIdentifier id_Ed25519 = id_edwards_curve_algs.branch("112").intern();
  public static final ASN1ObjectIdentifier id_Ed448 = id_edwards_curve_algs.branch("113").intern();

  public static final String X25519 = "X25519";

  public static final String Ed25519 = "Ed25519";

  public static final String X448 = "X448";

  public static final String Ed448 = "Ed448";

  private EdECConstants() {
  }

  public static boolean isEdwardsCurve(ASN1ObjectIdentifier curveOid) {
    return id_Ed25519.equals(curveOid) || id_Ed448.equals(curveOid);
  }

  public static boolean isMontgomeryCurve(ASN1ObjectIdentifier curveOid) {
    return id_X25519.equals(curveOid) || id_X448.equals(curveOid);
  }

  public static boolean isEdwardsOrMontgomeryCurve(ASN1ObjectIdentifier curveOid) {
    return isEdwardsCurve(curveOid) || isMontgomeryCurve(curveOid);
  }

  public static int getKeyBitSize(ASN1ObjectIdentifier curveOid) {
    if (id_X25519.equals(curveOid)) {
      return 256;
    } else if (id_X448.equals(curveOid)) {
      return 448;
    } else if (id_Ed25519.equals(curveOid)) {
      return 256;
    } else if (id_Ed448.equals(curveOid)) {
      return 448;
    } else {
      return 0;
    }
  }

  public static int getPublicKeyByteSize(ASN1ObjectIdentifier curveOid) {
    if (id_X25519.equals(curveOid)) {
      return 32;
    } else if (id_X448.equals(curveOid)) {
      return 56;
    } else if (id_Ed25519.equals(curveOid)) {
      return 32;
    } else if (id_Ed448.equals(curveOid)) {
      return 57;
    } else {
      return 0;
    }
  }

  public static String getName(ASN1ObjectIdentifier curveOid) {
    if (id_X25519.equals(curveOid)) {
      return X25519;
    } else if (id_X448.equals(curveOid)) {
      return X448;
    } else if (id_Ed25519.equals(curveOid)) {
      return Ed25519;
    } else if (id_Ed448.equals(curveOid)) {
      return Ed448;
    } else {
      return null;
    }
  }

  public static ASN1ObjectIdentifier getCurveOid(String curveName) {
    if (X25519.equalsIgnoreCase(curveName) || id_X25519.getId().equals(curveName)) {
      return id_X25519;
    } else if (X448.equalsIgnoreCase(curveName) || id_X448.getId().equals(curveName)) {
      return id_X448;
    } else if (Ed25519.equalsIgnoreCase(curveName) || id_Ed25519.getId().equals(curveName)) {
      return id_Ed25519;
    } else if (Ed448.equalsIgnoreCase(curveName) || id_Ed448.getId().equals(curveName)) {
      return id_Ed448;
    } else {
      return null;
    }
  }

}
