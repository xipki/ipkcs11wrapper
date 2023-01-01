// Copyright (c) 2002 Graz University of Technology. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// 3. The end-user documentation included with the redistribution, if any, must
//    include the following acknowledgment:
//
//    "This product includes software developed by IAIK of Graz University of
//     Technology."
//
//    Alternately, this acknowledgment may appear in the software itself, if and
//    wherever such third-party acknowledgments normally appear.
//
// 4. The names "Graz University of Technology" and "IAIK of Graz University of
//    Technology" must not be used to endorse or promote products derived from
//    this software without prior written permission.
//
// 5. Products derived from this software may not be called "IAIK PKCS Wrapper",
//    nor may "IAIK" appear in their name, without prior written permission of
//    Graz University of Technology.
//
// THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESSED OR IMPLIED
// WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE LICENSOR BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
// OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
// OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
// ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

package demo.pkcs.pkcs11.wrapper.basics;

import demo.pkcs.pkcs11.wrapper.TestBase;
import demo.pkcs.pkcs11.wrapper.util.Util;
import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.MechanismInfo;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.objects.AttributeVector;
import org.junit.Test;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;

import static iaik.pkcs.pkcs11.wrapper.PKCS11Constants.*;

/**
 * This demo program can be used to personalize a card. It uploads a private
 * RSA key and the corresponding certificate. The key and the certificate are
 * given as a file in PKCS#12 format. The usage flags of the key object are
 * taken from the key usage flags of the certificate.
 */
public class UploadPrivateKey extends TestBase {

  private static final String p12ResourcePath = "/demo_cert.p12";
  private static final String p12Password = "1234";

  private static final int digitalSignature  = 0;
  private static final int nonRepudiation    = 1;
  private static final int keyEncipherment   = 2;
  private static final int dataEncipherment  = 3;
  private static final int keyAgreement      = 4;
  private static final int keyCertSign       = 5;
  private static final int cRLSign           = 6;
  // private static final int encipherOnly      = 7;
  // private static final int decipherOnly      = 8;

  @Test
  public void main() throws Exception {
    Token token = getNonNullToken();
    Session session = openReadWriteSession(token);
    try {
      main0(token, session);
    } finally {
      session.closeSession();
    }
  }

  private void main0(Token token, Session session) throws Exception {
    LOG.info("##################################################");
    LOG.info("Reading private key and certifiacte from: {}", p12ResourcePath);
    char[] filePassword = p12Password.toCharArray();
    InputStream dataInputStream = getResourceAsStream(p12ResourcePath);
    KeyStore keystore = KeyStore.getInstance("PKCS12");
    keystore.load(dataInputStream, filePassword);

    String keyAlias = null;
    Enumeration<String> aliases = keystore.aliases();
    while (aliases.hasMoreElements()) {
      String alias = aliases.nextElement();
      if (keystore.isKeyEntry(alias)) {
        keyAlias = alias;
        break;
      }
    }

    if (keyAlias == null) {
      LOG.error("Found no private Key in the PKCS#12 file.");
      throw new IOException("Given file does not include a key!");
    }

    java.security.PrivateKey jcaPrivateKey = (PrivateKey) keystore.getKey(keyAlias, filePassword);

    if (!jcaPrivateKey.getAlgorithm().equals("RSA")) {
      LOG.error("Private Key in the PKCS#12 file is not a RSA key.");
      throw new IOException("Given file does not include a RSA key!");
    }

    java.security.interfaces.RSAPrivateKey jcaRsaPrivateKey = (java.security.interfaces.RSAPrivateKey) jcaPrivateKey;

    LOG.info("got private key");

    Certificate[] certificateChain = keystore.getCertificateChain(keyAlias);

    X509Certificate userCertificate = (X509Certificate) certificateChain[0];
    String userCommonName = Util.getCommontName(userCertificate.getSubjectX500Principal());
    MessageDigest sha1 = MessageDigest.getInstance("SHA1");
    byte[] encodedCert = userCertificate.getEncoded();
    byte[] certificateFingerprint = sha1.digest(encodedCert);
    boolean[] keyUsage = userCertificate.getKeyUsage();

    LOG.info("got user certificate");
    LOG.info("##################################################");
    LOG.info("creating private key object on the card... ");

    // check out what attributes of the keys we may set using the mechanism info
    MechanismInfo signatureMechanismInfo;
    if (Util.supports(token, CKM_RSA_PKCS)) {
      signatureMechanismInfo = token.getMechanismInfo(Mechanism.get(CKM_RSA_PKCS));
    } else if (Util.supports(token, CKM_RSA_X_509)) {
      signatureMechanismInfo = token.getMechanismInfo(Mechanism.get(CKM_RSA_X_509));
    } else if (Util.supports(token, CKM_RSA_9796)) {
      signatureMechanismInfo = token.getMechanismInfo(Mechanism.get(CKM_RSA_9796));
    } else if (Util.supports(token, CKM_RSA_PKCS_OAEP)) {
      signatureMechanismInfo = token.getMechanismInfo(Mechanism.get(CKM_RSA_PKCS_OAEP));
    } else {
      signatureMechanismInfo = null;
    }

    // create private key object template
    String keyLabel = userCommonName + "'s " + Util.getRdnValue(userCertificate.getIssuerX500Principal(), "O");

    byte[] extnValue = userCertificate.getExtensionValue("2.5.29.14");
    byte[] newObjectID;
    if (extnValue != null) {
      newObjectID = Arrays.copyOfRange(extnValue, 4, extnValue.length);
      if (newObjectID.length != 20) {
        throw new IllegalStateException("invalid extension SubjectKeyIdentifier");
      }
    } else {
      // then we simply take the fingerprint of the certificate
      newObjectID = certificateFingerprint;
    }

    AttributeVector p11RsaPrivateKey = newPrivateKey(CKK_RSA)
        .attr(CKA_SENSITIVE, true).attr(CKA_TOKEN, true)
        .attr(CKA_PRIVATE, true).attr(CKA_LABEL, keyLabel).attr(CKA_ID, newObjectID)
        .attr(CKA_SUBJECT, userCertificate.getSubjectX500Principal().getEncoded());

    if (keyUsage != null) {
      // set the attributes in a way netscape does, this should work with most
      // tokens
      if (signatureMechanismInfo != null) {
        p11RsaPrivateKey
            .attr(CKA_DECRYPT,
                (keyUsage[dataEncipherment] || keyUsage[keyCertSign]) && signatureMechanismInfo.isDecrypt())
            .attr(CKA_SIGN,
                (keyUsage[digitalSignature] || keyUsage[keyCertSign] || keyUsage[cRLSign] || keyUsage[nonRepudiation])
                          && signatureMechanismInfo.isSign())
            .attr(CKA_SIGN_RECOVER,
                (keyUsage[digitalSignature] || keyUsage[keyCertSign] || keyUsage[cRLSign] || keyUsage[nonRepudiation])
                          && signatureMechanismInfo.isSignRecover())
            .attr(CKA_DERIVE, keyUsage[keyAgreement] && signatureMechanismInfo.isDerive())
            .attr(CKA_UNWRAP, keyUsage[keyEncipherment] && signatureMechanismInfo.isUnwrap());
      } else {
        // if we have no mechanism information, we try to set the flags according to the key usage only
        p11RsaPrivateKey.attr(CKA_DECRYPT, keyUsage[dataEncipherment] || keyUsage[keyCertSign])
            .attr(CKA_SIGN, keyUsage[digitalSignature] || keyUsage[keyCertSign]
                                      || keyUsage[cRLSign] || keyUsage[nonRepudiation])
            .attr(CKA_SIGN_RECOVER, keyUsage[digitalSignature] || keyUsage[keyCertSign]
                                      || keyUsage[cRLSign] || keyUsage[nonRepudiation])
            .attr(CKA_DERIVE, keyUsage[keyAgreement])
            .attr(CKA_UNWRAP, keyUsage[keyEncipherment]);
      }
    } else {
      // if there is no key-usage extension in the certificate, try to set all
      // flags according to the mechanism info
      if (signatureMechanismInfo != null) {
        p11RsaPrivateKey.attr(CKA_SIGN, signatureMechanismInfo.isSign())
            .attr(CKA_SIGN_RECOVER, signatureMechanismInfo.isSignRecover())
            .attr(CKA_DECRYPT, signatureMechanismInfo.isDecrypt())
            .attr(CKA_DERIVE, signatureMechanismInfo.isDerive())
            .attr(CKA_UNWRAP, signatureMechanismInfo.isUnwrap());
      } else {
        // if we have neither mechanism info nor key usage we just try all
        p11RsaPrivateKey.attr(CKA_SIGN, true)
            .attr(CKA_SIGN_RECOVER, true)
            .attr(CKA_DECRYPT, true)
            .attr(CKA_DERIVE, true)
            .attr(CKA_UNWRAP, true);
      }
    }

    p11RsaPrivateKey.attr(CKA_MODULUS, jcaRsaPrivateKey.getModulus())
        .attr(CKA_PRIVATE_EXPONENT, jcaRsaPrivateKey.getPrivateExponent())
        .attr(CKA_PUBLIC_EXPONENT, ((RSAPublicKey) userCertificate.getPublicKey()).getPublicExponent());

    if (jcaRsaPrivateKey instanceof RSAPrivateCrtKey) {
      // if we have the CRT field, we write it to the card
      // e.g. gemsafe seems to need it
      RSAPrivateCrtKey crtKey = (RSAPrivateCrtKey) jcaRsaPrivateKey;
      p11RsaPrivateKey.attr(CKA_PRIME_1, crtKey.getPrimeP())
          .attr(CKA_PRIME_2, crtKey.getPrimeQ())
          .attr(CKA_EXPONENT_1, crtKey.getPrimeExponentP())
          .attr(CKA_EXPONENT_1, crtKey.getPrimeExponentQ())
          .attr(CKA_COEFFICIENT, crtKey.getCrtCoefficient());
    }

    LOG.info("{}", p11RsaPrivateKey);

    List<Long> newP1kcs11Objects = new ArrayList<>();
    try {
      newP1kcs11Objects.add(session.createObject(p11RsaPrivateKey));

      LOG.info("##################################################");
      LOG.info("creating certificate object on the card... ");

      // create certificate object template
      AttributeVector certTemp = new AttributeVector()
          .attr(CKA_CLASS, CKO_CERTIFICATE)
          .attr(CKA_CERTIFICATE_TYPE, CKC_X_509)
          .attr(CKA_TOKEN, true)
          .attr(CKA_PRIVATE, false)
          .attr(CKA_ID, newObjectID)
          .attr(CKA_LABEL, keyLabel)
          .attr(CKA_SUBJECT, userCertificate.getSubjectX500Principal().getEncoded())
          .attr(CKA_ISSUER, userCertificate.getIssuerX500Principal().getEncoded())
          .attr(CKA_SERIAL_NUMBER, Util.encodedAsn1Integer(userCertificate.getSerialNumber()))
          .attr(CKA_VALUE, userCertificate.getEncoded());

      LOG.info("{}", certTemp);
      newP1kcs11Objects.add(session.createObject(certTemp));
    } finally {
      for (Long m : newP1kcs11Objects) {
        session.destroyObject(m);
      }
    }

    LOG.info("##################################################");
  }

}
