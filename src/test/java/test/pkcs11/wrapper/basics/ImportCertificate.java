// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.
//
// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.wrapper.basics;

import org.junit.Test;
import org.xipki.pkcs11.wrapper.*;
import test.pkcs11.wrapper.TestBase;
import test.pkcs11.wrapper.util.Util;

import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.security.auth.x500.X500Principal;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import static org.xipki.pkcs11.wrapper.PKCS11Constants.*;

/**
 * This demo program imports a given X.509 certificate onto a PKCS#11 token.
 */
public class ImportCertificate extends TestBase {

  private static final String resourceFile = "/demo_cert.der";

  @Test
  public void main() throws PKCS11Exception, CertificateException, NoSuchAlgorithmException {
    Token token = getNonNullToken();
    TokenInfo tokenInfo = token.getTokenInfo();

    LOG.info("##################################################");
    LOG.info("Information of Token:\n{}", tokenInfo);
    LOG.info("##################################################");

    Session session = openReadWriteSession(token);
    try {
      main0(session);
    } finally {
      session.closeSession();
    }
  }

  private void main0(Session session) throws PKCS11Exception, CertificateException, NoSuchAlgorithmException {
    LOG.info("Reading certificate from resource file: {}", resourceFile);

    // parse certificate
    CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
    InputStream inputStream = getResourceAsStream(resourceFile);
    Collection<? extends Certificate> certChain = certificateFactory.generateCertificates(inputStream);
    if (certChain.size() < 1) {
      LOG.error("Did not find any certificate in the given input file.");
      throw new CertificateException("No certificate found!");
    }
    X509Certificate x509Certificate = (X509Certificate) certChain.iterator().next();
    certChain.remove(x509Certificate);

    LOG.info("##################################################");
    LOG.info("Searching for corresponding private key on token.");

    PublicKey publicKey = x509Certificate.getPublicKey();

    AttributeVector searchTemplate;
    if (publicKey.getAlgorithm().equalsIgnoreCase("RSA")) {
      RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
      searchTemplate = AttributeVector.newRSAPrivateKey().modulus(rsaPublicKey.getModulus());
    } else if (publicKey.getAlgorithm().equalsIgnoreCase("DSA")) {
      DSAParams dsaParams = ((DSAPublicKey) publicKey).getParams();
      searchTemplate = AttributeVector.newDSAPrivateKey()
          .base(dsaParams.getG()).prime(dsaParams.getP()).subprime(dsaParams.getQ());
    } else if (publicKey.getAlgorithm().equalsIgnoreCase("DH")
        || publicKey.getAlgorithm().equalsIgnoreCase("DiffieHellman")) {
      DHParameterSpec dhParams = ((DHPublicKey) publicKey).getParams();
      searchTemplate = AttributeVector.newPrivateKey(CKK_DSA).base(dhParams.getG()).prime(dhParams.getP());
    } else {
      searchTemplate = null;
    }

    byte[] objectID = null;
    if (searchTemplate != null) {
      long[] foundKeyObjects = session.findObjectsSingle(searchTemplate, 1);
      if (foundKeyObjects.length > 0) {
        long foundKey = foundKeyObjects[0];
        objectID = session.getByteArrayAttrValue(foundKey, CKA_ID);
        LOG.info("found a corresponding key on the token:\n{}", foundKey);
      } else {
        LOG.info("found no corresponding key on the token.");
      }
    } else {
      LOG.info("private key is neither RSA, DSA nor DH.");
    }

    LOG.info("##################################################");
    LOG.info("Create certificate object(s) on token.");

    // start with user cert
    X509Certificate currentCertificate = x509Certificate;
    boolean importedCompleteChain = false;

    List<Long> importedObjects = new ArrayList<>();

    try {
      while (!importedCompleteChain) {
        // create certificate object template
        X500Principal subjectName = currentCertificate.getSubjectX500Principal();
        X500Principal issuerName = currentCertificate.getIssuerX500Principal();
        byte[] encodedSubject = subjectName.getEncoded();
        byte[] encodedIssuer = issuerName.getEncoded();

        String subjectCommonName = Util.getCommontName(subjectName);
        String issuerCommonName = Util.getCommontName(issuerName);
        String label = subjectCommonName + "'s " +
            ((issuerCommonName != null) ? issuerCommonName + " " : "") + "Certificate";

        byte[] newObjectID;
        // if we need a new object ID, create one
        if (objectID == null) {
          MessageDigest digest = MessageDigest.getInstance("SHA-1");

          if (publicKey instanceof RSAPublicKey) {
            newObjectID = ((RSAPublicKey) publicKey).getModulus().toByteArray();
            newObjectID = digest.digest(newObjectID);
          } else if (publicKey instanceof DSAPublicKey) {
            newObjectID = ((DSAPublicKey) publicKey).getY().toByteArray();
            newObjectID = digest.digest(newObjectID);
          } else {
            byte[] encodedCert = currentCertificate.getEncoded();
            newObjectID = digest.digest(encodedCert);
          }
        } else {
          // we already got one from a corresponding private key before
          newObjectID = objectID;
        }

        byte[] encodedAsn1serialNumber = Util.encodedAsn1Integer(currentCertificate.getSerialNumber());

        AttributeVector pkcs11X509PublicKeyCertificate = AttributeVector.newCertificate(CKC_X_509)
            .token(true).private_(false).label(label).id(newObjectID).issuer(encodedIssuer)
            .subject(encodedSubject).serialNumber(encodedAsn1serialNumber).value(currentCertificate.getEncoded());

        LOG.info("{}", pkcs11X509PublicKeyCertificate);
        LOG.info("___________________________________________________");
        importedObjects.add(session.createObject(pkcs11X509PublicKeyCertificate));

        if (certChain.size() > 0) {
          currentCertificate = (X509Certificate) certChain.iterator().next();
          certChain.remove(currentCertificate);
          objectID = null; // do not use the same ID for other certificates
        } else {
          importedCompleteChain = true;
        }
      }
    } finally {
      // delete the objects just created
      for (Long objHandle : importedObjects) {
        session.destroyObject(objHandle);
      }
    }

    LOG.info("##################################################");
  }

}
