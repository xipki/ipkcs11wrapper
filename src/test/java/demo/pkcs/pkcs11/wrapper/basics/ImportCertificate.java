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
import org.junit.Test;
import org.xipki.pkcs11.*;

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

import static org.xipki.pkcs11.PKCS11Constants.*;

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

    AttributeVector searchTemplate = new AttributeVector();
    if (publicKey.getAlgorithm().equalsIgnoreCase("RSA")) {
      RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
      searchTemplate.class_(CKO_PRIVATE_KEY).keyType(CKK_RSA).modulus(rsaPublicKey.getModulus());
    } else if (publicKey.getAlgorithm().equalsIgnoreCase("DSA")) {
      DSAParams dsaParams = ((DSAPublicKey) publicKey).getParams();
      searchTemplate.class_(CKO_PRIVATE_KEY).keyType(CKK_DSA)
          .base(dsaParams.getG()).prime(dsaParams.getP()).subprime(dsaParams.getQ());
    } else if (publicKey.getAlgorithm().equalsIgnoreCase("DH")
        || publicKey.getAlgorithm().equalsIgnoreCase("DiffieHellman")) {
      DHParameterSpec dhParams = ((DHPublicKey) publicKey).getParams();
      searchTemplate.class_(CKO_PRIVATE_KEY).keyType(CKK_DSA).base(dhParams.getG()).prime(dhParams.getP());
    }

    byte[] objectID = null;
    if (searchTemplate != null) {
      session.findObjectsInit(searchTemplate);
      long[] foundKeyObjects = session.findObjects(1);
      if (foundKeyObjects.length > 0) {
        long foundKey = foundKeyObjects[0];
        objectID = session.getByteArrayAttrValue(foundKey, CKA_ID);
        LOG.info("found a corresponding key on the token:\n{}", foundKey);
      } else {
        LOG.info("found no corresponding key on the token.");
      }
      session.findObjectsFinal();
    } else {
      LOG.info("public key is neither RSA, DSA nor DH.");
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
