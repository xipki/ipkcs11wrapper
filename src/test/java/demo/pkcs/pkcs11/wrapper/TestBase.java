// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package demo.pkcs.pkcs11.wrapper;

import demo.pkcs.pkcs11.wrapper.util.KeyUtil;
import demo.pkcs.pkcs11.wrapper.util.Util;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.pkcs11.*;
import org.xipki.pkcs11.params.CkParams;
import org.xipki.util.Hex;

import java.io.InputStream;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.Random;

import static org.xipki.pkcs11.PKCS11Constants.*;

public class TestBase {

  // plen: 2048, qlen: 256
  public static final BigInteger DSA_P = new BigInteger(
      "E13AC60336C29FAF1B48393D80C74B781E15E23E3F59F0827190FF016720A8E0"
      + "DAC2D4FF699EBA2196E1B9815ECAE0506441A4BC4DA97E97F2723A808EF6B634"
      + "3968906137B04B23F6540FC4B9D7C0A46635B6D52AEDD08347370B9BE43A7222"
      + "807655CB5ED480F4C66128357D0E0A2C62785DC38160645661FA569ADCE46D3B"
      + "3BFAB114613436242855F5717143D51FB365972F6B8695C2186CBAD1E8C5B4D3"
      + "1AD70876EBDD1C2191C5FB6C4804E0D38CBAA054FC7AFD25E0F2735F726D8A31"
      + "DE97431BFB6CF1AD563811830131E7D5E5117D92389406EF436A8077E69B8795"
      + "18436E33A9F221AB3A331680D0345B316F5BEBDA8FBF70612BEC734272E760BF", 16);

  public static final BigInteger DSA_Q = new BigInteger(
      "9CF2A23A8F95FEFB0CA67212991AC172FDD3F4D70401B684C3E4223D46D090E5", 16);

  public static final BigInteger DSA_G = new BigInteger(
      "1CBEF6EEB9E73C5997BF64CA8BCC33CDC6AFC5601B86FDE1B0AC4C34066DFBF9"
      + "9B80CCE264C909B32CF88CE09CB73476C0A6E701092E09C93507FE3EBD425B75"
      + "8AE3C5E3FDC1076AF237C5EF40A790CF6555EB3408BCEF212AC5A1C125A7183D"
      + "24935554C0D258BF1F6A5A6D05C0879DB92D32A0BCA3A85D42F9B436AE97E62E"
      + "0E30E53B8690D8585493D291969791EA0F3B062645440587C031CD2880481E0B"
      + "E3253A28EFFF3ACEB338A2FE4DB8F652E0FDA277268B73D5E532CF9E4E2A1CAB"
      + "738920F760012DD9389F35E0AA7C8528CE173934529397DABDFAA1E77AF83FAD"
      + "629AC102596885A06B5C670FFA838D37EB55FE7179A88F6FF927B37E0F827726", 16);

  private static String modulePath;

  private static String modulePin;

  private static Integer slotIndex;

  private static PKCS11Module module;

  private static RuntimeException initException;

  private static int speedThreads;

  private static String speedDuration;

  private static final SecureRandom random = new SecureRandom();

  protected final Logger LOG = LoggerFactory.getLogger(getClass());

  static {
    Properties props = new Properties();
    try {
      props.load(TestBase.class.getResourceAsStream("/pkcs11.properties"));
      modulePath = props.getProperty("module.path");
      modulePin = props.getProperty("module.pin");
      String str = props.getProperty("module.slotIndex");
      slotIndex = (str == null) ? null : Integer.parseInt(str);
      module = PKCS11Module.getInstance(modulePath);

      speedThreads = Integer.getInteger("speed.threads", 2);
      speedDuration = System.getProperty("speed.duration", "3s");
      module.initialize();

      Runtime.getRuntime().addShutdownHook(new Thread() {
        public void run() {
          System.out.println("finalizing module");
          try {
            module.finalize(null);
          } catch (PKCS11Exception ex) {
            ex.printStackTrace();
          }
        }
      });
    } catch (Exception ex) {
      initException = new RuntimeException(ex);
    }
  }

  protected char[] getModulePin() {
    return modulePin.toCharArray();
  }

  protected Token getNonNullToken() throws PKCS11Exception {
    Token token = getToken();
    if (token == null) {
      LOG.error("We have no token to proceed. Finished.");
      throw new PKCS11Exception(CKR_DEVICE_ERROR);
    }
    return token;
  }

  protected Token getToken() throws PKCS11Exception {
    if (initException != null) {
      throw initException;
    }
    return Util.selectToken(module, slotIndex);
  }

  protected PKCS11Module getModule() {
    if (initException != null) {
      throw initException;
    }
    return module;
  }

  protected Session openReadOnlySession(Token token) throws PKCS11Exception {
    return Util.openAuthorizedSession(token, false, modulePin == null ? null : modulePin.toCharArray());
  }

  protected Session openReadOnlySession() throws PKCS11Exception {
    return openReadOnlySession(getToken());
  }

  protected Session openReadWriteSession(Token token) throws PKCS11Exception {
    return Util.openAuthorizedSession(token, true, modulePin == null ? null : modulePin.toCharArray());
  }

  protected Session openReadWriteSession() throws PKCS11Exception {
    return openReadWriteSession(getToken());
  }

  protected String getSpeedTestDuration() {
    return speedDuration;
  }

  protected int getSpeedTestThreads() {
    return speedThreads;
  }

  protected InputStream getResourceAsStream(String path) {
    return getClass().getResourceAsStream(path);
  }

  public static byte[] randomBytes(int len) {
    byte[] ret = new byte[len];
    random.nextBytes(ret);
    return ret;
  }

  protected void assertSupport(Token token, long mechCode) throws PKCS11Exception {
    if (!Util.supports(token, mechCode)) {
      String msg = "Mechanism " + ckmCodeToName(mechCode) + " is not supported";
      LOG.error(msg);
      throw new PKCS11Exception(CKR_MECHANISM_INVALID);
    }
  }

  protected Mechanism getSupportedMechanism(Token token, long mechCode) throws PKCS11Exception {
    assertSupport(token, mechCode);
    return new Mechanism(mechCode);
  }

  protected Mechanism getSupportedMechanism(Token token, long mechCode, CkParams parameters) throws PKCS11Exception {
    assertSupport(token, mechCode);
    return new Mechanism(mechCode, parameters);
  }

  protected PKCS11KeyPair generateRSAKeypair(Token token, Session session, int keysize, boolean inToken)
      throws PKCS11Exception {
    Mechanism keyPairGenMechanism = getSupportedMechanism(token, CKM_RSA_PKCS_KEY_PAIR_GEN);
    AttributeVector publicKeyTemplate = newPublicKey(CKK_RSA);
    AttributeVector privateKeyTemplate = newPrivateKey(CKK_RSA);

    // set the general attributes for the public key
    byte[] id = new byte[20];
    new Random().nextBytes(id);

    publicKeyTemplate.modulusBits(keysize).token(inToken).id(id).verify(true);
    privateKeyTemplate.sensitive(true).token(inToken).private_(true).id(id).sign(true);

    return session.generateKeyPair(keyPairGenMechanism, publicKeyTemplate, privateKeyTemplate);
  }

  protected PKCS11KeyPair generateECKeypair(Token token, Session session, byte[] ecParams, boolean inToken)
      throws PKCS11Exception {
    return generateECKeypair(CKM_EC_KEY_PAIR_GEN, CKK_EC, token, session, ecParams, inToken);
  }

  protected PKCS11KeyPair generateEdDSAKeypair(Token token, Session session, byte[] ecParams, boolean inToken)
      throws PKCS11Exception {
    return generateECKeypair(CKM_EC_EDWARDS_KEY_PAIR_GEN, CKK_EC_EDWARDS, token, session, ecParams, inToken);
  }

  private PKCS11KeyPair generateECKeypair(
      long keyGenMechanism, long keyType, Token token, Session session, byte[] ecParams, boolean inToken)
      throws PKCS11Exception {
    Mechanism keyPairGenMechanism = getSupportedMechanism(token, keyGenMechanism);
    byte[] id = new byte[20];
    new Random().nextBytes(id);

    AttributeVector publicKeyTemplate  = newPublicKey(keyType) .ecParams(ecParams).token(inToken).id(id).verify(true);
    AttributeVector privateKeyTemplate = newPrivateKey(keyType).sensitive(true)
        .token(inToken).private_(true).id(id).sign(true);

    return session.generateKeyPair(keyPairGenMechanism, publicKeyTemplate, privateKeyTemplate);
  }

  protected PKCS11KeyPair generateDSAKeypair(Token token, Session session, boolean inToken)
      throws PKCS11Exception {
    Mechanism keyPairGenMechanism = getSupportedMechanism(token, CKM_DSA_KEY_PAIR_GEN);
    byte[] id = new byte[20];
    new Random().nextBytes(id);

    AttributeVector publicKeyTemplate = newPublicKey(CKK_DSA).prime(DSA_P).subprime(DSA_Q).base(DSA_G)
        .token(inToken).id(id).verify(true);

    AttributeVector privateKeyTemplate = newPrivateKey(CKK_DSA).sensitive(true).token(inToken).private_(true)
        .id(id).sign(true);

    return session.generateKeyPair(keyPairGenMechanism, publicKeyTemplate, privateKeyTemplate);
  }

  protected AttributeVector newSecretKey(long keyType) {
    return AttributeVector.newSecretKey(keyType);
  }

  protected AttributeVector newPublicKey(long keyTye) {
    return AttributeVector.newPublicKey(keyTye);
  }

  protected AttributeVector newPrivateKey(long keyType) {
    return AttributeVector.newPrivateKey(keyType);
  }

  protected static PublicKey generateJCEPublicKey(Session session, long p11Key, Long keyType)
      throws InvalidKeySpecException, PKCS11Exception {
    if (keyType == null) {
      keyType = session.getLongAttrValue(p11Key, CKA_KEY_TYPE);
    }

    if (keyType == CKK_RSA) {
      AttributeVector attrValues = session.getAttrValues(p11Key, CKA_MODULUS, CKA_PUBLIC_EXPONENT);
      return KeyUtil.generateRSAPublicKey(new RSAPublicKeySpec(attrValues.modulus(), attrValues.publicExponent()));
    } else if (keyType == CKK_DSA) {
      AttributeVector attrValues = session.getAttrValues(p11Key,
          CKA_VALUE, CKA_PRIME, CKA_SUBPRIME, CKA_BASE); // y, p, q, g

      DSAPublicKeySpec keySpec = new DSAPublicKeySpec(new BigInteger(1, attrValues.value()),
          attrValues.prime(), attrValues.subprime(), attrValues.base());
      return KeyUtil.generateDSAPublicKey(keySpec);
    } else if (keyType == CKK_EC || keyType == CKK_EC_EDWARDS
        || keyType == CKK_EC_MONTGOMERY || keyType == CKK_VENDOR_SM2) {
      byte[] encodedPoint = session.getByteArrayAttrValue(p11Key, CKA_EC_POINT);
      encodedPoint = ASN1OctetString.getInstance(encodedPoint).getOctets();

      byte[] ecParams;
      try {
        ecParams = session.getByteArrayAttrValue(p11Key, CKA_EC_PARAMS);
      } catch (PKCS11Exception ex) {
        if (keyType == CKK_VENDOR_SM2) {
          // GMObjectIdentifiers.sm2p256v1.getEncoded();
          ecParams = Hex.decode("06082a811ccf5501822d");
        } else {
          throw ex;
        }
      }

      if (keyType == CKK_EC_EDWARDS || keyType == CKK_EC_MONTGOMERY) {
        ASN1ObjectIdentifier algOid = ASN1ObjectIdentifier.getInstance(ecParams);
        SubjectPublicKeyInfo pkInfo = new SubjectPublicKeyInfo(new AlgorithmIdentifier(algOid), encodedPoint);
        return KeyUtil.generatePublicKey(pkInfo);
      } else {
        return KeyUtil.createECPublicKey(ecParams, encodedPoint);
      }
    } else {
      throw new InvalidKeySpecException("unknown publicKey type " + ckkCodeToName(keyType));
    }
  } // method generatePublicKey

  protected static List<Long> getMechanismList(Token token) throws PKCS11Exception {
    long[] supportedMechanisms = token.getMechanismList();
    List<Long> list = new ArrayList<>(supportedMechanisms.length);
    for (long mech : supportedMechanisms) {
      list.add(mech);
    }
    return list;
  }

}
