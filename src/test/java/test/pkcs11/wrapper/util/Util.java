// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.
//
// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.wrapper.util;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;
import org.xipki.pkcs11.wrapper.*;
import org.xipki.util.Args;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.math.BigInteger;

import static org.xipki.pkcs11.wrapper.PKCS11Constants.*;

/**
 * This class contains only static methods. It is the place for all functions
 * that are used by several classes in this package.
 */
public class Util {

  /**
   * Lists all available tokens of the given module and lets the user select
   * one, if there is more than one available.
   *
   * @param pkcs11Module
   *          The PKCS#11 module to use.
   * @return The selected token or null, if no token is available or the user
   *         canceled the action.
   * @exception PKCS11Exception
   *              If listing the tokens failed.
   */
  public static Token selectToken(PKCS11Module pkcs11Module) throws PKCS11Exception {
    return selectToken(pkcs11Module, null);
  }

  /**
   * Lists all available tokens of the given module and lets the user select
   * one, if there is more than one available. Supports token preselection.
   *
   * @param pkcs11Module
   *          The PKCS#11 module to use.
   * @param slotIndex
   *          The slot index, beginning with 0.
   * @return The selected token or null, if no token is available or the user
   *         canceled the action.
   * @exception PKCS11Exception
   *              If listing the tokens failed.
   */
  public static Token selectToken(PKCS11Module pkcs11Module, Integer slotIndex) throws PKCS11Exception {
    if (pkcs11Module == null) {
      throw new NullPointerException("Argument pkcs11Module must not be null.");
    }

    Slot[] slots = pkcs11Module.getSlotList(true);
    if (slots == null || slots.length == 0) {
      return null;
    } else if (slotIndex != null) {
      if (slotIndex >= slots.length) {
        return null;
      } else {
        Token token = slots[slotIndex].getToken();
        if (!token.getTokenInfo().hasFlagBit(CKF_TOKEN_INITIALIZED)) {
          throw new IllegalArgumentException("token is not initialized");
        } else {
          return token;
        }
      }
    } else {
      // return the first initialized token
      for (Slot slot : slots) {
        if (slot.getToken().getTokenInfo().hasFlagBit(CKF_TOKEN_INITIALIZED)) {
          return slot.getToken();
        }
      }

      throw new IllegalArgumentException("found no initialized token");
    }
  }

  /**
   * Opens an authorized session for the given token. If the token requires the
   * user to login for private operations, the method loggs in the user.
   *
   * @param token
   *          The token to open a session for.
   * @param rwSession
   *          If the session should be a read-write session. This may be
   *          Token.SessionReadWriteBehavior.RO_SESSION or
   *          Token.SessionReadWriteBehavior.RW_SESSION.
   * @param pin
   *          PIN.
   * @return The selected token or null, if no token is available or the user
   *         canceled the action.
   * @exception PKCS11Exception
   *              If listing the tokens failed.
   */
  public static Session openAuthorizedSession(Token token, boolean rwSession, char[] pin)
      throws PKCS11Exception {
    if (token == null) {
      throw new NullPointerException("Argument 'token' must not be null.");
    }

    Session session = token.openSession(rwSession);

    TokenInfo tokenInfo = token.getTokenInfo();
    if (tokenInfo.hasFlagBit(CKF_LOGIN_REQUIRED)) {
      if (tokenInfo.hasFlagBit(CKF_PROTECTED_AUTHENTICATION_PATH)) {
        System.out.print("Please enter the user-PIN at the PIN-pad of your reader.");
        System.out.flush();
        // the token prompts the PIN by other means; e.g. PIN-pad
        session.login(CKU_USER, null);
      } else {
        try {
          session.login(CKU_USER, pin);
        } catch (PKCS11Exception ex) {
          if (ex.getErrorCode() != CKR_USER_ALREADY_LOGGED_IN) {
            throw ex;
          }
        }
      }
    }

    return session;
  }

  public static String getCommontName(X500Principal name) {
    return getRdnValue(name, "CN");
  }

  public static String getRdnValue(X500Principal name, String rdnType) {
    String dn = name.getName();
    LdapName ldapDN;
    try {
      ldapDN = new LdapName(dn);
    } catch (InvalidNameException ex) {
      throw new IllegalArgumentException("invalid LdapName", ex);
    }
    for(Rdn rdn: ldapDN.getRdns()) {
      if (rdn.getType().equalsIgnoreCase(rdnType)) {
        Object obj = rdn.getValue();
        if (obj instanceof String) {
          return (String) obj;
        } else {
          return obj.toString();
        }
      }
    }

    return null;
  }

  public static byte[] encodedAsn1Integer(BigInteger bn) {
    byte[] encodedBn = bn.toByteArray();
    int len = encodedBn.length;

    byte[] encoded;
    int idx = 1;
    if (len > 0xFFFF) {
      encoded = new byte[5 + len];
      encoded[idx++] = (byte) 0x83;
      encoded[idx++] = (byte) (len >> 16);
      encoded[idx++] = (byte) (len >> 8);
      encoded[idx++] = (byte)  len;
    } else if(len > 0x7F) {
      encoded = new byte[4 + len];
      encoded[idx++] = (byte) 0x82;
      encoded[idx++] = (byte) (len >> 8);
      encoded[idx++] = (byte)  len;
    } else {
      encoded = new byte[2 + len];
      encoded[idx++] = (byte) len;
    }
    encoded[0] = 2; // tag
    System.arraycopy(encodedBn, 0, encoded, idx, encodedBn.length);
    return encoded;
  }

  public static boolean supports(Token token, long mechCode) throws PKCS11Exception {
    for (long mech : token.getMechanismList()) {
      if (mech == mechCode) {
        return true;
      }
    }
    return false;
  }

  public static byte[] dsaSigPlainToX962(byte[] signature) {
    Args.notNull(signature, "signature");
    if (signature.length % 2 != 0) {
      throw new IllegalArgumentException("signature.length must be even, but is odd");
    }
    byte[] ba = new byte[signature.length / 2];
    ASN1EncodableVector sigder = new ASN1EncodableVector();

    System.arraycopy(signature, 0, ba, 0, ba.length);
    sigder.add(new ASN1Integer(new BigInteger(1, ba)));

    System.arraycopy(signature, ba.length, ba, 0, ba.length);
    sigder.add(new ASN1Integer(new BigInteger(1, ba)));

    DERSequence seq = new DERSequence(sigder);
    try {
      return seq.getEncoded();
    } catch (IOException ex) {
      throw new IllegalArgumentException("IOException, message: " + ex.getMessage(), ex);
    }
  }

}
