// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.
//
// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.wrapper.util;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;

/**
 * This class contains only static methods. It is the place for all functions
 * that are used by several classes in this package.
 */
public class Util {

  public static String getCommonName(X500Principal name) {
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

}
