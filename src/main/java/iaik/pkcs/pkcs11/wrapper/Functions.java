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

package iaik.pkcs.pkcs11.wrapper;

import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Util;

import java.util.*;

/**
 * This class contains only static methods. It is the place for all functions
 * that are used by several classes in this package.
 *
 * @author Karl Scheibelhofer
 * @author Martin Schlaeffer
 * @author Lijun Liao
 */
public class Functions implements PKCS11Constants {

  private static class Hex {

    private static final char[] DIGITS = {'0', '1', '2', '3', '4',
        '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    private static final char[] UPPER_DIGITS = {'0', '1', '2', '3', '4',
        '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

    private static final int[] LINTS = new int['f' + 1];
    private static final int[] HINTS = new int[LINTS.length];

    static {
      for (int i = 0; i < DIGITS.length; i++) {
        LINTS[DIGITS[i]] = i;
      }

      for (int i = 10; i < UPPER_DIGITS.length; i++) {
        LINTS[UPPER_DIGITS[i]] = i;
      }

      for (int i = 0; i < LINTS.length; i++) {
        HINTS[i] = LINTS[i] << 4;
      }
    }

    public static String encode(byte[] bytes) {
      return new String(encodeToChars(bytes));
    }

    public static char[] encodeToChars(byte[] data) {
      int len = data.length;

      char[] out = new char[len << 1];

      // two characters form the hex value.
      for (int i = 0, j = 0; i < len; i++) {
        out[j++] = DIGITS[(0xF0 & data[i]) >>> 4];
        out[j++] = DIGITS[0x0F & data[i]];
      }

      return out;
    }

    public static byte[] decode(String hex) {
      char[] data = hex.toCharArray();
      int len = data.length;

      if ((len & 0x01) != 0) {
        throw new IllegalArgumentException("Odd number of characters.");
      }

      byte[] out = new byte[len >> 1];

      // two characters form the hex value.
      for (int i = 0, j = 0; j < len; i++) {
        out[i] = (byte) (HINTS[data[j++]] | LINTS[data[j++]]);
      }

      return out;
    }

  }

  /**
   * The name of the properties file that holds the names of the PKCS#11
   * mechanism-codes.
   */
  private static final String CKM_CODE_PROPERTIES = "/iaik/pkcs/pkcs11/wrapper/ckm.properties";

  /**
   * The name of the properties file that holds the names of the PKCS#11
   * mechanism-codes.
   */
  private static final String CKR_CODE_PROPERTIES = "/iaik/pkcs/pkcs11/wrapper/ckr.properties";

  /**
   * True, if the mapping of mechanism codes to PKCS#11 mechanism names is
   * available.
   */
  private static boolean mechCodeNamesAvailable;

  /**
   * Maps mechanism codes as Long to their names as Strings.
   */
  private static Map<Long, String> mechNames;

  /**
   * Maps mechanism name as String to their code as Long.
   */
  private static Map<String, Long> mechNameToCodes;

  private static final Map<Long, String> hashMechCodeToHashNames;

  /**
   * True, if the mapping of error codes to PKCS#11 error names is available.
   */
  private static boolean errorCodeNamesAvailable;

  /**
   * The properties object that holds the mapping from error-code to the name
   * of the PKCS#11 error.
   */
  private static Map<Long, String> errorCodeNames;

  // MGFs (CKG_*)
  private static final Map<Long, String> mgfNames = new HashMap<>();

  /**
   * A table holding string representations for all known key types. Table key
   * is the key type as Long object.
   */
  protected static Hashtable<Long, String> objectClassNames;

  /**
   * A table holding string representations for all known key types. Table key
   * is the key type as Long object.
   */
  protected static Hashtable<Long, String> keyTypeNames;

  static {
    hashMechCodeToHashNames = new HashMap<>();
    hashMechCodeToHashNames.put(CKM_SHA_1,      "SHA1");
    hashMechCodeToHashNames.put(CKM_SHA224,     "SHA224");
    hashMechCodeToHashNames.put(CKM_SHA256,     "SHA256");
    hashMechCodeToHashNames.put(CKM_SHA384,     "SHA384");
    hashMechCodeToHashNames.put(CKM_SHA512,     "SHA512");
    hashMechCodeToHashNames.put(CKM_SHA512_224, "SHA512/224");
    hashMechCodeToHashNames.put(CKM_SHA512_256, "SHA512/256");
    hashMechCodeToHashNames.put(CKM_SHA3_224,   "SHA3-224");
    hashMechCodeToHashNames.put(CKM_SHA3_256,   "SHA3-256");
    hashMechCodeToHashNames.put(CKM_SHA3_384,   "SHA3-384");
    hashMechCodeToHashNames.put(CKM_SHA3_512,   "SHA3-512");

    mgfNames.put(CKG_MGF1_SHA1,     "CKG_MGF1_SHA1");
    mgfNames.put(CKG_MGF1_SHA256,   "CKG_MGF1_SHA256");
    mgfNames.put(CKG_MGF1_SHA384,   "CKG_MGF1_SHA384");
    mgfNames.put(CKG_MGF1_SHA512,   "CKG_MGF1_SHA512");
    mgfNames.put(CKG_MGF1_SHA224,   "CKG_MGF1_SHA224");
    mgfNames.put(CKG_MGF1_SHA3_224, "CKG_MGF1_SHA3-224");
    mgfNames.put(CKG_MGF1_SHA3_256, "CKG_MGF1_SHA3-256");
    mgfNames.put(CKG_MGF1_SHA3_384, "CKG_MGF1_SHA3-384");
    mgfNames.put(CKG_MGF1_SHA3_512, "CKG_MGF1_SHA3-512");
  }

  /**
   * Converts the long value code of a mechanism to a name.
   *
   * @param mechCode
   *          The code of the mechanism to be converted to a string.
   * @return The string representation of the mechanism.
   */
  public static String mechanismCodeToString(long mechCode) {
    initMechanismMap();
    String name = mechCodeNamesAvailable ? mechNames.get(mechCode) : null;
    return name != null ? name : "Unknown mechanism with code: 0x" + toFullHex(mechCode);
  }

  /**
   * Describes the mechanism in form of &lt;hex digital&gt;(name), like
   * 0x00001082 (CKM_AES_CBC).
   *
   * @param mechCode
   *          The code of the mechanism to be converted to a string.
   * @return The description of the mechanism.
   */
  public static String getMechanismDescription(long mechCode) {
    return String.format("%#010x", mechCode) + " (" + mechanismCodeToString(mechCode) + ")";
  }

  /**
   * Converts the mechanism name to code value.
   *
   * @param mechName
   *          The name of the mechanism to be converted to a code.
   * @return The code representation of the mechanism.
   */
  public static long mechanismStringToCode(String mechName) {
    initMechanismMap();
    Long code = mechCodeNamesAvailable ? mechNameToCodes.get(mechName) : null;
    return (code != null) ? code : -1;
  }

  public static String getMGFName(long id) {
    return mgfNames.get(id);
  }

  private static synchronized void initMechanismMap() {
    // ensure that another thread has not loaded the codes meanwhile
    if (mechNames != null) {
      return;
    }

    // if the names of the defined codes are not yet loaded, load them
    Map<Long, String> codeNameMap = new HashMap<>();
    Map<String, Long> nameCodeMap = new HashMap<>();

    Properties props = new Properties();
    try {
      props.load(Functions.class.getResourceAsStream(CKM_CODE_PROPERTIES));
      for (String propName : props.stringPropertyNames()) {
        String mechNames = props.getProperty(propName);
        StringTokenizer tokens = new StringTokenizer(mechNames, ",");

        if (!tokens.hasMoreTokens()) {
          System.out.println("No name defined for Mechanism code " + propName);
        }

        long code;
        if (propName.startsWith("0x") || propName.startsWith("0X")) {
          code = Long.parseLong(propName.substring(2), 16);
        } else {
          code = Long.parseLong(propName);
        }

        String mainMechName = tokens.nextToken();
        codeNameMap.put(code, mainMechName);

        while (tokens.hasMoreTokens()) {
          nameCodeMap.put(tokens.nextToken(), code);
        }
      }

      codeNameMap.put(CKM_VENDOR_SM2, "CKM_VENDOR_SM2");
      codeNameMap.put(CKM_VENDOR_SM2_ENCRYPT, "CKM_VENDOR_SM2_ENCRYPT");
      codeNameMap.put(CKM_VENDOR_SM2_KEY_PAIR_GEN, "CKM_VENDOR_SM2_KEY_PAIR_GEN");
      codeNameMap.put(CKM_VENDOR_SM2_SM3, "CKM_VENDOR_SM2_SM3");
      codeNameMap.put(CKM_VENDOR_SM3, "CKM_VENDOR_SM3");
      codeNameMap.put(CKM_VENDOR_SM4_CBC, "CKM_VENDOR_SM4_CBC");
      codeNameMap.put(CKM_VENDOR_SM4_ECB, "CKM_VENDOR_SM4_ECB");
      codeNameMap.put(CKM_VENDOR_SM4_KEY_GEN, "CKM_VENDOR_SM4_KEY_GEN");
      codeNameMap.put(CKM_VENDOR_SM4_MAC, "CKM_VENDOR_SM4_MAC");
      codeNameMap.put(CKM_VENDOR_SM4_MAC_GENERAL, "CKM_VENDOR_SM4_MAC_GENERAL");

      Set<Long> codes = codeNameMap.keySet();
      for (Long code : codes) {
        nameCodeMap.put(codeNameMap.get(code), code);
      }

      mechNames = codeNameMap;
      mechNameToCodes = nameCodeMap;
      mechCodeNamesAvailable = true;
    } catch (Exception ex) {
      System.err.println("Could not read properties for code names: " + ex.getMessage());
    }
  }

  /**
   * Converts the long value code of an error to a name.
   *
   * @param errorCode
   *          The code of the error to be converted to a string.
   * @return The string representation of the error.
   */
  public static String errorCodeToString(long errorCode) {
    initErrorCodeMap();

    String name = errorCodeNamesAvailable ? errorCodeNames.get(errorCode) : null;
    return name != null ? name : "Unknown CKR with code: 0x" + toFullHex(errorCode);
  }

  private static synchronized void initErrorCodeMap() {
    // ensure that another thread has not loaded the codes meanwhile
    if (errorCodeNames != null) {
      return;
    }

    // if the names of the defined codes are not yet loaded, load them
    Map<Long, String> codeNamMap = new HashMap<>();
    Properties props = new Properties();
    try {
      props.load(Functions.class.getResourceAsStream(CKR_CODE_PROPERTIES));
      for (String propName : props.stringPropertyNames()) {
        String errorName = props.getProperty(propName);
        long code = (propName.startsWith("0x") || propName.startsWith("0X"))
            ? Long.parseLong(propName.substring(2), 16) : Long.parseLong(propName);
        codeNamMap.put(code, errorName);
      }
      errorCodeNames = codeNamMap;
      errorCodeNamesAvailable = true;
    } catch (Exception ex) {
      System.err.println("Could not read properties for error code names: " + ex.getMessage());
    }
  }

  private static Set<Long> asSet(long[] elements) {
    HashSet<Long> set = new HashSet<>();
    for (long el : elements) {
      set.add(el);
    }
    return set;
  }

  /**
   * Converts a long value to a hexadecimal String of length 16. Includes
   * leading zeros if necessary.
   *
   * @param value
   *          The long value to be converted.
   * @return The hexadecimal string representation of the long value.
   */
  public static String toFullHex(long value) {
    long currentValue = value;
    StringBuilder stringBuffer = new StringBuilder(16);
    final int size = value > 0xFFFFFFFFL ? 16 : 8;
    for (int j = 0; j < size; j++) {
      int currentDigit = (int) currentValue & 0xf;
      stringBuffer.append(Hex.DIGITS[currentDigit]);
      currentValue >>>= 4;
    }

    return stringBuffer.reverse().toString();
  }

  /**
   * Converts a byte array to a hexadecimal String. Each byte is presented by
   * its two digit hex-code; 0x0A -&gt; "0a", 0x00 -&gt; "00". No leading "0x"
   * is included in the result.
   *
   * @param value
   *          the byte array to be converted
   * @return the hexadecimal string representation of the byte array
   */
  public static String toHexString(byte[] value) {
    return Hex.encode(value);
  }

  public static byte[] decodeHex(String encoded) {
    return Hex.decode(encoded);
  }

  public static String getHashAlgName(Mechanism hashMechanism) {
    return getHashAlgName(hashMechanism.getMechanismCode());
  }

  public static String getHashAlgName(long hashMechanism) {
    return hashMechCodeToHashNames.get(hashMechanism);
  }

  /**
   * Get the given certificate type as string.
   *
   * @param certificateType
   *          The certificate type to get as string.
   * @return A string denoting the object certificate type; e.g.
   *         "X.509 Public Key".
   */
  public static String getCertificateTypeName(Long certificateType) {
    Util.requireNonNull("certificateType", certificateType);
    String certificateTypeName;

    if (certificateType == CKC_X_509) {
      certificateTypeName = "X.509 Public Key";
    } else if (certificateType == CKC_X_509_ATTR_CERT) {
      certificateTypeName = "X.509 Attribute";
    } else if ((certificateType & CKC_VENDOR_DEFINED) != 0L) {
      certificateTypeName = "Vendor Defined";
    } else {
      certificateTypeName = "<unknown>";
    }

    return certificateTypeName;
  }


  /**
   * Get the given object class as string.
   *
   * @param objectClass
   *          The object class to get as string.
   * @return A string denoting the object class; e.g. "Private Key".
   */
  public static String getObjectClassName(long objectClass) {
    String objectClassName;
    if ((objectClass & PKCS11Constants.CKO_VENDOR_DEFINED) != 0L) {
      objectClassName = "Vendor Defined";
    } else {
      if (objectClassNames == null) {
        // setup object class names table
        objectClassNames = new Hashtable<>(7);
        objectClassNames.put(CKO_DATA, "Data");
        objectClassNames.put(CKO_CERTIFICATE, "Certificate");
        objectClassNames.put(CKO_PUBLIC_KEY, "Public Key");
        objectClassNames.put(CKO_PRIVATE_KEY, "Private Key");
        objectClassNames.put(CKO_SECRET_KEY, "Secret Key");
        objectClassNames.put(CKO_HW_FEATURE, "Hardware Feature");
        objectClassNames.put(CKO_DOMAIN_PARAMETERS, "Domain Parameters");
      }

      objectClassName = objectClassNames.get(objectClass);
      if (objectClassName == null) {
        objectClassName = "<unknown>";
      }
    }

    return objectClassName;
  }

  /**
   * Get the given key type as string.
   *
   * @param keyType
   *          The key type to get as string.
   * @return A string denoting the key type; e.g. "RSA".
   */
  public static String getKeyTypeName(long keyType) {
    if (keyTypeNames == null) {
      // setup key type names table
      keyTypeNames = new Hashtable<>(24);
      keyTypeNames.put(CKK_RSA, "RSA");
      keyTypeNames.put(CKK_DSA, "DSA");
      keyTypeNames.put(CKK_DH, "DH");
      keyTypeNames.put(CKK_EC, "EC");
      keyTypeNames.put(CKK_EC_EDWARDS, "EC_EDWARDS");
      keyTypeNames.put(CKK_EC_MONTGOMERY, "EC_MONTGOMERY");
      keyTypeNames.put(CKK_X9_42_DH, "X9_42_DH");
      keyTypeNames.put(CKK_KEA, "KEA");
      keyTypeNames.put(CKK_GENERIC_SECRET, "GENERIC_SECRET");
      keyTypeNames.put(CKK_RC2, "RC2");
      keyTypeNames.put(CKK_RC4, "RC4");
      keyTypeNames.put(CKK_DES, "DES");
      keyTypeNames.put(CKK_DES2, "DES2");
      keyTypeNames.put(CKK_DES3, "DES3");
      keyTypeNames.put(CKK_CAST, "CAST");
      keyTypeNames.put(CKK_CAST3, "CAST3");
      keyTypeNames.put(CKK_CAST128, "CAST128");
      keyTypeNames.put(CKK_RC5, "RC5");
      keyTypeNames.put(CKK_IDEA, "IDEA");
      keyTypeNames.put(CKK_SKIPJACK, "SKIPJACK");
      keyTypeNames.put(CKK_BATON, "BATON");
      keyTypeNames.put(CKK_JUNIPER, "JUNIPER");
      keyTypeNames.put(CKK_CDMF, "CDMF");
      keyTypeNames.put(CKK_AES, "AES");
      keyTypeNames.put(CKK_BLOWFISH, "BLOWFISH");
      keyTypeNames.put(CKK_TWOFISH, "TWOFISH");
      keyTypeNames.put(CKK_AES_XTS, "XTS");
      keyTypeNames.put(CKK_CAMELLIA, "CAMELLIA");
      keyTypeNames.put(CKK_ARIA, "ARIA");
      keyTypeNames.put(CKK_SEED, "SEED");
      keyTypeNames.put(CKK_CHACHA20, "CHACHA20");
      keyTypeNames.put(CKK_SALSA20, "SALSA20");
      keyTypeNames.put(CKK_POLY1305, "POLY1305");
      keyTypeNames.put(CKK_VENDOR_SM2, "SM2");
      keyTypeNames.put(CKK_VENDOR_SM4, "SM4");
    }

    String keyTypeName = keyTypeNames.get(keyType);
    if (keyTypeName == null) {
      if ((keyType & PKCS11Constants.CKK_VENDOR_DEFINED) != 0L) {
        keyTypeName = "Vendor Defined";
      } else {
        keyTypeName = "<unknown>";
      }
    }

    return keyTypeName;
  }

  /**
   * Get the given hardware feature type as string.
   *
   * @param hardwareFeatureType
   *          The hardware feature type to get as string.
   * @return A string denoting the object hardware feature type; e.g. "Clock".
   */
  public static String getHardwareFeatureTypeName(long hardwareFeatureType) {
    String hardwareFeatureTypeName;

    if (hardwareFeatureType == CKH_MONOTONIC_COUNTER) {
      hardwareFeatureTypeName = "Monotonic Counter";
    } else if (hardwareFeatureType == CKH_CLOCK) {
      hardwareFeatureTypeName = "Clock";
    } else if (hardwareFeatureType == CKH_USER_INTERFACE) {
      hardwareFeatureTypeName = "User Interface";
    } else if ((hardwareFeatureType & CKH_VENDOR_DEFINED) != 0L) {
      hardwareFeatureTypeName = "Vendor Defined";
    } else {
      hardwareFeatureTypeName = "<unknown>";
    }

    return hardwareFeatureTypeName;
  }

  public static String getUserTypeName(long userType) {
    if (userType == PKCS11Constants.CKU_SO) {
      return "CKU_SO";
    } else if (userType == PKCS11Constants.CKU_USER) {
      return "CKU_USER";
    } else if (userType == PKCS11Constants.CKU_CONTEXT_SPECIFIC) {
      return "CKU_CONTEXT_SPECIFIC";
    } else {
      return "VENDOR_" + userType;
    }
  }

}
