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

  private static class CodeNameMap {

    private final String type;

    private final Map<Long, String> codeNameMap;
    private final Map<String, Long> nameCodeMap;

    CodeNameMap(String type, String resourcePath) {
      this.type = type;
      codeNameMap = new HashMap<>();
      nameCodeMap = new HashMap<>();
      Properties props = new Properties();
      try {
        props.load(Functions.class.getResourceAsStream(resourcePath));
        for (String propName : props.stringPropertyNames()) {
          String mechNames = props.getProperty(propName);
          StringTokenizer tokens = new StringTokenizer(mechNames, ",");

          if (!tokens.hasMoreTokens()) {
            System.out.println("No name defined for code " + propName);
          }

          long code;
          if (propName.startsWith("0x") || propName.startsWith("0X")) {
            code = Long.parseLong(propName.substring(2), 16);
          } else {
            code = Long.parseLong(propName);
          }

          String mainName = tokens.nextToken();
          codeNameMap.put(code, mainName);

          while (tokens.hasMoreTokens()) {
            nameCodeMap.put(tokens.nextToken(), code);
          }
        }

        Set<Long> codes = codeNameMap.keySet();
        for (Long code : codes) {
          nameCodeMap.put(codeNameMap.get(code), code);
        }
      } catch (Throwable t) {
        throw new IllegalStateException("error reading properties file " + resourcePath + ": " + t.getMessage());
      }

      if (codeNameMap.isEmpty()) {
        throw new IllegalStateException("no code to name map is defined properties file " + resourcePath);
      }
    }

    String codeToString(long code) {
      String name = codeNameMap.get(code);
      return name != null ? name : "Unknown " + type + " with code: 0x" + toFullHex(code);
    }

    long stringToCode(String name) {
      Long code = nameCodeMap.get(name);
      return (code != null) ? code : -1;
    }

  }

  private static class Hex {

    private static final char[] DIGITS = {'0', '1', '2', '3', '4',
        '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    private static final char[] UPPER_DIGITS = {'0', '1', '2', '3', '4',
        '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

    private static final int[] LINTS = new int['f' + 1];
    private static final int[] HINTS = new int[LINTS.length];

    static {
      for (int i = 0; i < DIGITS.length; i++) LINTS[DIGITS[i]] = i;

      for (int i = 10; i < UPPER_DIGITS.length; i++) LINTS[UPPER_DIGITS[i]] = i;

      for (int i = 0; i < LINTS.length; i++) HINTS[i] = LINTS[i] << 4;
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

  private static final CodeNameMap ckaCodeNameMap;
  private static final CodeNameMap ckcCodeNameMap;
  private static final CodeNameMap ckdCodeNameMap;
  private static final CodeNameMap ckgCodeNameMap;
  private static final CodeNameMap ckhCodeNameMap;
  private static final CodeNameMap ckkCodeNameMap;
  private static final CodeNameMap ckmCodeNameMap;
  private static final CodeNameMap ckoCodeNameMap;
  private static final CodeNameMap ckrCodeNameMap;
  private static final CodeNameMap ckuCodeNameMap;

  private static final Map<Long, String> hashMechCodeToHashNames;

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

    String prefix = "/iaik/pkcs/pkcs11/wrapper/";
    ckaCodeNameMap = new CodeNameMap("attribute", prefix + "cka.properties");
    ckcCodeNameMap = new CodeNameMap("certificate type", prefix + "ckc.properties");
    ckdCodeNameMap = new CodeNameMap("key derivation function", prefix + "ckd.properties");
    ckgCodeNameMap = new CodeNameMap("mask generation function", prefix + "ckg.properties");
    ckhCodeNameMap = new CodeNameMap("hardware feature", prefix + "ckh.properties");
    ckkCodeNameMap = new CodeNameMap("key type", prefix + "ckk.properties");
    ckmCodeNameMap = new CodeNameMap("mechanism type", prefix + "ckm.properties");
    ckoCodeNameMap = new CodeNameMap("object class", prefix + "cko.properties");
    ckrCodeNameMap = new CodeNameMap("return value", prefix + "ckr.properties");
    ckuCodeNameMap = new CodeNameMap("user", prefix + "cku.properties");
  }

  /**
   * Converts the long value code of an attribute (CKA) to a name.
   *
   * @param code
   *          The code of the attribute to be converted to a string.
   * @return The string representation of the attribute.
   */
  public static String ckaCodeToName(long code) {
    return ckaCodeNameMap.codeToString(code);
  }

  /**
   * Converts the attribute (CKA) name to code value.
   *
   * @param name
   *          The name of the attribute to be converted to a code.
   * @return The code representation of the attribute.
   */
  public static long ckaNameToCode(String name) {
    return ckaCodeNameMap.stringToCode(name);
  }

  /**
   * Converts the long value code of a certificate type (CKC) to a name.
   *
   * @param code
   *          The code of the certificate type to be converted to a string.
   * @return The string representation of the certificate type.
   */
  public static String ckcCodeToName(long code) {
    return ckcCodeNameMap.codeToString(code);
  }

  /**
   * Converts the certificate type (CKC) name to code value.
   *
   * @param name
   *          The name of the certificate type to be converted to a code.
   * @return The code representation of the certificate type.
   */
  public static long ckcNameToCode(String name) {
    return ckcCodeNameMap.stringToCode(name);
  }

  /**
   * Converts the long value code of a key derivation function (CKD) to a name.
   *
   * @param code
   *          The code of the key derivation function to be converted to a string.
   * @return The string representation of the key derivation function.
   */
  public static String ckdCodeToName(long code) {
    return ckdCodeNameMap.codeToString(code);
  }

  /**
   * Converts the key derivation function (CKD) name to code value.
   *
   * @param name
   *          The name of the key derivation function to be converted to a code.
   * @return The code representation of the key derivation function.
   */
  public static long ckdNameToCode(String name) {
    return ckdCodeNameMap.stringToCode(name);
  }

  /**
   * Converts the long value code of a mask generation function (CKO) to a name.
   *
   * @param code
   *          The code of the mask generation function to be converted to a string.
   * @return The string representation of the mask generation function.
   */
  public static String ckgCodeToName(long code) {
    return ckgCodeNameMap.codeToString(code);
  }

  /**
   * Converts the mask generation function (CKG) name to code value.
   *
   * @param name
   *          The name of the mask generation function to be converted to a code.
   * @return The code representation of the mask generation function.
   */
  public static long ckgNameToCode(String name) {
    return ckgCodeNameMap.stringToCode(name);
  }

  /**
   * Converts the long value code of a hardware feature (CKH) to a name.
   *
   * @param code
   *          The code of the hardware feature to be converted to a string.
   * @return The string representation of the hardware feature.
   */
  public static String ckhCodeToName(long code) {
    return ckhCodeNameMap.codeToString(code);
  }

  /**
   * Converts the hardware feature (CKH) name to code value.
   *
   * @param name
   *          The name of the hardware feature to be converted to a code.
   * @return The code representation of the hardware feature.
   */
  public static long ckhNameToCode(String name) {
    return ckhCodeNameMap.stringToCode(name);
  }

  /**
   * Converts the long value code of a key type (CKK) to a name.
   *
   * @param code
   *          The code of the key type to be converted to a string.
   * @return The string representation of the key type.
   */
  public static String ckkCodeToName(long code) {
    return ckkCodeNameMap.codeToString(code);
  }

  /**
   * Converts the key type (CKHK) name to code value.
   *
   * @param name
   *          The name of the key type to be converted to a code.
   * @return The code representation of the key type.
   */
  public static long ckkNameToCode(String name) {
    return ckkCodeNameMap.stringToCode(name);
  }

  /**
   * Converts the long value code of a mechanism (CKM) to a name.
   *
   * @param code
   *          The code of the mechanism to be converted to a string.
   * @return The string representation of the mechanism.
   */
  public static String ckmCodeToName(long code) {
    return ckmCodeNameMap.codeToString(code);
  }

  /**
   * Converts the mechanism (CKM) name to code value.
   *
   * @param name
   *          The name of the mechanism to be converted to a code.
   * @return The code representation of the mechanism.
   */
  public static long ckmNameToCode(String name) {
    return ckmCodeNameMap.stringToCode(name);
  }

  /**
   * Converts the long value code of an object class (CKO) to a name.
   *
   * @param code
   *          The code of the object class to be converted to a string.
   * @return The string representation of the object class.
   */
  public static String ckoCodeToName(long code) {
    return ckoCodeNameMap.codeToString(code);
  }

  /**
   * Converts the object class (CKO) name to code value.
   *
   * @param name
   *          The name of the object class to be converted to a code.
   * @return The code representation of the object class.
   */
  public static long ckoNameToCode(String name) {
    return ckoCodeNameMap.stringToCode(name);
  }

  /**
   * Converts the long value code of a return code (CKR) to a name.
   *
   * @param code
   *          The code of the return code to be converted to a string.
   * @return The string representation of the return code.
   */
  public static String ckrCodeToName(long code) {
    return ckrCodeNameMap.codeToString(code);
  }

  /**
   * Converts the return code (CKR) name to code value.
   *
   * @param name
   *          The name of the return code to be converted to a code.
   * @return The code representation of the return code.
   */
  public static long ckrNameToCode(String name) {
    return ckrCodeNameMap.stringToCode(name);
  }

  /**
   * Converts the long value code of a user (CKU) to a name.
   *
   * @param code
   *          The code of the user to be converted to a string.
   * @return The string representation of the user.
   */
  public static String ckuCodeToName(long code) {
    return ckuCodeNameMap.codeToString(code);
  }

  /**
   * Converts the user (CKU) name to code value.
   *
   * @param name
   *          The name of the user to be converted to a code.
   * @return The code representation of the user.
   */
  public static long ckuNameToCode(String name) {
    return ckuCodeNameMap.stringToCode(name);
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

}
