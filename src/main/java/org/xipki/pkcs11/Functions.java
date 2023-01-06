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

package org.xipki.pkcs11;

import java.util.*;

import static org.xipki.pkcs11.PKCS11Constants.*;

/**
 * This class contains only static methods. It is the place for all functions
 * that are used by several classes in this package.
 *
 * @author Karl Scheibelhofer
 * @author Martin Schlaeffer
 * @author Lijun Liao
 */
public class Functions {

  private static class CodeNameMap {

    private final String type;

    private final Map<Long, String> codeNameMap;
    private final Map<String, Long> nameCodeMap;

    CodeNameMap(String prefix, String resourcePath, String type) {
      this.type = type;
      codeNameMap = new HashMap<>();
      nameCodeMap = new HashMap<>();
      Properties props = new Properties();
      try {
        props.load(Functions.class.getClassLoader().getResourceAsStream(resourcePath));
        for (String propName : props.stringPropertyNames()) {
          String names = props.getProperty(propName);
          StringTokenizer tokens = new StringTokenizer(names, ",");

          if (!tokens.hasMoreTokens()) {
            System.out.println("No name defined for code " + propName);
            continue;
          }

          long code = (propName.startsWith("0x") || propName.startsWith("0X"))
              ? Long.parseLong(propName.substring(2), 16) : Long.parseLong(propName);

          if (codeNameMap.containsKey(code)) {
            throw new IllegalStateException("duplicated definition of " + prefix + ": " + toFullHex(code));
          }

          boolean first = true;
          while (tokens.hasMoreTokens()) {
            String name = tokens.nextToken();
            if (!name.startsWith(prefix)) throw new IllegalStateException(name + " does not start with " + prefix);

            if (first) {
              codeNameMap.put(code, name);
              first = false;
            } else {
              nameCodeMap.put(name, code);
            }
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
        throw new IllegalStateException("no code to name map is defined in the properties file " + resourcePath);
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

    Set<Long> codes() {
      return codeNameMap.keySet();
    }

  }

  private static class Hex {

    private static final char[] DIGITS = "0123456789abcdef".toCharArray();
    private static final char[] UPPER_DIGITS = "0123456789ABCDEF".toCharArray();

    private static final int[] LINTS = new int['f' + 1];
    private static final int[] HINTS = new int[LINTS.length];

    static {
      for (int i = 0; i < DIGITS.length; i++) LINTS[DIGITS[i]] = i;

      for (int i = 10; i < UPPER_DIGITS.length; i++) LINTS[UPPER_DIGITS[i]] = i;

      for (int i = 0; i < LINTS.length; i++) HINTS[i] = LINTS[i] << 4;
    }

    public static String encode(byte[] data) {
      int len = data.length;

      char[] out = new char[len << 1];

      // two characters from the hex value.
      for (int i = 0, j = 0; i < len; i++) {
        out[j++] = DIGITS[(0xF0 & data[i]) >>> 4];
        out[j++] = DIGITS[0x0F & data[i]];
      }

      return new String(out);
    }

    public static byte[] decode(String hex) {
      char[] data = hex.toCharArray();
      int len = data.length;

      if ((len & 0x01) != 0) throw new IllegalArgumentException("Odd number of characters.");

      byte[] out = new byte[len >> 1];

      // two characters from the hex value.
      for (int i = 0, j = 0; j < len; i++) out[i] = (byte) (HINTS[data[j++]] | LINTS[data[j++]]);

      return out;
    }

  }

  private static final CodeNameMap ckaCodeNameMap;
  private static final CodeNameMap ckcCodeNameMap;
  private static final CodeNameMap ckdCodeNameMap;
  private static final CodeNameMap ckfCodeNameMap;
  private static final CodeNameMap ckgCodeNameMap;
  private static final CodeNameMap ckhCodeNameMap;
  private static final CodeNameMap ckkCodeNameMap;
  private static final CodeNameMap ckmCodeNameMap;
  private static final CodeNameMap ckoCodeNameMap;
  private static final CodeNameMap ckpCodeNameMap;
  private static final CodeNameMap ckrCodeNameMap;
  private static final CodeNameMap cksCodeNameMap;
  private static final CodeNameMap ckuCodeNameMap;
  private static final CodeNameMap ckzCodeNameMap;

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

    String prefix = "org/xipki/pkcs11/";
    ckaCodeNameMap = new CodeNameMap("CKA", prefix + "cka.properties", "attribute");
    ckcCodeNameMap = new CodeNameMap("CKC", prefix + "ckc.properties", "certificate type");
    ckdCodeNameMap = new CodeNameMap("CKD", prefix + "ckd.properties", "key derivation function");
    ckfCodeNameMap = new CodeNameMap("CKF", prefix + "ckf.properties", "bit flag");
    ckgCodeNameMap = new CodeNameMap("CKG", prefix + "ckg.properties", "mask generation function");
    ckhCodeNameMap = new CodeNameMap("CKH", prefix + "ckh.properties", "hardware feature");
    ckkCodeNameMap = new CodeNameMap("CKK", prefix + "ckk.properties", "key type");
    ckmCodeNameMap = new CodeNameMap("CKM", prefix + "ckm.properties", "mechanism type");
    ckoCodeNameMap = new CodeNameMap("CKO", prefix + "cko.properties", "object class");
    ckpCodeNameMap = new CodeNameMap("CKP", prefix + "ckp.properties", "pseudo-random function");
    ckrCodeNameMap = new CodeNameMap("CKR", prefix + "ckr.properties", "return value");
    cksCodeNameMap = new CodeNameMap("CKS", prefix + "cks.properties", "session state");
    ckuCodeNameMap = new CodeNameMap("CKU", prefix + "cku.properties", "user");
    ckzCodeNameMap = new CodeNameMap("CKZ", prefix + "ckz.properties", "salt/encoding parameter source");
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
   * Converts the long value code of a bit flag (CKF) to a name.
   *
   * @param code
   *          The code of the bit flag to be converted to a string.
   * @return The string representation of the bit flag.
   */
  public static String ckfCodeToName(long code) {
    return ckfCodeNameMap.codeToString(code);
  }

  /**
   * Converts the bit flag (CKF) name to code value.
   *
   * @param name
   *          The name of the bit flag to be converted to a code.
   * @return The code representation of the bit flag.
   */
  public static long ckfNameToCode(String name) {
    return ckfCodeNameMap.stringToCode(name);
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
   * Converts the long value code of a pseudo-random function (CKP) to a name.
   *
   * @param code
   *          The code of the pseudo-random function to be converted to a string.
   * @return The string representation of the pseudo-random function.
   */
  public static String ckpCodeToName(long code) {
    return ckpCodeNameMap.codeToString(code);
  }

  /**
   * Converts the pseudo-random function (CKP) name to code value.
   *
   * @param name
   *          The name of the pseudo-random function to be converted to a code.
   * @return The code representation of the pseudo-random function.
   */
  public static long ckpNameToCode(String name) {
    return ckpCodeNameMap.stringToCode(name);
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
   * Converts the long value code of a session state (CKS) to a name.
   *
   * @param code
   *          The code of the session state to be converted to a string.
   * @return The string representation of the session state.
   */
  public static String cksCodeToName(long code) {
    return cksCodeNameMap.codeToString(code);
  }

  /**
   * Converts the session state (CKS) name to code value.
   *
   * @param name
   *          The name of the session state to be converted to a code.
   * @return The code representation of the session state.
   */
  public static long cksNameToCode(String name) {
    return cksCodeNameMap.stringToCode(name);
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
   * Converts the long value code of a salt/encoding parameter source (CKZ) to a name.
   *
   * @param code
   *          The code of the salt/encoding parameter source to be converted to a string.
   * @return The string representation of the salt/encoding parameter source.
   */
  public static String ckzCodeToName(long code) {
    return ckzCodeNameMap.codeToString(code);
  }

  /**
   * Converts the salt/encoding parameter source (CKZ) name to code value.
   *
   * @param name
   *          The name of the salt/encoding parameter source to be converted to a code.
   * @return The code representation of the salt/encoding parameter source.
   */
  public static long ckzNameToCode(String name) {
    return ckzCodeNameMap.stringToCode(name);
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
  public static String toHex(byte[] value) {
    return Hex.encode(value);
  }

  public static byte[] decodeHex(String encoded) {
    return Hex.decode(encoded);
  }

  public static String getHashAlgName(long hashMechanism) {
    return hashMechCodeToHashNames.get(hashMechanism);
  }

  public static <T> T requireNonNull(String paramName, T param) {
    if (param == null) throw new NullPointerException("Argument '" + paramName + "' must not be null.");

    return param;
  }

  public static int requireRange(String name, int argument, int min, int max) {
    if (argument < min || argument > max) {
      throw new IllegalArgumentException(String.format(
          "%s may not be out of the range [%d, %d]: %d", name, min, max, argument));
    }
    return argument;
  }

  public static int requireAmong(String name, int argument, int... candidates) {
    for (int candidate : candidates) {
      if (argument == candidate) return argument;
    }

    throw new IllegalArgumentException(name + " is not among " + Arrays.toString(candidates) + ": " + argument);
  }

  public static long requireAmong(String name, long argument, long... candidates) {
    for (long candidate : candidates) {
      if (argument == candidate) return argument;
    }

    throw new IllegalArgumentException(name + " is not among " + Arrays.toString(candidates) + ": " + argument);
  }

  public static String toStringFlags(String prefix, long flags, long... flagMasks) {
    StringBuilder sb = new StringBuilder(prefix.length() + 100);
    sb.append(prefix).append("0x").append(toFullHex(flags)).append(" (");
    boolean first = true;
    for (long flagMask : flagMasks) {
      if ((flags & flagMask) != 0L) {
        if (first) {
          first = false;
        } else {
          sb.append(" | ");
        }
        sb.append(Functions.ckfCodeToName(flagMask));
      }
    }

    return sb.append(")").toString();
  }

}
