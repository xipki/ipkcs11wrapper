/*
 *
 * Copyright (c) 2022 - 2023 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.xipki.pkcs11;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import static org.xipki.pkcs11.PKCS11Constants.*;

/**
 * This class contains only static methods. It is the place for all functions
 * that are used by several classes in this package.
 *
 * @author Lijun Liao (xipki)
 */
public class Functions {

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

  private static final Map<Long, String> hashMechCodeToHashNames;

  static {
    hashMechCodeToHashNames = new HashMap<>();
    hashMechCodeToHashNames.put(CKM_SHA_1, "SHA1");
    hashMechCodeToHashNames.put(CKM_SHA224, "SHA224");
    hashMechCodeToHashNames.put(CKM_SHA256, "SHA256");
    hashMechCodeToHashNames.put(CKM_SHA384, "SHA384");
    hashMechCodeToHashNames.put(CKM_SHA512, "SHA512");
    hashMechCodeToHashNames.put(CKM_SHA512_224, "SHA512/224");
    hashMechCodeToHashNames.put(CKM_SHA512_256, "SHA512/256");
    hashMechCodeToHashNames.put(CKM_SHA3_224, "SHA3-224");
    hashMechCodeToHashNames.put(CKM_SHA3_256, "SHA3-256");
    hashMechCodeToHashNames.put(CKM_SHA3_384, "SHA3-384");
    hashMechCodeToHashNames.put(CKM_SHA3_512, "SHA3-512");
  }

  public static String getHashAlgName(long hashMechanism) {
    return hashMechCodeToHashNames.get(hashMechanism);
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

  public static String toStringFlags(Category category, String prefix, long flags, long... flagMasks) {
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
        sb.append(codeToName(category, flagMask));
      }
    }

    return sb.append(")").toString();
  }

  public static byte[] fixECDSASignature(byte[] sig) {
    if (sig[0] != 0x30) return sig;

    int b = sig[1];
    int ofs = 2;

    int len = ((b & 0x80) == 0) ? 0xFF & b
        : (b == (byte) 0x81) ? 0xFF & sig[ofs++] : 0;

    if (len == 0) return sig;

    if (ofs + len != sig.length) return sig;

    // first integer, r
    if (sig[ofs++] != 0x02) return sig;

    b = sig[ofs++];
    if ((b & 0x80) != 0) return sig;

    int rLen = 0xFF & b;
    byte[] r = Arrays.copyOfRange(sig, ofs, ofs + rLen);
    ofs += rLen;

    // second integer, s
    if (sig[ofs++] != 0x02) return sig;

    b = sig[ofs++];
    if ((b & 0x80) != 0) return sig;

    int sLen = 0xFF & b;
    if (ofs + sLen != sig.length) return sig;

    byte[] s = Arrays.copyOfRange(sig, ofs, sig.length);

    // remove leading zero
    if (r[0] == 0) r = Arrays.copyOfRange(r, 1, r.length);

    if (s[0] == 0) s = Arrays.copyOfRange(s, 1, s.length);

    // valid length is either multiple of 8, e.g. 32, 48, and 64, or 66 for the curve P-521.
    int maxFieldLen = Math.max(r.length, s.length);
    int fieldLen = (maxFieldLen > 64 && maxFieldLen <= 66) ? 66
        : (maxFieldLen % 8 == 0) ? maxFieldLen : (maxFieldLen + 7) / 8 * 8;

    byte[] rs = new byte[2 * fieldLen];
    System.arraycopy(r, 0, rs, fieldLen - r.length, r.length);
    System.arraycopy(s, 0, rs, rs.length - s.length, s.length);
    return rs;
  }

}
