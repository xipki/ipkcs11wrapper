// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11;

import java.util.*;

import static org.xipki.pkcs11.PKCS11Constants.Category;
import static org.xipki.pkcs11.PKCS11Constants.codeToName;

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

    public static String encode(byte[] data, int ofs, int len) {
      char[] out = new char[len << 1];

      // two characters from the hex value.
      int endOfs = ofs + len;
      for (int i = ofs, j = 0; i < endOfs; i++) {
        out[j++] = DIGITS[(0xF0 & data[i]) >>> 4];
        out[j++] = DIGITS[0x0F & data[i]];
      }

      return new String(out);
    }

    public static byte[] decode(String hex) {
      char[] data = hex.toCharArray();
      int len = data.length;

      if ((len & 0x01) != 0) {
        throw new IllegalArgumentException("Odd number of characters.");
      }

      byte[] out = new byte[len >> 1];

      // two characters from the hex value.
      for (int i = 0, j = 0; j < len; i++) {
        out[i] = (byte) (HINTS[data[j++]] | LINTS[data[j++]]);
      }

      return out;
    }

  }

  private static final Map<String, Integer> ecParamsToFieldSize;
  private static final Map<String, Integer> ecParamsToOrderSize;

  private static final Map<String, Integer> edwardsMontegomeryEcParamsToFieldSize;

  static {
    edwardsMontegomeryEcParamsToFieldSize = new HashMap<>(6);
    // X25519 (1.3.101.110)
    edwardsMontegomeryEcParamsToFieldSize.put("06032b656e", 32);
    // X448 (1.3.101.111)
    edwardsMontegomeryEcParamsToFieldSize.put("06032b656f", 56);
    // ED25519 (1.3.101.112)
    edwardsMontegomeryEcParamsToFieldSize.put("06032b6570", 32);
    // ED448 (1.3.101.113)
    edwardsMontegomeryEcParamsToFieldSize.put("06032b6571", 57);

    ecParamsToFieldSize = new HashMap<>(130);
    ecParamsToOrderSize = new HashMap<>(130);

    String propFile = "org/xipki/pkcs11/size-EC.properties";
    Properties props = new Properties();
    try {
      props.load(Functions.class.getClassLoader().getResourceAsStream(propFile));
      for (String name : props.stringPropertyNames()) {
        name = name.trim();

        if (ecParamsToFieldSize.containsKey(name)) {
          throw new IllegalStateException("duplicated definition of " + name);
        }

        byte[] ecParams = Hex.decode(name);

        String value = props.getProperty(name);

        int fieldBitSize;
        int orderBitSize;
        if (value.contains(",")) {
          String[] tokens = value.split(",");
          fieldBitSize = Integer.parseInt(tokens[0].trim());
          orderBitSize = Integer.parseInt(tokens[1].trim());
        } else {
          fieldBitSize = Integer.parseInt(value);
          orderBitSize = fieldBitSize;
        }

        String hexEcParams = Hex.encode(ecParams, 0, ecParams.length);

        ecParamsToFieldSize.put(hexEcParams, (fieldBitSize + 7) / 8);
        ecParamsToOrderSize.put(hexEcParams, (orderBitSize + 7) / 8);
      }
    } catch (Throwable t) {
      throw new IllegalStateException("error reading properties file " + propFile + ": " + t.getMessage());
    }
  }

  public static byte[] asUnsignedByteArray(java.math.BigInteger bn) {
    byte[] bytes = bn.toByteArray();
    return bytes[0] != 0 ? bytes : Arrays.copyOfRange(bytes, 1, bytes.length);
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
    return Hex.encode(value, 0, value.length);
  }

  public static String toHex(byte[] value, int ofs, int len) {
    return Hex.encode(value, ofs, len);
  }

  public static byte[] decodeHex(String encoded) {
    return Hex.decode(encoded);
  }

  public static <T> T requireNonNull(String paramName, T param) {
    if (param == null) {
      throw new NullPointerException("Argument '" + paramName + "' must not be null.");
    }

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
      if (argument == candidate) {
        return argument;
      }
    }

    throw new IllegalArgumentException(name + " is not among " + Arrays.toString(candidates) + ": " + argument);
  }

  public static long requireAmong(String name, long argument, long... candidates) {
    for (long candidate : candidates) {
      if (argument == candidate) {
        return argument;
      }
    }

    throw new IllegalArgumentException(name + " is not among " + Arrays.toString(candidates) + ": " + argument);
  }

  public static String toStringFlags(Category category, String prefix, long flags, long... flagMasks) {
    // initialize the indent for non-first lines.
    char[] indentChars = new char[prefix.length() + 1];
    Arrays.fill(indentChars, ' ');
    String indent = new String(indentChars);

    ArrayList<Long> sortedMasks = new ArrayList<>(flagMasks.length);
    for (long flagMask : flagMasks) {
      sortedMasks.add(flagMask);
    }
    java.util.Collections.sort(sortedMasks);

    boolean first = true;
    List<String> lines = new LinkedList<>();

    String line = prefix + "0x" + toFullHex(flags) + " (";
    for (long flagMask : sortedMasks) {
      if ((flags & flagMask) == 0L) {
        continue;
      }

      String thisEntry = first ? "" : " | ";

      if (first) {
        first = false;
      }

      thisEntry += codeToName(category, flagMask).substring(4); // 4 = "CKF_".length
      if (line.length() + thisEntry.length() > 100) {
        lines.add(line);
        line = indent;
      }
      line += thisEntry;
    }

    if (line.length() > indentChars.length) {
      lines.add(line);
    }

    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < lines.size(); i++) {
      if (i != 0) {
        sb.append("\n");
      }

      sb.append(lines.get(i));
    }
    return sb.append(")").toString();
  }

  static byte[] fixECDSASignature(byte[] sig, byte[] ecParams) {
    Integer rOrSLen = ecParamsToOrderSize.get(Hex.encode(ecParams, 0, ecParams.length));
    return (rOrSLen == null) ? sig : fixECDSASignature(sig, rOrSLen);
  }

  static byte[] fixECDSASignature(byte[] sig, int rOrSLen) {
    if (sig.length == 2 * rOrSLen || sig[0] != 0x30) {
      return sig;
    }

    int b = sig[1];
    int ofs = 2;

    int len = ((b & 0x80) == 0) ? 0xFF & b
        : (b == (byte) 0x81) ? 0xFF & sig[ofs++] : 0;

    if (len == 0 || ofs + len != sig.length) {
      return sig;
    }

    // first integer, r
    if (sig[ofs++] != 0x02) {
      return sig;
    }

    b = sig[ofs++];
    if ((b & 0x80) != 0) {
      return sig;
    }

    int rLen = 0xFF & b;
    byte[] r = Arrays.copyOfRange(sig, ofs, ofs + rLen);
    ofs += rLen;

    // second integer, s
    if (sig[ofs++] != 0x02) {
      return sig;
    }

    b = sig[ofs++];
    if ((b & 0x80) != 0) {
      return sig;
    }

    int sLen = 0xFF & b;
    if (ofs + sLen != sig.length) {
      return sig;
    }

    byte[] s = Arrays.copyOfRange(sig, ofs, sig.length);

    // remove leading zero
    if (r[0] == 0) {
      r = Arrays.copyOfRange(r, 1, r.length);
    }

    if (s[0] == 0) {
      s = Arrays.copyOfRange(s, 1, s.length);
    }

    if (r.length > rOrSLen || s.length > rOrSLen) {
      // we can not fix it.
      return sig;
    }

    byte[] rs = new byte[2 * rOrSLen];
    System.arraycopy(r, 0, rs, rOrSLen - r.length, r.length);
    System.arraycopy(s, 0, rs, rs.length - s.length, s.length);
    return rs;
  }

  public static String toString(byte[] bytes) {
    final int numPerLine = 40;
    final int len = bytes.length;
    StringBuilder sb = new StringBuilder(5 * (len + numPerLine - 1) / numPerLine + 4 * bytes.length);
    for (int ofs = 0; ofs < len; ofs += numPerLine) {
      int num = Math.min(numPerLine, len - ofs);
      sb.append(ofs == 0 ? "    " : "\n    ").append(toHex(bytes, ofs, num));
    }
    return sb.toString();
  }

  // some HSM does not return the standard conform ECPoint
  static byte[] fixECPoint(byte[] ecPoint, byte[] ecParams) {
    if (ecParams == null) {
      return ecPoint;
    }

    int len = ecPoint.length;

    if (len > 0xFFF0) {
      return ecPoint; // too long, should not happen.
    }

    String hexEcParams = Hex.encode(ecParams, 0, ecParams.length);
    Integer fieldSize = ecParamsToFieldSize.get(hexEcParams);
    if (fieldSize != null) {
      // weierstrauss curve.
      if (ecPoint.length == 2 * fieldSize) {
        // HSM returns x_coord. || y_coord.
        return toOctetString((byte) 0x04, ecPoint);
      } else {
        byte encodingByte = ecPoint[0];
        if (encodingByte == 0x04) {
          if (len == 1 + 2 * fieldSize) {
            // HSM returns 04 || x_coord. || y_coord.
            return toOctetString(null, ecPoint);
          }
        } else if (encodingByte == 0x02 || encodingByte == 0x03) {
          if (len == 1 + fieldSize) {
            // HSM returns <02 or 03> || x_coord.
            return toOctetString(null, ecPoint);
          }
        }
      }

      return ecPoint;
    }

    fieldSize = edwardsMontegomeryEcParamsToFieldSize.get(hexEcParams);
    if (fieldSize != null) {
      return (len == fieldSize) ? toOctetString(null, ecPoint) : ecPoint;
    }

    return ecPoint;
  }

  private static byte[] toOctetString(Byte byte1, byte[] bytes) {
    int len = bytes.length;
    if (byte1 != null) {
      len++;
    }

    int numLenBytes = (len <= 0x7F) ? 1 : (len < 0xFF) ? 2 : 3;

    byte[] ret = new byte[1 + numLenBytes + len];
    ret[0] = 0x04;
    if (numLenBytes == 2) {
      ret[1] = (byte) 0x81;
    } else if (numLenBytes == 3) {
      ret[1] = (byte) 0x82;
      ret[2] = (byte) (len >> 8);
    }
    ret[numLenBytes] = (byte) len;

    if (byte1 == null) {
      System.arraycopy(bytes, 0, ret, 1 + numLenBytes, bytes.length);
    } else {
      ret[1 + numLenBytes] = byte1;
      System.arraycopy(bytes, 0, ret, 2 + numLenBytes, bytes.length);
    }
    return ret;
  }

}
