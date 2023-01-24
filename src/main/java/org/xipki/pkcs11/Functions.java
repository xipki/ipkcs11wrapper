// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11;

import java.nio.charset.StandardCharsets;
import java.util.*;

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

  private static class ECInfo {
    int fieldSize;
    int orderSize;
    long ecParamsHash;
    String[] names;
  }

  /**
   * Implementation of SipHash as specified in "SipHash: a fast short-input PRF", by Jean-Philippe
   * Aumasson and Daniel J. Bernstein (https://131002.net/siphash/siphash.pdf).
   * <p>
   * "SipHash is a family of PRFs SipHash-c-d where the integer parameters c and d are the number of
   * compression rounds and the number of finalization rounds. A compression round is identical to a
   * finalization round and this round function is called SipRound. Given a 128-bit key k and a
   * (possibly empty) byte string m, SipHash-c-d returns a 64-bit value..."
   */
  private static class SipHash24 {
    private final int c = 2, d = 4;

    private final long k0 = 0x0706050403020100L, k1 = 0x0f0e0d0c0b0a0908L;
    private long v0, v1, v2, v3;

    private long m = 0;
    private int wordPos = 0;
    private int wordCount = 0;

    public SipHash24() {
      reset();
    }

    public void update(byte[] input, int offset, int length) {
      int i = 0, fullWords = length & ~7;
      if (wordPos == 0) {
        for (; i < fullWords; i += 8) {
          m = littleEndianToLong(input, offset + i);
          processMessageWord();
        }
        for (; i < length; ++i) {
          m >>>= 8;
          m |= (input[offset + i] & 0xffL) << 56;
        }
        wordPos = length - fullWords;
      } else {
        int bits = wordPos << 3;
        for (; i < fullWords; i += 8) {
          long n = littleEndianToLong(input, offset + i);
          m = (n << bits) | (m >>> -bits);
          processMessageWord();
          m = n;
        }

        for (; i < length; ++i) {
          m >>>= 8;
          m |= (input[offset + i] & 0xffL) << 56;

          if (++wordPos == 8) {
            processMessageWord();
            wordPos = 0;
          }
        }
      }
    }

    public long doFinal() {
      // NOTE: 2 distinct shifts to avoid "64-bit shift" when wordPos == 0
      m >>>= ((7 - wordPos) << 3);
      m >>>= 8;
      m |= (((wordCount << 3) + wordPos) & 0xffL) << 56;

      processMessageWord();

      v2 ^= 0xffL;

      applySipRounds(d);

      long result = v0 ^ v1 ^ v2 ^ v3;

      reset();

      return result;
    }

    public void reset() {
      v0 = k0 ^ 0x736f6d6570736575L;
      v1 = k1 ^ 0x646f72616e646f6dL;
      v2 = k0 ^ 0x6c7967656e657261L;
      v3 = k1 ^ 0x7465646279746573L;

      m = 0;
      wordPos = 0;
      wordCount = 0;
    }

    private void processMessageWord() {
      ++wordCount;
      v3 ^= m;
      applySipRounds(c);
      v0 ^= m;
    }

    private void applySipRounds(int n) {
      long r0 = v0, r1 = v1, r2 = v2, r3 = v3;

      for (int r = 0; r < n; ++r) {
        r0 += r1; r2 += r3;
        r1 = (r1 << 13) | (r1 >>> 51); // rotateLeft(r1, 13);
        r3 = (r3 << 16) | (r3 >>> 48); // rotateLeft(r3, 16);
        r1 ^= r0; r3 ^= r2;
        r0 = (r0 << 32) | (r0 >>> 32); // rotateLeft(r0, 32);
        r2 += r1; r0 += r3;
        r1 = (r1 << 17) | (r1 >>> 47); // rotateLeft(r1, 17);
        r3 = (r3 << 21) | (r3 >>> 43); // rotateLeft(r3, 21);
        r1 ^= r2; r3 ^= r0;
        r2 = (r2 << 32) | (r2 >>> 32); // rotateLeft(r2, 32);
      }

      v0 = r0; v1 = r1; v2 = r2; v3 = r3;
    }

    private static long littleEndianToLong(byte[] bs, int off) {
      return      (bs[off++] & 0xFFL) | (bs[off++] & 0xFFL) << 8
          | (bs[off++] & 0xFFL) << 16 | (bs[off++] & 0xFFL) << 24
          | (bs[off++] & 0xFFL) << 32 | (bs[off++] & 0xFFL) << 40
          | (bs[off++] & 0xFFL) << 48 | (bs[off]   & 0xFFL) << 56;
    }

  }

  private static final Map<String, ECInfo> ecParamsInfoMap;

  private static final Set<String> edwardsMontgomeryEcParams;

  static {
    edwardsMontgomeryEcParams = new HashSet<>(6);
    // X25519 (1.3.101.110)
    edwardsMontgomeryEcParams.add("06032b656e");
    // X448 (1.3.101.111)
    edwardsMontgomeryEcParams.add("06032b656f");
    // ED25519 (1.3.101.112)
    edwardsMontgomeryEcParams.add("06032b6570");
    // ED448 (1.3.101.113)
    edwardsMontgomeryEcParams.add("06032b6571");

    ecParamsInfoMap = new HashMap<>(120);

    String propFile = "org/xipki/pkcs11/EC.properties";
    Properties props = new Properties();
    try {
      props.load(Functions.class.getClassLoader().getResourceAsStream(propFile));
      for (String name : props.stringPropertyNames()) {
        name = name.trim();

        if (ecParamsInfoMap.containsKey(name)) {
          throw new IllegalStateException("duplicated definition of " + name);
        }

        byte[] ecParams = Hex.decode(name);

        ECInfo ecInfo = new ECInfo();

        String[] values = props.getProperty(name).split(",");
        ecInfo.names = values[0].toUpperCase(Locale.ROOT).split(":");
        ecInfo.ecParamsHash = "-".equals(values[1]) ? 0 : SipHash24.littleEndianToLong(Hex.decode(values[1]), 0);
        ecInfo.fieldSize = (Integer.parseInt(values[2]) + 7) / 8;
        ecInfo.orderSize = (values.length > 3) ? (Integer.parseInt(values[3]) + 7) / 8 : ecInfo.fieldSize;
        String hexEcParams = Hex.encode(ecParams, 0, ecParams.length);

        ecParamsInfoMap.put(hexEcParams, ecInfo);
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
    ECInfo ecInfo = ecParamsInfoMap.get(Hex.encode(ecParams, 0, ecParams.length));
    return (ecInfo == null) ? sig : fixECDSASignature(sig, ecInfo.orderSize);
  }

  static byte[] fixECParams(byte[] ecParams) {
    // some HSMs, e.g. SoftHSM may return the ASN.1 string, e.g. edwards25519 for ED25519.
    int tag = 0xFF & ecParams[0];
    if (tag == 12 || tag == 19) { // 12: UTF8 String, 19: Printable String
      int len = 0xFF & ecParams[1];
      if (len < 128 && 2 + len == ecParams.length) {
        String curveName = new String(ecParams, 2, len, StandardCharsets.UTF_8).trim().toUpperCase(Locale.ROOT);
        for (Map.Entry<String, ECInfo> m : ecParamsInfoMap.entrySet()) {
          for (String name : m.getValue().names) {
            if (name.equals(curveName)) {
              return decodeHex(m.getKey());
            }
          }
        }
      }

      return ecParams;
    }

    if (tag == 0x30) { // ECParameters
      int offset = 1;
      int lenb = 0xFF & ecParams[offset++];

      int len = (lenb <= 127) ? lenb
          : (lenb == 0x81) ? 0xFF & ecParams[offset++]
          : (lenb == 0x82) ? ((0xFF & ecParams[offset++]) << 8) | (0xFF & ecParams[offset++])
          : -1;

      if (len == -1 || offset + len != ecParams.length) {
        return ecParams;
      }

      SipHash24 hash = new SipHash24();
      hash.update(ecParams, 0, ecParams.length);
      long hashValue = hash.doFinal();
      for (Map.Entry<String, ECInfo> m : ecParamsInfoMap.entrySet()) {
        if (hashValue == m.getValue().ecParamsHash) {
          return decodeHex(m.getKey());
        }
      }
    }

    return ecParams;
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
    ECInfo ecInfo = ecParamsInfoMap.get(hexEcParams);

    if (ecInfo == null) {
      return ecPoint;
    }

    int fieldSize = ecInfo.fieldSize;
    if (edwardsMontgomeryEcParams.contains(hexEcParams)) {
      // edwards or montgomery curve
      return (len == fieldSize) ? toOctetString(null, ecPoint) : ecPoint;
    }

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
