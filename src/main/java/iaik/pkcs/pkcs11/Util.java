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

package iaik.pkcs.pkcs11;

import iaik.pkcs.pkcs11.parameters.CCMParameters;
import iaik.pkcs.pkcs11.wrapper.Functions;
import sun.security.pkcs11.wrapper.CK_ATTRIBUTE;
import sun.security.pkcs11.wrapper.CK_DATE;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;

/**
 * A class consisting of static methods only which provide certain static
 * pieces of code that are used frequently in this project.
 *
 * @author Karl Scheibelhofer
 * @author Lijun Liao
 * @version 1.0
 */
public class Util {

  public static <T> T requireNonNull(String paramName, T param) {
    if (param == null) {
      throw new NullPointerException("Argument '" + paramName + "' must not be null.");
    }
    return param;
  }

  /**
   * Parse a time character array as defined in PKCS#11 and return is as a
   * Date object.
   *
   * @param timeChars
   *          A time encoded as character array as specified in PKCS#11.
   * @return A Date object set to the time indicated in the given char-array.
   *         null, if the given char array is null or the format is wrong.
   */
  public static Date parseTime(char[] timeChars) {
    Date time = null;

    if ((timeChars != null) && timeChars.length > 2) {
      String timeString = new String(timeChars, 0, timeChars.length - 2);
      try {
        SimpleDateFormat utc = new SimpleDateFormat("yyyyMMddhhmmss");
        utc.setTimeZone(TimeZone.getTimeZone("UTC"));
        time = utc.parse(timeString);
      } catch (ParseException ex) { /* nothing else to be done */
      }
    }

    return time;
  }

  /**
   * Convert the given CK_DATE object to a Date object.
   *
   * @param ckDate
   *          The object providing the date information.
   * @return The new Date object or null, if the given ckDate is null.
   */
  public static Date convertToDate(CK_DATE ckDate) {
    Date date = null;

    if (ckDate != null) {
      int year = Integer.parseInt(new String(ckDate.year));
      int month = Integer.parseInt(new String(ckDate.month));
      int day = Integer.parseInt(new String(ckDate.day));
      // poor performance, consider alternatives
      Calendar calendar = new GregorianCalendar();
      // calendar starts months with 0
      calendar.set(year, Calendar.JANUARY + (month - 1), day);
      date = calendar.getTime();
    }

    return date;
  }

  /**
   * Convert the given Date object to a CK_DATE object.
   *
   * @param date
   *          The object providing the date information.
   * @return The new CK_DATE object or null, if the given date is null.
   */
  public static CK_DATE convertToCkDate(Date date) {
    CK_DATE ckDate = null;

    if (date != null) {
      //poor memory/performance behavior, consider alternatives
      Calendar calendar = new GregorianCalendar();
      calendar.setTime(date);
      int year = calendar.get(Calendar.YEAR);
      // month counting starts with zero
      int month = calendar.get(Calendar.MONTH) + 1;
      int day = calendar.get(Calendar.DAY_OF_MONTH);
      ckDate = new CK_DATE(toCharArray(year, 4),
                toCharArray(month, 2), toCharArray(day, 2));
    }

    return ckDate;
  }

  /**
   * Converts the given number into a char-array. If the length of the array
   * is shorter than the required exact length, the array is padded with
   * leading '0' chars. If the array is longer than the wanted length the most
   * significant digits are cut off until the array has the exact length.
   *
   * @param number
   *          The number to convert to a char array.
   * @param exactArrayLength
   *          The exact length of the returned array.
   * @return The number as char array, one char for each decimal digit.
   */
  public static char[] toCharArray(int number, int exactArrayLength) {
    char[] charArray;

    String numberString = Integer.toString(number);
    char[] numberChars = numberString.toCharArray();

    if (numberChars.length > exactArrayLength) {
      // cut off digits beginning at most significant digit
      charArray = new char[exactArrayLength];
      System.arraycopy(numberChars, 0, charArray, 0, charArray.length);
    } else if (numberChars.length < exactArrayLength) {
      // pad with '0' leading chars
      charArray = new char[exactArrayLength];
      int offset = exactArrayLength - numberChars.length;
      for (int i = 0; i < charArray.length; i++) {
        charArray[i] = (i < offset) ? '0' : numberChars[i - offset];
      }
    } else {
      charArray = numberChars;
    }

    return charArray;
  }

  /**
   * Converts the given string to a char-array of exactly the given length.
   * If the given string is short than the wanted length, then the array is
   * padded with trailing padding chars. If the string is longer, the last
   * character are cut off that the string has the wanted size.
   *
   * @param string
   *          The string to convert.
   * @param exactArrayLength
   *          The length of the returned char-array.
   * @param paddingChar
   *          The character to use for padding, if necessary.
   * @return The string as char array, padded or cut off, if necessary.
   *         The array will have length exactArrayLength. null, if the
   *         given string is null.
   */
  public static char[] toPaddedCharArray(String string, int exactArrayLength, char paddingChar) {
    char[] charArray = null;

    if (string != null) {
      int stringLength = string.length();
      charArray = new char[exactArrayLength];
      string.getChars(0, Math.min(stringLength, exactArrayLength), charArray, 0);
      // fill the rest of the array with padding char
      for (int i = stringLength; i < charArray.length; i++) {
        charArray[i] = paddingChar;
      }
    }

    return charArray;
  }

  /**
   * Convert a BigInteger to a byte-array, but treat the byte-array given from
   * the BigInteger as unsigned and removing any leading zero bytes; e.g. a
   * 1024 bit integer with its highest bit set will result in an 128 byte
   * array.
   *
   * @param bigInteger
   *          The BigInteger to convert.
   * @return The byte-array representation of the BigInterger without
   *         signum-bit. null, if the BigInteger is null.
   */
  public static byte[] unsignedBigIntergerToByteArray(BigInteger bigInteger) {
    if (bigInteger == null) {
      return null;
    }

    byte[] integerBytes = bigInteger.toByteArray();
    return ((integerBytes.length > 0) && (integerBytes[0] == 0x00))
        ? Arrays.copyOfRange(integerBytes, 1, integerBytes.length) : integerBytes;
  }

  /**
   * Converts the given vector into an array of CK_ATTRIBUTE elements.
   * Elements not of type CK_ATTRIBUTE will not be present in the resulting
   * array and be set to null.
   *
   * @param attributes
   *          The vector which contains the attributes.
   * @return The array of the attributes.
   */
  public static CK_ATTRIBUTE[] convertAttributesVectorToArray(Vector<CK_ATTRIBUTE> attributes) {
    if (attributes == null) {
      return null;
    }
    int numberOfAttributes = attributes.size();
    CK_ATTRIBUTE[] attributeArray = new CK_ATTRIBUTE[numberOfAttributes];

    for (int i = 0; i < numberOfAttributes; i++) {
      attributeArray[i] = attributes.elementAt(i);
    }

    return attributeArray;
  }

  /**
   * Converts a byte array to a hexadecimal String. Each byte is presented by
   * its two digit hex-code; 0x0A to "0a", 0x00 to "00". No leading "0x" is
   * included in the result.
   *
   * @param value
   *          The byte array to be converted
   * @return the hexadecimal string representation of the byte array
   */
  public static String toHex(byte[] value) {
    return value == null ? null : Functions.toHexString(value);
  }

  public static String concat(String s1, String... strs) {
    int len = (s1 == null) ? 0 : s1.length();
    for (String str : strs) {
      len += (str == null) ? 0 : str.length();
    }
    StringBuilder sb = new StringBuilder(len);
    sb.append(s1);
    for (String str : strs) {
      sb.append(str);
    }
    return sb.toString();
  }

  public static String concatObjects(Object o1, Object... objs) {
    StringBuilder sb = new StringBuilder();
    sb.append(o1);
    for (Object obj : objs) {
      sb.append(obj);
    }
    return sb.toString();
  }

  public static String concatObjectsCap(int cap, Object o1, Object... objs) {
    StringBuilder sb = new StringBuilder(cap);
    sb.append(o1);
    for (Object obj : objs) {
      sb.append(obj);
    }
    return sb.toString();
  }

  public static Field getField(Class<?> clazz, String fieldName) {
    try {
      return clazz.getField(fieldName);
    } catch (Throwable th) {
      return null;
    }
  }

  public static Method getMethod(Class<?> clazz, String name, Class<?>... parameterTypes) {
    try {
      return clazz.getMethod(name, parameterTypes);
    } catch (Throwable th) {
      return null;
    }
  }

  public static Constructor<?> getConstructor(String className, Class<?>... parameterTypes) {
    try {
      Class<?> clazz = Class.forName(className, false, CCMParameters.class.getClassLoader());
      return getConstructor(clazz, parameterTypes);
    } catch (Throwable th) {
      return null;
    }
  }

  public static Constructor<?> getConstructor(Class<?> clazz, Class<?>... parameterTypes) {
    try {
      return clazz.getConstructor(parameterTypes);
    } catch (Throwable th) {
      return null;
    }
  }

}
