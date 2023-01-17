// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.

package iaik.pkcs.pkcs11.wrapper;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;

/**
 * @author Stiftung SIC
 */
public class PKCS11UTIL {

  /**
   * encodes the given charArray as UTF8 encoded byte array.
   *
   * @param charArray
   *          char array to be encoded
   * @return UTF8 encoded byte array
   * @throws UnsupportedEncodingException
   *           if UTF8 encoding is not supported
   */
  public static byte[] utf8Encoder(char[] charArray) throws UnsupportedEncodingException {
    return new String(charArray).getBytes(StandardCharsets.UTF_8);
  }

  /**
   * decodes the given UTF8 Encoding to a char array.
   *
   * @param byteArray
   *          the UTF8 encoding
   * @return the char array
   * @throws UnsupportedEncodingException
   *           if UTF8 encoding is not supported
   */
  public static char[] utf8Decoder(byte[] byteArray) throws UnsupportedEncodingException {
    return new String(byteArray, StandardCharsets.UTF_8).toCharArray();
  }

}
