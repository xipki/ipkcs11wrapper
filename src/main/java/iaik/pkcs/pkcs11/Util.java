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

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;

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
   * Converts a byte array to a hexadecimal String. Each byte is presented by
   * its two digit hex-code; 0x0A to "0a", 0x00 to "00". No leading "0x" is
   * included in the result.
   *
   * @param value
   *          The byte array to be converted. May be null.
   * @return the hexadecimal string representation of the byte array
   */
  public static String toHex(byte[] value) {
    return value == null ? null : Functions.toHexString(value);
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
