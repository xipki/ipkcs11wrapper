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

package iaik.pkcs.pkcs11.parameters;

import iaik.pkcs.pkcs11.Util;
import iaik.pkcs.pkcs11.wrapper.Functions;
import sun.security.pkcs11.wrapper.CK_RSA_PKCS_PSS_PARAMS;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;

/**
 * This class encapsulates parameters for the Mechanism.RSA_PKCS_PSS.
 *
 * @author Karl Scheibelhofer
 * @version 1.0
 */
public class RSAPkcsPssParameters extends RSAPkcsParameters {

  private static final String CLASS_CK_PARAMS = "sun.security.pkcs11.wrapper.CK_RSA_PKCS_PSS_PARAMS";

  private static final Constructor<?> constructor;

  private static final Constructor<?> constructorNoArgs;

  private static final Field hashAlgField;

  private static final Field mgfField;

  private static final Field sLenField;

  /**
   * The length of the salt value in octets.
   */
  private long saltLength;

  static {
    Class<?> clazz = CK_RSA_PKCS_PSS_PARAMS.class;

    constructor = Util.getConstructor(clazz, String.class, String.class, String.class, int.class);
    constructorNoArgs = (constructor != null) ? null : Util.getConstructor(clazz);

    if (constructorNoArgs != null) {
      hashAlgField = Util.getField(clazz, "hashAlg");
      mgfField = Util.getField(clazz, "mgf");
      sLenField = Util.getField(clazz, "sLen");
    } else {
      hashAlgField = null;
      mgfField = null;
      sLenField = null;
    }
  }

  /**
   * Create a new RSAPkcsOaepParameters object with the given attributes.
   *
   * @param hashAlg
   *          The message digest algorithm used to calculate the digest of the
   *          encoding parameter.
   * @param mgf
   *          The mask to apply to the encoded block. One of the constants
   *          defined in the MessageGenerationFunctionType interface.
   * @param saltLength
   *          The length of the salt value in octets.
   */
  public RSAPkcsPssParameters(long hashAlg, long mgf, long saltLength) {
    super(hashAlg, mgf);
    if (constructor == null && constructorNoArgs == null) {
      throw new IllegalStateException("could not find constructor for class " + CLASS_CK_PARAMS);
    }
    this.saltLength = saltLength;
  }

  /**
   * Get this parameters object as an object of the CK_RSA_PKCS_PSS_PARAMS
   * class.
   *
   * @return This object as a CK_RSA_PKCS_PSS_PARAMS object.
   */
  @Override
  public CK_RSA_PKCS_PSS_PARAMS getPKCS11ParamsObject() {
    if (constructorNoArgs != null) {
      try {
        CK_RSA_PKCS_PSS_PARAMS ret = (CK_RSA_PKCS_PSS_PARAMS) constructorNoArgs.newInstance();
        hashAlgField.set(ret, hashAlg);
        mgfField.set(ret, mgf);
        sLenField.set(ret, saltLength);
        return ret;
      } catch (Exception ex) {
        throw new IllegalStateException("Could not create new instance of " + CLASS_CK_PARAMS, ex);
      }
    } else {
      String hashAlgName = Functions.getHashAlgName(hashAlg);
      String mgfHashAlgName = Functions.getHashAlgName(mgf2HashAlgMap.get(mgf));
      try {
        return (CK_RSA_PKCS_PSS_PARAMS) constructor.newInstance(
            hashAlgName, "MGF1", mgfHashAlgName, (int) saltLength);
      } catch (Exception ex) {
        throw new IllegalStateException("Could not create new instance of " + CLASS_CK_PARAMS, ex);
      }
    }
  }

  /**
   * Get the length of the salt value in octets.
   *
   * @return The length of the salt value in octets.
   */
  public long getSaltLength() {
    return saltLength;
  }

  /**
   * Set the length of the salt value in octets.
   *
   * @param saltLength
   *          The length of the salt value in octets.
   */
  public void setSaltLength(long saltLength) {
    this.saltLength = saltLength;
  }

  /**
   * Returns the string representation of this object. Do not parse data from
   * this string, it is for debugging only.
   *
   * @return A string representation of this object.
   */
  @Override
  public String toString() {
    return super.toString() + "\n  Salt Length (octets, dec): " + saltLength;
  }

}
