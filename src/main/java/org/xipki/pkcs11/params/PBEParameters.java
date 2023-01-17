// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.
//
// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.params;

import iaik.pkcs.pkcs11.wrapper.CK_PBE_PARAMS;
import org.xipki.pkcs11.Functions;

/**
 * This class encapsulates parameters for the Mechanism.PBA_* and
 * Mechanism.PBA_SHA1_WITH_SHA1_HMAC mechanisms.
 *
 * @author Karl Scheibelhofer (SIC)
 * @author Lijun Liao (xipki)
 */
public class PBEParameters implements Parameters {

  /**
   * The 8-byte initialization vector (IV), if an IV is required.
   */
  private final char[] iv;

  /**
   * The password to be used in the PBE key generation.
   */
  private final char[] password;

  /**
   * The salt to be used in the PBE key generation.
   */
  private final char[] salt;

  /**
   * The number of iterations required for the generation.
   */
  private final int iterations;

  /**
   * Create a new PBEDeriveParameters object with the given attributes.
   *
   * @param iv
   *          The 8-byte initialization vector (IV), if an IV is required.
   * @param password
   *          The password to be used in the PBE key generation.
   * @param salt
   *          The salt to be used in the PBE key generation.
   * @param iterations
   *          The number of iterations required for the generation.
   */
  public PBEParameters(char[] iv, char[] password, char[] salt, int iterations) {
    this.iv = Functions.requireNonNull("iv", iv);
    Functions.requireAmong("iv.length", iv.length, 8);
    this.password = Functions.requireNonNull("password", password);
    this.salt = Functions.requireNonNull("salt", salt);
    this.iterations = iterations;
  }

  /**
   * Get this parameters object as an object of the CK_PBE_PARAMS class.
   *
   * @return This object as a CK_PBE_PARAMS object.
   */
  @Override
  public CK_PBE_PARAMS getPKCS11ParamsObject() {
    CK_PBE_PARAMS params = new CK_PBE_PARAMS();

    params.pInitVector = iv;
    params.pPassword = password;
    params.pSalt = salt;
    params.ulIteration = iterations;

    return params;
  }

  /**
   * Returns the string representation of this object. Do not parse data from
   * this string, it is for debugging only.
   *
   * @return A string representation of this object.
   */
  @Override
  public String toString() {
    return "Class: " + getClass().getName() + "\n  IV: " + (iv != null ? new String(iv) : null) +
        "\n  Password: " + (password != null ? new String(password) : null) +
        "\n  Salt: " + (salt != null ? new String(salt) : null) + "\n  Iterations (dec): " + iterations;
  }

}
