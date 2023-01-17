// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.
//
// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.params;

import iaik.pkcs.pkcs11.wrapper.CK_GCM_PARAMS;
import org.xipki.pkcs11.Functions;

/**
 * This class encapsulates parameters for the AES-GCM en/decryption.
 *
 * @author Otto Touzil (SIC)
 * @author Lijun Liao (xipki)
 */
public class GcmParameters implements Parameters {

  private final byte[] iv;
  private final byte[] aad;
  private final int tagBits;

  /**
   * Create a new GCMParameters object with the given attributes.
   *
   * @param iv       Initialization vector
   * @param aad      additional authentication data. This data is authenticated but not encrypted.
   * @param tagBits length of authentication tag (output following ciphertext) in bits. (0 - 128)
   *                  depending on the algorithm implementation within the hsm, ulTagBits may be any
   *                  one of the following five values: 128, 120, 112, 104, or 96, may be 64 or 32;
   */
  public GcmParameters(byte[] iv, byte[] aad, int tagBits) {
    this.iv = Functions.requireNonNull("iv", iv);
    this.tagBits = Functions.requireRange("tagBits", tagBits, 0, 128);
    this.aad = aad;
  }

  /**
   * Get this parameters object as an object of the CK_GCM_PARAMS class.
   *
   * @return This object as a CK_GCM_PARAMS object.
   */
  @Override
  public CK_GCM_PARAMS getPKCS11ParamsObject() {
    CK_GCM_PARAMS params = new CK_GCM_PARAMS();
    params.pIv = iv;
    params.pAAD = aad;
    params.ulTagBits = tagBits;

    return params;
  }

  /**
   * Returns the string representation of this object. Do not parse data from this string, it is for
   * debugging only.
   *
   * @return A string representation of this object.
   */
  @Override
  public String toString() {
    return "Class: " + getClass().getName() + "\n   IV: " + Functions.toHex(iv) +
        "\n  AAD: " + (aad == null ? " " : Functions.toHex(aad)) + "\n   TagBits: " + tagBits;
  }

}

