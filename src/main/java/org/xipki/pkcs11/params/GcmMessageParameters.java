// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.
//
// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.params;

import iaik.pkcs.pkcs11.wrapper.CK_GCM_MESSAGE_PARAMS;
import org.xipki.pkcs11.Functions;

/**
 * This class encapsulates parameters for the AES-GCM en/decryption.
 *
 * @author Otto Touzil (SIC)
 * @author Lijun Liao (xipki)
 */
public class GcmMessageParameters implements Parameters, MessageParameters {

  private byte[] iv;
  private long ivFixedBits;
  private long ivGenerator;
  private byte[] tag;

  /**
   * Create a new GCMParameters object with the given attributes.
   *
   * @param iv Initialization vector
   * @param ivFixedBits number of bits of the original IV to preserve when generating an <br>
   *                      new IV. These bits are counted from the Most significant bits (to the right).
   * @param ivGenerator Function used to generate a new IV. Each IV must be unique for a given session.
   * @param tag ocation of the authentication tag which is returned on MessageEncrypt, and provided on MessageDecrypt.
   */
  public GcmMessageParameters(byte[] iv, long ivFixedBits, long ivGenerator, byte[] tag) {
    init(iv, ivFixedBits, ivGenerator, tag);
  }

  private void init(byte[] iv, long ivFixedBits, long ivGenerator, byte[] tag) {
    this.iv = Functions.requireNonNull("pIV", iv);
    this.ivFixedBits = ivFixedBits;
    this.ivGenerator = ivGenerator;
    this.tag = tag;
  }

  /**
   * Get this parameters object as an object of the CK_ECDH1_DERIVE_PARAMS class.
   *
   * @return This object as a CK_ECDH1_DERIVE_PARAMS object.
   */
  @Override
  public CK_GCM_MESSAGE_PARAMS getPKCS11ParamsObject() {
    CK_GCM_MESSAGE_PARAMS params = new CK_GCM_MESSAGE_PARAMS();
    params.pIv = iv;
    params.ulIvFixedBits = ivFixedBits;
    params.ivGenerator = ivGenerator;
    params.pTag = tag;

    return params;
  }

  /**
   * Read the parameters from the PKCS11Object and overwrite the values into this object.
   *
   * @param obj Object to read the parameters from
   */
  @Override
  public void setValuesFromPKCS11Object(Object obj) {
    CK_GCM_MESSAGE_PARAMS params = (CK_GCM_MESSAGE_PARAMS) obj;
    init(params.pIv, params.ulIvFixedBits, params.ivGenerator, params.pTag);
  }

  /**
   * Returns the string representation of this object. Do not parse data from this string, it is for
   * debugging only.
   *
   * @return A string representation of this object.
   */
  @Override
  public String toString() {
    return "Class: " + getClass().getName() + "\n  IV: " + Functions.toHex(iv) +
        "\n  Tag: " + Functions.toHex(tag) + "\n  ivGenerator: " + ivGenerator + "\n  IVFixedBits: " + ivFixedBits;
  }

}

