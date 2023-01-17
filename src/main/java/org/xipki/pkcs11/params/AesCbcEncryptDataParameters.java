// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.
//
// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.params;

import iaik.pkcs.pkcs11.wrapper.CK_AES_CBC_ENCRYPT_DATA_PARAMS;

/**
 * This class encapsulates parameters for the algorithm Mechanism.AES_CBC_ENCRYPT_DATA.
 *
 * @author Karl Scheibelhofer (SIC)
 * @author Lijun Liao (xipki)
 */
public class AesCbcEncryptDataParameters extends CbcEncryptDataParameters {

  /**
   * Create a new AesCbcEncryptDataParameters object with the given IV and data.
   *
   * @param iv
   *          The initialization vector.
   * @param data
   *          The key derivation data.
   *
   */
  public AesCbcEncryptDataParameters(byte[] iv, byte[] data) {
    super(16, iv, data);
  }

  /**
   * Get this parameters object as Long object.
   *
   * @return This object as Long object.
   *
   */
  @Override
  public CK_AES_CBC_ENCRYPT_DATA_PARAMS getPKCS11ParamsObject() {
    CK_AES_CBC_ENCRYPT_DATA_PARAMS params = new CK_AES_CBC_ENCRYPT_DATA_PARAMS();

    params.iv = iv;
    params.pData = data;

    return params;
  }

}
