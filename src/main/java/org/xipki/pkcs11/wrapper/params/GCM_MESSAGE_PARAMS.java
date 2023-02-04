// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.params;

import iaik.pkcs.pkcs11.wrapper.CK_GCM_MESSAGE_PARAMS;
import org.xipki.pkcs11.wrapper.PKCS11Constants;

/**
 * Represents the CK_GCM_MESSAGE_PARAMS.
 *
 * @author Lijun Liao (xipki)
 */
public class GCM_MESSAGE_PARAMS extends CkParams implements CkMessageParams {

  private CK_GCM_MESSAGE_PARAMS params;

  /**
   * Create a new GCM_MESSAGE_PARAMS object with the given attributes.
   *
   * @param iv Initialization vector
   * @param ivFixedBits number of bits of the original IV to preserve when generating an <br>
   *                    new IV. These bits are counted from the Most significant bits (to the right).
   * @param ivGenerator Function used to generate a new IV. Each IV must be unique for a given session.
   * @param tag location of the authentication tag which is returned on MessageEncrypt, and provided on MessageDecrypt.
   */
  public GCM_MESSAGE_PARAMS(byte[] iv, long ivFixedBits, long ivGenerator, byte[] tag) {
    params = new CK_GCM_MESSAGE_PARAMS();
    params.pIv = iv;
    params.ulIvFixedBits = ivFixedBits;
    params.ivGenerator = ivGenerator;
    params.pTag = tag;
  }

  @Override
  public CK_GCM_MESSAGE_PARAMS getParams() {
    return params;
  }

  @Override
  public void setValuesFromPKCS11Object(Object obj) {
    this.params = (CK_GCM_MESSAGE_PARAMS) obj;
  }

  @Override
  public String toString() {
    return "CK_GCM_MESSAGE_PARAMS:" +
        ptrToString("\n  IV:            ", params.pIv) +
        ptrToString("\n  pTag:          ", params.pTag) +
        "\n  ivGenerator:   " + PKCS11Constants.codeToName(PKCS11Constants.Category.CKG_GENERATOR, params.ivGenerator) +
        "\n  ulIvFixedBits: " + params.ulIvFixedBits;
  }

}

