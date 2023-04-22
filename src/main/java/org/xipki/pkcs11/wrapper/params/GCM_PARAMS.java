// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.params;

import iaik.pkcs.pkcs11.wrapper.CK_GCM_PARAMS;
import org.xipki.pkcs11.wrapper.Functions;

/**
 * Represents the CK_GCM_PARAMS.
 *
 * @author Lijun Liao (xipki)
 */
public class GCM_PARAMS extends CkParams {

  private final CK_GCM_PARAMS params;

  /**
   * Create a new GCM_PARAMS object with the given attributes.
   *
   * @param iv       Initialization vector
   * @param aad      additional authentication data. This data is authenticated but not encrypted.
   * @param tagBits length of authentication tag (output following ciphertext) in bits. (0 - 128)
   *                depending on the algorithm implementation within the hsm, ulTagBits may be any
   *                one of the following five values: 128, 120, 112, 104, or 96, may be 64 or 32;
   */
  public GCM_PARAMS(byte[] iv, byte[] aad, int tagBits) {
    params = new CK_GCM_PARAMS();
    params.pIv = requireNonNull("iv", iv);
    params.pAAD = aad;
    params.ulTagBits = Functions.requireAmong("tagBits", tagBits, 128, 120, 112, 104, 96, 64, 32);
  }

  @Override
  public CK_GCM_PARAMS getParams() {
    return params;
  }

  @Override
  protected int getMaxFieldLen() {
    return 9; // ulTagBits
  }

  @Override
  public String toString(String indent) {
    return indent + "CK_GCM_PARAMS:" +
        ptr2str(indent, "pIv", params.pIv) +
        ptr2str(indent, "pAAD", params.pAAD) +
        val2Str(indent, "ulTagBits", params.ulTagBits);
  }

}

