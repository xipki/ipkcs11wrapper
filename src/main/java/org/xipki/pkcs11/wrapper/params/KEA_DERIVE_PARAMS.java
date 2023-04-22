// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.params;

import iaik.pkcs.pkcs11.wrapper.CK_KEA_DERIVE_PARAMS;

/**
 * Represents the CK_KEA_DERIVE_PARAMS.
 *
 * @author Lijun Liao (xipki)
 */
public class KEA_DERIVE_PARAMS extends CkParams {

  private final CK_KEA_DERIVE_PARAMS params;

  /**
   * Create a new KEA_DERIVE_PARAMS object with the given attributes.
   *
   * @param isSender
   *          Option for generating the key (called a TEK). The value is TRUE if the sender
   *          (originator) generates the TEK, FALSE if the recipient is regenerating the TEK.
   * @param randomA
   *          The random data Ra.
   * @param randomB
   *          The random data Rb.
   * @param publicData
   *          The other party's KEA public key value.
   */
  public KEA_DERIVE_PARAMS(boolean isSender, byte[] randomA, byte[] randomB, byte[] publicData) {
    params = new CK_KEA_DERIVE_PARAMS();

    params.isSender = isSender;
    params.pRandomA = requireNonNull("randomA", randomA);
    params.pRandomB = requireNonNull("randomB", randomB);
    params.pPublicData = requireNonNull("publicData", publicData);

  }

  @Override
  public CK_KEA_DERIVE_PARAMS getParams() {
    return params;
  }

  @Override
  protected int getMaxFieldLen() {
    return 11; // pPublicData
  }

  @Override
  public String toString(String indent) {
    return indent + "CK_KEA_DERIVE_PARAMS:" +
        val2Str(indent, "isSender", params.isSender) +
        ptr2str(indent, "pRandomA", params.pRandomA) +
        ptr2str(indent, "pRandomB", params.pRandomB) +
        ptr2str(indent, "pPublicData", params.pPublicData);
  }

}
