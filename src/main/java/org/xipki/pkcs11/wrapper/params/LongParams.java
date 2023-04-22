// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.params;

/**
 * This class encapsulates parameters CK_LONG.
 *
 * @author Lijun Liao (xipki)
 */
public class LongParams extends CkParams {

  /**
   * The PKCS#11 object.
   */
  protected final long params;

  /**
   * Create a new LongParams object using the given object.
   *
   * @param params
   *          The params.
   */
  public LongParams(long params) {
    this.params = params;
  }

  @Override
  public Long getParams() {
    return params;
  }

  @Override
  protected int getMaxFieldLen() {
    return 0;
  }

  @Override
  public String toString(String indent) {
    return indent + "Long Params: " + params;
  }

}
