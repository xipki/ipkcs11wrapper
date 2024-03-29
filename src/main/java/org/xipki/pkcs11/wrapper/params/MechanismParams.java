// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.params;

import org.xipki.pkcs11.wrapper.PKCS11Constants.Category;

/**
 * This class encapsulates parameters CK_LONG.
 *
 * @author Lijun Liao (xipki)
 */
public class MechanismParams extends CkParams {

  /**
   * The PKCS#11 object.
   */
  protected final long params;

  /**
   * Create a new MechanismParams object using the given object.
   *
   * @param params
   *          The mechanism.
   */
  public MechanismParams(long params) {
    this.params = params;
  }

  @Override
  public Long getParams() {
    if (module == null) {
      return params;
    }

    return module.genericToVendorCode(Category.CKM, params);
  }

  @Override
  protected int getMaxFieldLen() {
    return 0;
  }

  @Override
  public String toString(String indent) {
    return indent + "MechanismParams Params: " + codeToName(Category.CKM, params);
  }

}
